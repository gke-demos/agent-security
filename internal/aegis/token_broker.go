package aegis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/auth/gcp"
)

func init() {
	RegisterHTTPRoutes(registerTokenBrokerRoutes)
}

const (
	tokenBrokerExtKey        = "token_broker"
	sharedRootServiceToken   = "shared-service-account-root-token"
	defaultCredentialTTL     = 1 * time.Hour
	jiraIssueSEC101URL       = "https://api.atlassian.com/ex/jira/acme/rest/api/3/issue/SEC-101"
	githubAdvisorySEC101URL  = "https://api.github.com/repos/acme-secops/checkout-service/security-advisories/GHSA-sec-101"
)

type authInvocationContextKey struct{}

// AuthInvocation carries per-request identity and provider parameters for TokenBroker.Credential.
type AuthInvocation struct {
	SessionID             string
	Persona               PersonaID
	Provider              ProviderID
	Scopes                []string
	BypassBrokerRedMode   bool
	RequireCold3LOConsent bool
	GCPResourceName       string
	ContinueURI           string
}

// WithAuthInvocation binds an AuthInvocation to ctx so auth.Transport can resolve per-persona 3LO credentials.
func WithAuthInvocation(ctx context.Context, inv AuthInvocation) context.Context {
	return context.WithValue(ctx, authInvocationContextKey{}, inv)
}

// AuthInvocationFromContext extracts the AuthInvocation from ctx, if present.
func AuthInvocationFromContext(ctx context.Context) (AuthInvocation, bool) {
	v, ok := ctx.Value(authInvocationContextKey{}).(AuthInvocation)
	return v, ok
}

// TokenBroker implements ADK Go v2's auth.CredentialProvider and auth.RefreshingProvider
// interfaces with a Persona-partitioned credential vault and dual-backend support
// (Direct OAuth 2.0 3LO + Google Cloud IAM Connector / Agent Identity via adk/v2/auth/gcp).
type TokenBroker struct {
	rt               *Runtime
	store            auth.CredentialStore
	mu               sync.RWMutex
	gcpClient        *gcp.Client
	revoked          map[string]bool
	nonFixtureGrants map[string]string
	nonces           map[string]ConsentChallenge
}

// NewTokenBroker constructs a TokenBroker bound to rt.
func NewTokenBroker(rt *Runtime) *TokenBroker {
	b := &TokenBroker{
		rt:               rt,
		store:            auth.NewInMemoryCredentialStore(),
		revoked:          make(map[string]bool),
		nonFixtureGrants: make(map[string]string),
		nonces:           make(map[string]ConsentChallenge),
	}
	b.seedConfiguredTokens(context.Background(), "default-session")
	return b
}

func (b *TokenBroker) seedConfiguredTokens(ctx context.Context, sessionID string) {
	if b.rt == nil {
		return
	}
	for _, persona := range []PersonaID{PersonaAlice, PersonaBob} {
		for _, provider := range []ProviderID{ProviderGitHub, ProviderGoogleGmail, ProviderAtlassianJira, ProviderGCPIAM} {
			if tok := b.configuredPersonaToken(persona, provider); tok != "" {
				scopes := defaultScopesForProvider(provider)
				key := b.credentialKey(sessionID, persona, provider, scopes)
				_ = b.store.Set(ctx, key, auth.BearerCredential{Token: tok}, time.Now().Add(defaultCredentialTTL))
			}
		}
	}
}

func (b *TokenBroker) configuredPersonaToken(persona PersonaID, provider ProviderID) string {
	if b.rt == nil {
		return ""
	}
	cfg := b.rt.Config()
	if provider == ProviderGCPIAM {
		if strings.TrimSpace(cfg.GCPProjectID) != "" || parseBoolEnv(os.Getenv("LIVE_GCP")) {
			return resolveGoogleADCToken(context.Background())
		}
		return ""
	}
	switch persona {
	case PersonaAlice:
		switch provider {
		case ProviderGitHub:
			return strings.TrimSpace(cfg.AliceGitHubToken)
		case ProviderGoogleGmail:
			return strings.TrimSpace(cfg.AliceGmailToken)
		case ProviderAtlassianJira:
			return strings.TrimSpace(cfg.AliceJiraToken)
		}
	case PersonaBob:
		switch provider {
		case ProviderGitHub:
			return strings.TrimSpace(cfg.BobGitHubToken)
		case ProviderGoogleGmail:
			return strings.TrimSpace(cfg.BobGmailToken)
		case ProviderAtlassianJira:
			return strings.TrimSpace(cfg.BobJiraToken)
		}
	}
	return ""
}

func (b *TokenBroker) configuredOrDefaultPersonaToken(persona PersonaID, provider ProviderID) string {
	if tok := b.configuredPersonaToken(persona, provider); tok != "" {
		return tok
	}
	return defaultPersona3LOToken(persona, provider)
}

// TokenBroker returns the Runtime's singleton TokenBroker instance.
func (r *Runtime) TokenBroker() *TokenBroker {
	if ext, ok := r.GetExtension(tokenBrokerExtKey); ok {
		if tb, ok := ext.(*TokenBroker); ok {
			return tb
		}
	}
	tb := NewTokenBroker(r)
	r.SetExtension(tokenBrokerExtKey, tb)
	return tb
}

// SetGCPClient configures the optional adk/v2/auth/gcp Client for IAM Connector / Agent Identity lookups.
func (b *TokenBroker) SetGCPClient(client *gcp.Client) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcpClient = client
}

// BuildGCPProvider creates an ADK v2 auth.CredentialProvider backed by google.golang.org/adk/v2/auth/gcp.
func (b *TokenBroker) BuildGCPProvider(ctx context.Context, scheme gcp.ProviderScheme) (auth.CredentialProvider, error) {
	b.mu.RLock()
	client := b.gcpClient
	b.mu.RUnlock()
	return gcp.NewProvider(ctx, gcp.ProviderConfig{
		Scheme: scheme,
		Client: client,
		Store:  b.store,
	})
}

// Credential implements auth.CredentialProvider.
func (b *TokenBroker) Credential(ctx context.Context) (auth.Credential, error) {
	inv, ok := AuthInvocationFromContext(ctx)
	if !ok {
		inv = AuthInvocation{
			SessionID: "default-session",
			Persona:   PersonaAlice,
			Provider:  ProviderAtlassianJira,
			Scopes:    defaultScopesForProvider(ProviderAtlassianJira),
		}
	}
	if inv.SessionID == "" {
		inv.SessionID = "default-session"
	}
	if inv.Persona == "" {
		inv.Persona = PersonaAlice
	}
	if inv.Provider == "" {
		inv.Provider = ProviderAtlassianJira
	}
	if len(inv.Scopes) == 0 {
		inv.Scopes = defaultScopesForProvider(inv.Provider)
	}

	if inv.BypassBrokerRedMode {
		return auth.BearerCredential{Token: sharedRootServiceToken}, nil
	}

	// If a GCP IAM Connector / Agent Identity resource name is supplied and a gcp.Client is wired,
	// delegate retrieval to google.golang.org/adk/v2/auth/gcp.
	if inv.GCPResourceName != "" {
		b.mu.RLock()
		gcpClient := b.gcpClient
		b.mu.RUnlock()
		if gcpClient != nil {
			key := b.credentialKey(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
			if cached, hit, err := b.store.Get(ctx, key); err == nil && hit {
				return cached, nil
			}
			retrieval, err := gcpClient.RetrieveCredential(ctx, gcp.Request{
				Resource:    inv.GCPResourceName,
				UserID:      fmt.Sprintf("%s:%s", inv.SessionID, inv.Persona),
				Scopes:      inv.Scopes,
				ContinueURI: inv.ContinueURI,
			})
			if err != nil {
				return nil, err
			}
			if !retrieval.ExpiresAt.IsZero() {
				_ = b.store.Set(ctx, key, retrieval.Credential, retrieval.ExpiresAt)
			}
			return retrieval.Credential, nil
		}
	}

	if inv.RequireCold3LOConsent || !b.hasActiveGrant(inv.SessionID, inv.Persona, inv.Provider) {
		challenge := b.issueConsentChallenge(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
		key := b.credentialKey(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
		return nil, fmt.Errorf("tokenbroker: 3LO consent required for %s/%s: %w", inv.Persona, inv.Provider, &auth.ConsentRequiredError{
			AuthURI: challenge.AuthURI,
			Nonce:   challenge.Nonce,
			Key:     key.Key,
		})
	}

	key := b.credentialKey(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
	if cached, hit, err := b.store.Get(ctx, key); err == nil && hit {
		return cached, nil
	}

	// Seed configured or deterministic per-persona 3LO token for warm session
	token := b.configuredOrDefaultPersonaToken(inv.Persona, inv.Provider)
	cred := auth.BearerCredential{Token: token}
	_ = b.store.Set(ctx, key, cred, time.Now().Add(defaultCredentialTTL))
	return cred, nil
}

// Refresh implements auth.RefreshingProvider.
func (b *TokenBroker) Refresh(ctx context.Context, rejected auth.Credential) (auth.Credential, error) {
	inv, ok := AuthInvocationFromContext(ctx)
	if !ok {
		return nil, errors.New("tokenbroker: cannot refresh without AuthInvocation in context")
	}
	key := b.credentialKey(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
	if cached, hit, err := b.store.Get(ctx, key); err == nil && hit {
		if !sameBearerToken(cached, rejected) {
			return cached, nil
		}
	}
	// Downstream 401/403 was an ACL refusal for the active Persona rather than a stale cached token.
	return nil, errors.New("tokenbroker: downstream 403/401 is an authorization refusal for active persona; no replacement token available")
}

// Grant stores a 3LO token for (SessionID, Persona, Provider, Scopes) and marks the provider granted.
func (b *TokenBroker) Grant(ctx context.Context, req OAuthGrantRequest) *SessionSnapshot {
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = "default-session"
	}
	persona := req.Persona
	if persona == "" {
		persona = PersonaAlice
	}
	provider := req.Provider
	if provider == "" {
		provider = ProviderAtlassianJira
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopesForProvider(provider)
	}
	token := firstNonEmpty(req.AccessToken, req.Token)
	if token == "" {
		token = b.configuredOrDefaultPersonaToken(persona, provider)
	}

	b.mu.Lock()
	slot := revocationSlot(sessionID, persona, provider)
	delete(b.revoked, slot)
	if !isFixture3LOToken(token) {
		b.nonFixtureGrants[slot] = token
	} else {
		delete(b.nonFixtureGrants, slot)
	}
	b.mu.Unlock()

	key := b.credentialKey(sessionID, persona, provider, scopes)
	_ = b.store.Set(ctx, key, auth.BearerCredential{Token: token}, time.Now().Add(defaultCredentialTTL))
	// Also warm the default scope key so callers omitting explicit scopes find the grant
	defKey := b.credentialKey(sessionID, persona, provider, defaultScopesForProvider(provider))
	_ = b.store.Set(ctx, defKey, auth.BearerCredential{Token: token}, time.Now().Add(defaultCredentialTTL))

	return b.rt.UpdateSession(sessionID, func(s *SessionSnapshot) {
		if s.GrantedProviders == nil {
			s.GrantedProviders = make(map[PersonaID][]ProviderID)
		}
		s.GrantedProviders[persona] = appendProviderUnique(s.GrantedProviders[persona], provider)
	})
}

// Revoke removes a Persona's 3LO token for Provider from the vault and session snapshot.
func (b *TokenBroker) Revoke(ctx context.Context, sessionID string, persona PersonaID, provider ProviderID, scopes []string) *SessionSnapshot {
	if sessionID == "" {
		sessionID = "default-session"
	}
	if persona == "" {
		persona = PersonaAlice
	}
	if provider == "" {
		provider = ProviderAtlassianJira
	}
	if len(scopes) == 0 {
		scopes = defaultScopesForProvider(provider)
	}

	b.mu.Lock()
	slot := revocationSlot(sessionID, persona, provider)
	b.revoked[slot] = true
	delete(b.nonFixtureGrants, slot)
	b.mu.Unlock()

	key := b.credentialKey(sessionID, persona, provider, scopes)
	_ = b.store.Delete(ctx, key)
	defKey := b.credentialKey(sessionID, persona, provider, defaultScopesForProvider(provider))
	_ = b.store.Delete(ctx, defKey)

	return b.rt.UpdateSession(sessionID, func(s *SessionSnapshot) {
		if s.GrantedProviders == nil {
			return
		}
		filtered := make([]ProviderID, 0, len(s.GrantedProviders[persona]))
		for _, p := range s.GrantedProviders[persona] {
			if p != provider {
				filtered = append(filtered, p)
			}
		}
		s.GrantedProviders[persona] = filtered
	})
}

// HasNonFixtureGrant returns true when any active session holds a granted non-fixture 3LO token for provider.
func (b *TokenBroker) HasNonFixtureGrant(provider ProviderID) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	suffix := fmt.Sprintf("|%d:%s", len(provider), provider)
	for slot, tok := range b.nonFixtureGrants {
		if strings.HasSuffix(slot, suffix) && !b.revoked[slot] && !isFixture3LOToken(tok) {
			return true
		}
	}
	return false
}

func isFixture3LOToken(token string) bool {
	tok := strings.TrimSpace(token)
	return tok == "" ||
		strings.HasPrefix(tok, "3lo-alice-") ||
		strings.HasPrefix(tok, "3lo-bob-") ||
		strings.HasPrefix(tok, "fixture-3lo-") ||
		tok == sharedRootServiceToken
}

func (b *TokenBroker) hasActiveGrant(sessionID string, persona PersonaID, provider ProviderID) bool {
	b.mu.RLock()
	isRevoked := b.revoked[revocationSlot(sessionID, persona, provider)]
	b.mu.RUnlock()
	if isRevoked {
		return false
	}
	snap := b.rt.GetOrCreateSession(sessionID)
	for _, p := range snap.GrantedProviders[persona] {
		if p == provider {
			return true
		}
	}
	return false
}

func (b *TokenBroker) issueConsentChallenge(sessionID string, persona PersonaID, provider ProviderID, scopes []string) ConsentChallenge {
	nonce := randomHex(12)
	q := url.Values{}
	q.Set("client_id", "aegis-sre-3lo-client")
	q.Set("response_type", "code")
	q.Set("session_id", sessionID)
	q.Set("persona", string(persona))
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", nonce)

	var baseAuthURL string
	resourceRef := "SEC-101"
	switch provider {
	case ProviderAtlassianJira:
		baseAuthURL = "https://auth.atlassian.com/authorize"
	case ProviderGitHub:
		baseAuthURL = "https://github.com/login/oauth/authorize"
	case ProviderGoogleGmail:
		baseAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
		resourceRef = "msg-p0-escalation"
	default:
		baseAuthURL = fmt.Sprintf("/oauth/%s/authorize", provider)
	}

	ch := ConsentChallenge{
		Provider:    provider,
		Persona:     persona,
		Scopes:      append([]string(nil), scopes...),
		AuthURI:     baseAuthURL + "?" + q.Encode(),
		Nonce:       nonce,
		ResourceRef: resourceRef,
	}
	b.mu.Lock()
	b.nonces[nonce] = ch
	b.mu.Unlock()
	return ch
}

func (b *TokenBroker) credentialKey(sessionID string, persona PersonaID, provider ProviderID, scopes []string) auth.CredentialKey {
	sorted := append([]string(nil), scopes...)
	sort.Strings(sorted)
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s|", len(provider), provider)
	for _, s := range sorted {
		_, _ = fmt.Fprintf(h, "%d:%s,", len(s), s)
	}
	return auth.CredentialKey{
		AppName: "aegis-sre",
		UserID:  fmt.Sprintf("%d:%s|%d:%s", len(sessionID), sessionID, len(persona), persona),
		Key:     hex.EncodeToString(h.Sum(nil)),
	}
}

func buildConsentChallengeCard(surfaceID, sessionID string, persona PersonaID, ch *ConsentChallenge) A2UICard {
	return A2UICard{
		SurfaceID: surfaceID,
		MimeType:  "application/json+a2ui",
		Version:   "0.9",
		Type:      CardConsentChallenge,
		Title:     "Per-User 3LO OAuth Consent Required",
		Subtitle:  "Boundary 3: Identity & 3LO Token Broker (adk_request_credential)",
		Severity:  "WARNING",
		Body:      fmt.Sprintf("Operator persona %q has not granted %q access (%s) in this session. Authorize 3LO access to continue.", persona, ch.Provider, strings.Join(ch.Scopes, ", ")),
		Fields: map[string]string{
			"Persona":  string(persona),
			"Provider": string(ch.Provider),
			"Scopes":   strings.Join(ch.Scopes, ", "),
			"Resource": ch.ResourceRef,
		},
		Actions: []A2UICardAction{
			{
				ID:       "act-oauth-grant",
				Label:    fmt.Sprintf("Authorize %s as %s (3LO)", ch.Provider, persona),
				Kind:     "oauth_consent",
				Endpoint: fmt.Sprintf("/api/sessions/%s/oauth/grant", sessionID),
				Payload: map[string]string{
					"persona":  string(persona),
					"provider": string(ch.Provider),
					"nonce":    ch.Nonce,
				},
			},
		},
	}
}

func registerTokenBrokerRoutes(mux *http.ServeMux, rt *Runtime) {
	mux.HandleFunc("GET /oauth/{provider}/authorize", func(w http.ResponseWriter, r *http.Request) {
		provider := ProviderID(r.PathValue("provider"))
		sessionID := firstNonEmpty(r.URL.Query().Get("session_id"), r.URL.Query().Get("sessionId"), "default-session")
		persona := PersonaID(firstNonEmpty(r.URL.Query().Get("persona"), string(PersonaAlice)))
		scopes := defaultScopesForProvider(provider)
		if rawScopes := strings.TrimSpace(r.URL.Query().Get("scopes")); rawScopes != "" {
			scopes = strings.Split(rawScopes, ",")
		}
		ch := rt.TokenBroker().issueConsentChallenge(sessionID, persona, provider, scopes)
		writeJSON(w, http.StatusOK, ch)
	})

	mux.HandleFunc("GET /oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		provider := ProviderID(r.PathValue("provider"))
		sessionID := firstNonEmpty(r.URL.Query().Get("session_id"), r.URL.Query().Get("sessionId"), "default-session")
		persona := PersonaID(firstNonEmpty(r.URL.Query().Get("persona"), string(PersonaAlice)))
		code := firstNonEmpty(r.URL.Query().Get("code"), "oauthcode")
		nonce := firstNonEmpty(r.URL.Query().Get("nonce"), r.URL.Query().Get("state"))
		token := fmt.Sprintf("3lo-%s-%s-%s", persona, provider, code)
		if exchanged, err := rt.TokenBroker().exchangeOAuthCode(r.Context(), provider, code); err == nil && exchanged != "" {
			token = exchanged
		}

		snap := rt.TokenBroker().Grant(r.Context(), OAuthGrantRequest{
			SessionID: sessionID,
			Persona:   persona,
			Provider:  provider,
			Token:     token,
			Nonce:     nonce,
		})
		writeJSON(w, http.StatusOK, snap)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/oauth/grant", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req OAuthGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.SessionID = sessionID
		snap := rt.TokenBroker().Grant(r.Context(), req)
		writeJSON(w, http.StatusOK, snap)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req OAuthGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		snap := rt.TokenBroker().Revoke(r.Context(), sessionID, req.Persona, req.Provider, req.Scopes)
		writeJSON(w, http.StatusOK, snap)
	})
}

func defaultScopesForProvider(provider ProviderID) []string {
	switch provider {
	case ProviderGoogleGmail:
		return []string{"https://www.googleapis.com/auth/gmail.readonly"}
	case ProviderAtlassianJira:
		return []string{"read:jira-work", "write:jira-work"}
	case ProviderGitHub:
		return []string{"repo", "security_events"}
	case ProviderGCPIAM:
		return []string{"https://www.googleapis.com/auth/cloud-platform"}
	default:
		return []string{"read"}
	}
}

func (b *TokenBroker) exchangeOAuthCode(ctx context.Context, provider ProviderID, code string) (string, error) {
	if b.rt == nil || strings.TrimSpace(code) == "" {
		return "", nil
	}
	cfg := b.rt.Config()

	var (
		clientID      string
		clientSecret  string
		tokenEndpoint string
	)
	switch provider {
	case ProviderGitHub:
		clientID = strings.TrimSpace(cfg.GitHubOAuthClientID)
		clientSecret = strings.TrimSpace(cfg.GitHubOAuthClientSecret)
		tokenEndpoint = "https://github.com/login/oauth/access_token"
	case ProviderGoogleGmail:
		clientID = strings.TrimSpace(cfg.GoogleOAuthClientID)
		clientSecret = strings.TrimSpace(cfg.GoogleOAuthClientSecret)
		tokenEndpoint = "https://oauth2.googleapis.com/token"
	case ProviderAtlassianJira:
		clientID = strings.TrimSpace(cfg.JiraOAuthClientID)
		clientSecret = strings.TrimSpace(cfg.JiraOAuthClientSecret)
		tokenEndpoint = "https://auth.atlassian.com/oauth/token"
	}

	if override := strings.TrimSpace(cfg.OAuthTokenEndpointOverride); override != "" {
		tokenEndpoint = override
	} else if clientID == "" || clientSecret == "" {
		return "", nil
	}

	if tokenEndpoint == "" {
		return "", nil
	}

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("oauth token exchange status %d", resp.StatusCode)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil && strings.TrimSpace(parsed.AccessToken) != "" {
		return strings.TrimSpace(parsed.AccessToken), nil
	}
	if vals, err := url.ParseQuery(string(raw)); err == nil {
		if tok := strings.TrimSpace(vals.Get("access_token")); tok != "" {
			return tok, nil
		}
	}
	return "", nil
}

func defaultPersona3LOToken(persona PersonaID, provider ProviderID) string {
	return fmt.Sprintf("3lo-%s-%s-token", persona, provider)
}

func classifyPrincipal(token string) string {
	switch {
	case strings.HasPrefix(token, "3lo-alice-"):
		return "alice@secops.acme.example.com (3LO per-user)"
	case strings.HasPrefix(token, "3lo-bob-"):
		return "bob@contractor.external.example.com (3LO per-user)"
	case token == sharedRootServiceToken:
		return "shared-service-account-root-token (Confused Deputy)"
	default:
		return "unknown"
	}
}

func sameBearerToken(a, b auth.Credential) bool {
	ha := http.Header{}
	hb := http.Header{}
	_ = a.Apply(ha)
	_ = b.Apply(hb)
	return ha.Get("Authorization") == hb.Get("Authorization")
}

func revocationSlot(sessionID string, persona PersonaID, provider ProviderID) string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(sessionID), sessionID, len(persona), persona, len(provider), provider)
}

func appendProviderUnique(list []ProviderID, item ProviderID) []ProviderID {
	for _, p := range list {
		if p == item {
			return list
		}
	}
	return append(list, item)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func randomHex(numBytes int) string {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "fallbacknonce123456"
	}
	return hex.EncodeToString(b)
}

type roundTripFuncInternal func(*http.Request) (*http.Response, error)

func (f roundTripFuncInternal) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
