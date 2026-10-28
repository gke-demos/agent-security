package aegis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
	tokenBrokerExtKey       = "token_broker"
	sharedRootServiceToken  = "shared-service-account-root-token"
	defaultCredentialTTL    = 15 * time.Minute
	pkceChallengeTTL        = 5 * time.Minute
	consumedNonceTTL        = 15 * time.Minute
	pkceCodeChallengeMethod = "S256"
	jiraIssueSEC101URL      = "https://api.atlassian.com/ex/jira/acme/rest/api/3/issue/SEC-101"
	githubAdvisorySEC101URL = "https://api.github.com/repos/acme-secops/checkout-service/security-advisories/GHSA-sec-101"
)

type grantSlotKey struct {
	sessionID string
	persona   PersonaID
	provider  ProviderID
}

// PKCEChallengeState stores a one-time RFC 7636 S256 PKCE authorization challenge in memory.
type PKCEChallengeState struct {
	SessionID           string
	Persona             PersonaID
	Provider            ProviderID
	Scopes              []string
	Nonce               string
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
	ClientBoundPKCE     bool
	ExpiresAt           time.Time
}

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

type ephemeralGrantMeta struct {
	SessionID           string
	Persona             PersonaID
	Provider            ProviderID
	Scopes              []string
	AuthMethod          string
	PKCEVerified        bool
	CodeChallengeMethod string
	IssuedAt            time.Time
	ExpiresAt           time.Time
}

// TokenBroker implements ADK Go v2's auth.CredentialProvider and auth.RefreshingProvider
// interfaces with a Persona-partitioned credential vault and dual-backend support
// (Direct OAuth 2.0 3LO + Google Cloud IAM Connector / Agent Identity via adk/v2/auth/gcp).
type TokenBroker struct {
	rt               *Runtime
	store            auth.CredentialStore
	mu               sync.RWMutex
	gcpClient        *gcp.Client
	revoked          map[grantSlotKey]bool
	nonFixtureGrants map[grantSlotKey]string
	grantMeta        map[grantSlotKey]ephemeralGrantMeta
	pkceChallenges   map[string]PKCEChallengeState
	consumedNonces   map[string]time.Time
}

// NewTokenBroker constructs a TokenBroker bound to rt.
func NewTokenBroker(rt *Runtime) *TokenBroker {
	b := &TokenBroker{
		rt:               rt,
		store:            auth.NewInMemoryCredentialStore(),
		revoked:          make(map[grantSlotKey]bool),
		nonFixtureGrants: make(map[grantSlotKey]string),
		grantMeta:        make(map[grantSlotKey]ephemeralGrantMeta),
		pkceChallenges:   make(map[string]PKCEChallengeState),
		consumedNonces:   make(map[string]time.Time),
	}
	b.seedConfiguredTokens(context.Background(), "default-session")
	return b
}

func (b *TokenBroker) seedWarmSessionGrants(sessionID string) {
	if sessionID == "" {
		sessionID = "default-session"
	}
	now := time.Now().UTC()
	expiresAt := now.Add(defaultCredentialTTL)
	storeExpiry := expiresAt.Add(auth.ExpirySkew)

	type pendingStoreItem struct {
		key   auth.CredentialKey
		token string
	}
	var toStore []pendingStoreItem

	type candidateGrant struct {
		persona  PersonaID
		provider ProviderID
		scopes   []string
		token    string
	}
	var candidates []candidateGrant
	for _, persona := range []PersonaID{PersonaAlice, PersonaBob} {
		for _, provider := range []ProviderID{ProviderGoogleGmail, ProviderAtlassianJira, ProviderGitHub, ProviderGCPIAM} {
			candidates = append(candidates, candidateGrant{
				persona:  persona,
				provider: provider,
				scopes:   defaultScopesForProvider(provider),
				token:    b.configuredOrDefaultPersonaToken(persona, provider),
			})
		}
	}

	b.mu.Lock()
	for _, c := range candidates {
		slot := grantSlotKey{sessionID: sessionID, persona: c.persona, provider: c.provider}
		if b.revoked[slot] {
			continue
		}
		if _, exists := b.grantMeta[slot]; exists {
			continue
		}
		b.grantMeta[slot] = ephemeralGrantMeta{
			SessionID:           sessionID,
			Persona:             c.persona,
			Provider:            c.provider,
			Scopes:              c.scopes,
			AuthMethod:          "warm_session_seed",
			PKCEVerified:        false,
			CodeChallengeMethod: "",
			IssuedAt:            now,
			ExpiresAt:           expiresAt,
		}
		toStore = append(toStore, pendingStoreItem{
			key:   b.credentialKey(sessionID, c.persona, c.provider, c.scopes),
			token: c.token,
		})
	}
	b.mu.Unlock()

	ctx := context.Background()
	for _, item := range toStore {
		_ = b.store.Set(ctx, item.key, auth.BearerCredential{Token: item.token}, storeExpiry)
	}
}

func (b *TokenBroker) pruneExpiredGrants(ctx context.Context, sessionID string) *SessionSnapshot {
	if sessionID == "" {
		sessionID = "default-session"
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()

	type expiredItem struct {
		persona  PersonaID
		provider ProviderID
		scopes   []string
	}
	var expired []expiredItem
	activeByPersona := map[PersonaID][]EphemeralPKCEGrant{
		PersonaAlice: {},
		PersonaBob:   {},
	}
	activeSet := map[PersonaID]map[ProviderID]bool{
		PersonaAlice: {},
		PersonaBob:   {},
	}

	b.mu.Lock()
	for slot, meta := range b.grantMeta {
		if slot.sessionID != sessionID {
			continue
		}
		if b.revoked[slot] {
			delete(b.grantMeta, slot)
			delete(b.nonFixtureGrants, slot)
			expired = append(expired, expiredItem{
				persona:  meta.Persona,
				provider: meta.Provider,
				scopes:   meta.Scopes,
			})
			continue
		}
		defKey := b.credentialKey(sessionID, meta.Persona, meta.Provider, defaultScopesForProvider(meta.Provider))
		_, hit, err := b.store.Get(ctx, defKey)
		if !meta.ExpiresAt.After(now) || err != nil || !hit {
			delete(b.grantMeta, slot)
			delete(b.nonFixtureGrants, slot)
			expired = append(expired, expiredItem{
				persona:  meta.Persona,
				provider: meta.Provider,
				scopes:   meta.Scopes,
			})
			continue
		}
		rem := int(math.Ceil(meta.ExpiresAt.Sub(now).Seconds()))
		if rem < 1 {
			rem = 1
		}
		if activeSet[meta.Persona] == nil {
			activeSet[meta.Persona] = make(map[ProviderID]bool)
		}
		activeSet[meta.Persona][meta.Provider] = true
		activeByPersona[meta.Persona] = append(activeByPersona[meta.Persona], EphemeralPKCEGrant{
			Provider:            meta.Provider,
			Persona:             meta.Persona,
			Scopes:              append([]string(nil), meta.Scopes...),
			AuthMethod:          meta.AuthMethod,
			PKCEVerified:        meta.PKCEVerified,
			CodeChallengeMethod: meta.CodeChallengeMethod,
			IssuedAt:            meta.IssuedAt,
			ExpiresAt:           meta.ExpiresAt,
			TTLRemainingSeconds: rem,
		})
	}
	b.mu.Unlock()

	for _, exp := range expired {
		_ = b.store.Delete(ctx, b.credentialKey(sessionID, exp.persona, exp.provider, exp.scopes))
		_ = b.store.Delete(ctx, b.credentialKey(sessionID, exp.persona, exp.provider, defaultScopesForProvider(exp.provider)))
	}

	for persona := range activeByPersona {
		sort.Slice(activeByPersona[persona], func(i, j int) bool {
			return activeByPersona[persona][i].Provider < activeByPersona[persona][j].Provider
		})
	}

	return b.rt.mutateSessionRaw(sessionID, func(s *SessionSnapshot) {
		if s.GrantedProviders == nil {
			s.GrantedProviders = make(map[PersonaID][]ProviderID)
		}
		for persona, list := range s.GrantedProviders {
			filtered := make([]ProviderID, 0, len(list))
			for _, p := range list {
				if activeSet[persona] != nil && activeSet[persona][p] {
					filtered = append(filtered, p)
				}
			}
			s.GrantedProviders[persona] = filtered
		}
		s.EphemeralGrants = activeByPersona
	})
}

func (b *TokenBroker) seedConfiguredTokens(ctx context.Context, sessionID string) {
	if b.rt == nil {
		return
	}
	storeExpiry := time.Now().UTC().Add(defaultCredentialTTL).Add(auth.ExpirySkew)
	for _, persona := range []PersonaID{PersonaAlice, PersonaBob} {
		for _, provider := range []ProviderID{ProviderGitHub, ProviderGoogleGmail, ProviderAtlassianJira, ProviderGCPIAM} {
			if tok := b.configuredPersonaToken(persona, provider); tok != "" {
				scopes := defaultScopesForProvider(provider)
				key := b.credentialKey(sessionID, persona, provider, scopes)
				_ = b.store.Set(ctx, key, auth.BearerCredential{Token: tok}, storeExpiry)
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

	if inv.RequireCold3LOConsent || !b.hasActiveGrant(ctx, inv.SessionID, inv.Persona, inv.Provider) {
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

	slot := grantSlotKey{sessionID: inv.SessionID, persona: inv.Persona, provider: inv.Provider}
	b.mu.RLock()
	meta, hasMeta := b.grantMeta[slot]
	b.mu.RUnlock()
	if !hasMeta || !meta.ExpiresAt.After(time.Now().UTC()) {
		challenge := b.issueConsentChallenge(inv.SessionID, inv.Persona, inv.Provider, inv.Scopes)
		return nil, fmt.Errorf("tokenbroker: 3LO consent required for %s/%s: %w", inv.Persona, inv.Provider, &auth.ConsentRequiredError{
			AuthURI: challenge.AuthURI,
			Nonce:   challenge.Nonce,
			Key:     key.Key,
		})
	}

	storeExpiry := meta.ExpiresAt.Add(auth.ExpirySkew)
	defKey := b.credentialKey(inv.SessionID, inv.Persona, inv.Provider, defaultScopesForProvider(inv.Provider))
	if defCred, hit, err := b.store.Get(ctx, defKey); err == nil && hit {
		_ = b.store.Set(ctx, key, defCred, storeExpiry)
		return defCred, nil
	}

	token := b.configuredOrDefaultPersonaToken(inv.Persona, inv.Provider)
	cred := auth.BearerCredential{Token: token}
	_ = b.store.Set(ctx, key, cred, storeExpiry)
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

// ErrPKCEVerificationFailed indicates an invalid, missing, expired, or replayed RFC 7636 S256 PKCE verifier.
var ErrPKCEVerificationFailed = errors.New("tokenbroker: OAuth 2.0 S256 PKCE verification failed")

func (b *TokenBroker) pruneExpiredPKCEChallengesLocked(now time.Time) {
	for k, st := range b.pkceChallenges {
		if !st.ExpiresAt.After(now) {
			delete(b.pkceChallenges, k)
		}
	}
	for k, exp := range b.consumedNonces {
		if !exp.After(now) {
			delete(b.consumedNonces, k)
		}
	}
}

func (b *TokenBroker) verifyAndConsumePKCE(nonce, codeVerifier string) (string, bool, error) {
	nonce = strings.TrimSpace(nonce)
	codeVerifier = strings.TrimSpace(codeVerifier)
	now := time.Now().UTC()

	b.mu.Lock()
	defer b.mu.Unlock()

	if nonce != "" {
		if exp, consumed := b.consumedNonces[nonce]; consumed && exp.After(now) {
			b.pruneExpiredPKCEChallengesLocked(now)
			return "", false, fmt.Errorf("%w: challenge nonce already consumed", ErrPKCEVerificationFailed)
		}
	}

	b.pruneExpiredPKCEChallengesLocked(now)

	if nonce != "" {
		st, ok := b.pkceChallenges[nonce]
		if !ok {
			return "", false, fmt.Errorf("%w: unknown or expired PKCE challenge state", ErrPKCEVerificationFailed)
		}
		candidate := codeVerifier
		if candidate == "" {
			if st.ClientBoundPKCE {
				return "", false, fmt.Errorf("%w: missing code_verifier for client-bound S256 PKCE challenge", ErrPKCEVerificationFailed)
			}
			candidate = st.CodeVerifier
		}
		computed := computeS256CodeChallenge(candidate)
		if subtle.ConstantTimeCompare([]byte(computed), []byte(st.CodeChallenge)) != 1 {
			return "", false, fmt.Errorf("%w: S256 code_verifier mismatch", ErrPKCEVerificationFailed)
		}
		delete(b.pkceChallenges, nonce)
		b.consumedNonces[nonce] = now.Add(consumedNonceTTL)
		return candidate, true, nil
	}

	if codeVerifier != "" {
		return "", false, fmt.Errorf("%w: unknown or expired PKCE challenge state", ErrPKCEVerificationFailed)
	}
	return "", false, nil
}

// VerifyAndGrant validates any RFC 7636 S256 PKCE challenge/verifier pair on req before granting the token.
func (b *TokenBroker) VerifyAndGrant(ctx context.Context, req OAuthGrantRequest) (*SessionSnapshot, error) {
	_, verified, err := b.verifyAndConsumePKCE(req.Nonce, req.CodeVerifier)
	if err != nil {
		return nil, err
	}
	return b.grantInternal(ctx, req, verified), nil
}

func normalizeNonPKCEAuthMethod(raw string) string {
	switch strings.TrimSpace(raw) {
	case "fixture_seed", "warm_session_seed", "a2a_server_side_oauth2", "direct_grant":
		return strings.TrimSpace(raw)
	default:
		return "direct_grant"
	}
}

// Grant stores a 3LO token for (SessionID, Persona, Provider, Scopes) and marks the provider granted.
func (b *TokenBroker) Grant(ctx context.Context, req OAuthGrantRequest) *SessionSnapshot {
	return b.grantInternal(ctx, req, false)
}

func (b *TokenBroker) grantInternal(ctx context.Context, req OAuthGrantRequest, pkceVerified bool) *SessionSnapshot {
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

	ttl := defaultCredentialTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	authMethod := normalizeNonPKCEAuthMethod(req.AuthMethod)
	codeChallengeMethod := ""
	if pkceVerified {
		authMethod = "oauth2_pkce_s256"
		codeChallengeMethod = pkceCodeChallengeMethod
	}

	b.rt.ensureSessionInitialized(sessionID)

	b.mu.Lock()
	slot := grantSlotKey{sessionID: sessionID, persona: persona, provider: provider}
	delete(b.revoked, slot)
	if !isFixture3LOToken(token) {
		b.nonFixtureGrants[slot] = token
	} else {
		delete(b.nonFixtureGrants, slot)
	}
	b.grantMeta[slot] = ephemeralGrantMeta{
		SessionID:           sessionID,
		Persona:             persona,
		Provider:            provider,
		Scopes:              append([]string(nil), scopes...),
		AuthMethod:          authMethod,
		PKCEVerified:        pkceVerified,
		CodeChallengeMethod: codeChallengeMethod,
		IssuedAt:            now,
		ExpiresAt:           expiresAt,
	}
	b.mu.Unlock()

	// Offset ADK InMemoryCredentialStore's internal 10s ExpirySkew so sub-10s TTL overrides
	// remain readable until exact wall-clock expiresAt, when pruneExpiredGrants deletes them.
	storeExpiry := expiresAt.Add(auth.ExpirySkew)
	key := b.credentialKey(sessionID, persona, provider, scopes)
	_ = b.store.Set(ctx, key, auth.BearerCredential{Token: token}, storeExpiry)
	// Also warm the default scope key so callers omitting explicit scopes find the grant
	defKey := b.credentialKey(sessionID, persona, provider, defaultScopesForProvider(provider))
	_ = b.store.Set(ctx, defKey, auth.BearerCredential{Token: token}, storeExpiry)

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
	slot := grantSlotKey{sessionID: sessionID, persona: persona, provider: provider}
	b.revoked[slot] = true
	delete(b.nonFixtureGrants, slot)
	delete(b.grantMeta, slot)
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

// HasNonFixtureGrant returns true when any active session holds a granted, non-expired non-fixture 3LO token for provider.
func (b *TokenBroker) HasNonFixtureGrant(provider ProviderID) bool {
	if b == nil {
		return false
	}
	now := time.Now().UTC()
	ctx := context.Background()
	b.mu.RLock()
	defer b.mu.RUnlock()
	for slot, tok := range b.nonFixtureGrants {
		if slot.provider != provider || b.revoked[slot] || isFixture3LOToken(tok) {
			continue
		}
		if meta, hasMeta := b.grantMeta[slot]; hasMeta && !meta.ExpiresAt.After(now) {
			continue
		}
		defKey := b.credentialKey(slot.sessionID, slot.persona, slot.provider, defaultScopesForProvider(slot.provider))
		if _, hit, err := b.store.Get(ctx, defKey); err != nil || !hit {
			continue
		}
		return true
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

func (b *TokenBroker) hasActiveGrant(ctx context.Context, sessionID string, persona PersonaID, provider ProviderID) bool {
	if sessionID == "" {
		sessionID = "default-session"
	}
	if persona == "" {
		persona = PersonaAlice
	}
	if provider == "" {
		provider = ProviderAtlassianJira
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b.rt.ensureSessionInitialized(sessionID)

	slot := grantSlotKey{sessionID: sessionID, persona: persona, provider: provider}
	b.mu.RLock()
	isRevoked := b.revoked[slot]
	meta, hasMeta := b.grantMeta[slot]
	b.mu.RUnlock()
	if isRevoked {
		return false
	}

	defKey := b.credentialKey(sessionID, persona, provider, defaultScopesForProvider(provider))
	_, hit, err := b.store.Get(ctx, defKey)
	if !hasMeta || !meta.ExpiresAt.After(time.Now().UTC()) || err != nil || !hit {
		b.pruneExpiredGrants(ctx, sessionID)
		return false
	}

	snap := b.pruneExpiredGrants(ctx, sessionID)
	for _, p := range snap.GrantedProviders[persona] {
		if p == provider {
			return true
		}
	}
	return false
}

func (b *TokenBroker) issueConsentChallenge(sessionID string, persona PersonaID, provider ProviderID, scopes []string) ConsentChallenge {
	return b.issueConsentChallengeWithPKCE(sessionID, persona, provider, scopes, "")
}

func (b *TokenBroker) issueConsentChallengeWithPKCE(sessionID string, persona PersonaID, provider ProviderID, scopes []string, clientCodeChallenge string) ConsentChallenge {
	if sessionID == "" {
		sessionID = "default-session"
	}
	if persona == "" {
		persona = PersonaAlice
	}
	if provider == "" {
		provider = ProviderAtlassianJira
	}
	nonce := randomHex(12)
	var (
		codeVerifier  string
		codeChallenge string
		clientBound   bool
	)
	if trimmed := strings.TrimSpace(clientCodeChallenge); trimmed != "" {
		codeChallenge = trimmed
		clientBound = true
	} else {
		codeVerifier = generatePKCEVerifier()
		codeChallenge = computeS256CodeChallenge(codeVerifier)
	}

	q := url.Values{}
	q.Set("client_id", "aegis-sre-3lo-client")
	q.Set("response_type", "code")
	q.Set("session_id", sessionID)
	q.Set("persona", string(persona))
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", pkceCodeChallengeMethod)

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

	scopesCopy := append([]string(nil), scopes...)
	ch := ConsentChallenge{
		Provider:            provider,
		Persona:             persona,
		Scopes:              scopesCopy,
		AuthURI:             baseAuthURL + "?" + q.Encode(),
		Nonce:               nonce,
		ResourceRef:         resourceRef,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: pkceCodeChallengeMethod,
		ExpiresInSeconds:    int(defaultCredentialTTL.Seconds()),
	}
	now := time.Now().UTC()
	targetSlot := grantSlotKey{sessionID: sessionID, persona: persona, provider: provider}

	b.mu.Lock()
	b.pruneExpiredPKCEChallengesLocked(now)
	for k, st := range b.pkceChallenges {
		if (grantSlotKey{sessionID: st.SessionID, persona: st.Persona, provider: st.Provider}) == targetSlot {
			delete(b.pkceChallenges, k)
		}
	}
	b.pkceChallenges[nonce] = PKCEChallengeState{
		SessionID:           sessionID,
		Persona:             persona,
		Provider:            provider,
		Scopes:              scopesCopy,
		Nonce:               nonce,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: pkceCodeChallengeMethod,
		ClientBoundPKCE:     clientBound,
		ExpiresAt:           now.Add(pkceChallengeTTL),
	}
	b.mu.Unlock()
	return ch
}

func generatePKCEVerifier() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// Deterministic length fallback only on OS CSPRNG failure
		sum := sha256.Sum256([]byte(fmt.Sprintf("pkce-fallback-%d", time.Now().UnixNano())))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func computeS256CodeChallenge(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func enrichConsentChallenge(ch *ConsentChallenge) {
	if ch == nil {
		return
	}
	if ch.ExpiresInSeconds == 0 {
		ch.ExpiresInSeconds = int(defaultCredentialTTL.Seconds())
	}
	if ch.CodeChallengeMethod == "" {
		ch.CodeChallengeMethod = pkceCodeChallengeMethod
	}
	if ch.CodeChallenge == "" && ch.AuthURI != "" {
		if u, err := url.Parse(ch.AuthURI); err == nil {
			if cc := u.Query().Get("code_challenge"); cc != "" {
				ch.CodeChallenge = cc
			}
			if ccm := u.Query().Get("code_challenge_method"); ccm != "" {
				ch.CodeChallengeMethod = ccm
			}
		}
	}
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
	enrichConsentChallenge(ch)
	return A2UICard{
		SurfaceID: surfaceID,
		MimeType:  "application/json+a2ui",
		Version:   "0.9",
		Type:      CardConsentChallenge,
		Title:     "Per-User 3LO OAuth Consent Required",
		Subtitle:  "Boundary 3: Identity & 3LO Token Broker (OAuth 2.0 + S256 PKCE)",
		Severity:  "WARNING",
		Body:      fmt.Sprintf("Operator persona %q has not granted %q access (%s) in this session. Authorize via OAuth 2.0 + S256 PKCE to mint a 15-minute ephemeral in-memory grant.", persona, ch.Provider, strings.Join(ch.Scopes, ", ")),
		Fields: map[string]string{
			"Persona":     string(persona),
			"Provider":    string(ch.Provider),
			"Scopes":      strings.Join(ch.Scopes, ", "),
			"Resource":    ch.ResourceRef,
			"PKCE Method": ch.CodeChallengeMethod,
			"Grant TTL":   "15m (ephemeral in-memory)",
		},
		Actions: []A2UICardAction{
			{
				ID:       "act-oauth-grant",
				Label:    fmt.Sprintf("Authorize %s as %s (OAuth 2.0 + PKCE)", ch.Provider, persona),
				Kind:     "oauth_consent",
				Endpoint: fmt.Sprintf("/api/sessions/%s/oauth/grant", sessionID),
				Payload: map[string]string{
					"persona":             string(persona),
					"provider":            string(ch.Provider),
					"nonce":               ch.Nonce,
					"codeChallenge":       ch.CodeChallenge,
					"codeChallengeMethod": ch.CodeChallengeMethod,
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
		codeChallenge := strings.TrimSpace(r.URL.Query().Get("code_challenge"))
		codeChallengeMethod := strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
		if codeChallengeMethod != "" && codeChallengeMethod != pkceCodeChallengeMethod {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "unsupported code_challenge_method: RFC 7636 S256 is required",
			})
			return
		}
		ch := rt.TokenBroker().issueConsentChallengeWithPKCE(sessionID, persona, provider, scopes, codeChallenge)
		writeJSON(w, http.StatusOK, ch)
	})

	mux.HandleFunc("GET /oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		provider := ProviderID(r.PathValue("provider"))
		sessionID := firstNonEmpty(r.URL.Query().Get("session_id"), r.URL.Query().Get("sessionId"), "default-session")
		persona := PersonaID(firstNonEmpty(r.URL.Query().Get("persona"), string(PersonaAlice)))
		code := firstNonEmpty(r.URL.Query().Get("code"), "oauthcode")
		nonce := firstNonEmpty(r.URL.Query().Get("nonce"), r.URL.Query().Get("state"))
		codeVerifier := firstNonEmpty(r.URL.Query().Get("code_verifier"), r.URL.Query().Get("codeVerifier"))

		if strings.TrimSpace(nonce) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("%s: missing OAuth state/nonce parameter", ErrPKCEVerificationFailed),
			})
			return
		}

		resolvedVerifier, verified, err := rt.TokenBroker().verifyAndConsumePKCE(nonce, codeVerifier)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if !verified {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("%s: unverified OAuth callback state", ErrPKCEVerificationFailed),
			})
			return
		}

		token := rt.TokenBroker().configuredPersonaToken(persona, provider)
		if exchanged, err := rt.TokenBroker().exchangeOAuthCode(r.Context(), provider, code, resolvedVerifier); err == nil && exchanged != "" {
			token = exchanged
		}
		if token == "" {
			token = fmt.Sprintf("3lo-%s-%s-%s", persona, provider, code)
		}

		var ttlSeconds int
		if rawTTL := firstNonEmpty(r.URL.Query().Get("ttl_seconds"), r.URL.Query().Get("ttlSeconds")); rawTTL != "" {
			if parsed, convErr := strconv.Atoi(rawTTL); convErr == nil && parsed > 0 {
				ttlSeconds = parsed
			}
		}

		snap := rt.TokenBroker().grantInternal(r.Context(), OAuthGrantRequest{
			SessionID:  sessionID,
			Persona:    persona,
			Provider:   provider,
			Token:      token,
			TTLSeconds: ttlSeconds,
		}, true)
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
		req.AuthMethod = ""
		snap, err := rt.TokenBroker().VerifyAndGrant(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
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
		return []string{
			"openid",
			"email",
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/drive.readonly",
			"https://www.googleapis.com/auth/calendar.readonly",
		}
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

func (b *TokenBroker) exchangeOAuthCode(ctx context.Context, provider ProviderID, code string, codeVerifier string) (string, error) {
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
	if trimmedVerifier := strings.TrimSpace(codeVerifier); trimmedVerifier != "" {
		form.Set("code_verifier", trimmedVerifier)
	}

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
