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
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/auth/gcp"
)

func init() {
	RegisterScenarioHandler(Scenario02ConfusedDeputy3LO, executeScenario02)
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
	rt        *Runtime
	store     auth.CredentialStore
	mu        sync.RWMutex
	gcpClient *gcp.Client
	revoked   map[string]bool
	nonces    map[string]ConsentChallenge
}

// NewTokenBroker constructs a TokenBroker bound to rt.
func NewTokenBroker(rt *Runtime) *TokenBroker {
	return &TokenBroker{
		rt:      rt,
		store:   auth.NewInMemoryCredentialStore(),
		revoked: make(map[string]bool),
		nonces:  make(map[string]ConsentChallenge),
	}
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

	// Seed deterministic per-persona 3LO token for warm session fixture
	token := defaultPersona3LOToken(inv.Persona, inv.Provider)
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
	token := strings.TrimSpace(req.Token)
	if token == "" {
		token = defaultPersona3LOToken(persona, provider)
	}

	b.mu.Lock()
	delete(b.revoked, revocationSlot(sessionID, persona, provider))
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
	b.revoked[revocationSlot(sessionID, persona, provider)] = true
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
	switch provider {
	case ProviderAtlassianJira:
		baseAuthURL = "https://auth.atlassian.com/authorize"
	case ProviderGitHub:
		baseAuthURL = "https://github.com/login/oauth/authorize"
	case ProviderGoogleGmail:
		baseAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	default:
		baseAuthURL = fmt.Sprintf("/oauth/%s/authorize", provider)
	}

	ch := ConsentChallenge{
		Provider:    provider,
		Persona:     persona,
		Scopes:      append([]string(nil), scopes...),
		AuthURI:     baseAuthURL + "?" + q.Encode(),
		Nonce:       nonce,
		ResourceRef: "SEC-101",
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

func executeScenario02(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
	broker := rt.TokenBroker()
	trace := make([]BoundaryTraceEvent, 0, 3)
	wireRecords := make([]OutboundWireRecord, 0, 2)
	var wireMu sync.Mutex

	downstream := roundTripFuncInternal(func(httpReq *http.Request) (*http.Response, error) {
		authHeader := httpReq.Header.Get("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
		principal := classifyPrincipal(token)
		toolName := "jira_get_issue"
		provider := ProviderAtlassianJira
		if strings.Contains(httpReq.URL.Host, "github.com") {
			toolName = "github_get_security_advisory"
			provider = ProviderGitHub
		}

		status := http.StatusOK
		respPayload := map[string]any{
			"id":             "SEC-101",
			"classification": "RESTRICTED_SECOPS_ONLY",
			"summary":        "P0 OAuth Token Exfiltration Investigation in checkout-service",
			"advisory":       "GHSA-sec-101",
			"authorizedAs":   principal,
		}

		// Enforce downstream resource ACLs:
		// - Alice's 3LO token ("3lo-alice-...") has SecOps Lead access -> 200 OK
		// - Shared root service token ("shared-service-account-root-token") has full admin access -> 200 OK (Confused Deputy!)
		// - Bob's 3LO token ("3lo-bob-...") is an External Contractor limited to PUB-202 -> 403 Forbidden on SEC-101 & GHSA-sec-101
		if strings.HasPrefix(token, "3lo-bob-") {
			status = http.StatusForbidden
			respPayload = map[string]any{
				"error":    "ACL_FORBIDDEN",
				"resource": "SEC-101",
				"message":  "Persona 'bob' (External Contractor) lacks 'secops:restricted:read' permission on SEC-101 (allowed: PUB-202 only)",
			}
		}

		wireMu.Lock()
		wireRecords = append(wireRecords, OutboundWireRecord{
			Provider:          provider,
			ToolName:          toolName,
			Method:            httpReq.Method,
			URL:               httpReq.URL.String(),
			AuthHeaderPresent: authHeader != "",
			AuthPrincipal:     principal,
			StatusCode:        status,
		})
		wireMu.Unlock()

		rawBytes, _ := json.Marshal(respPayload)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(rawBytes))),
			Request:    httpReq,
		}, nil
	})

	transportClient := &http.Client{
		Transport: &auth.Transport{
			Provider: broker,
			Base:     downstream,
		},
	}

	// Step 1: Outbound call to Atlassian Jira for restricted issue SEC-101
	jiraCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID:             req.SessionID,
		Persona:               req.Persona,
		Provider:              ProviderAtlassianJira,
		Scopes:                defaultScopesForProvider(ProviderAtlassianJira),
		BypassBrokerRedMode:   !req.Posture.TokenBrokerEnabled,
		RequireCold3LOConsent: req.RequireCold3LOConsent,
	})
	jiraHTTPReq, err := http.NewRequestWithContext(jiraCtx, http.MethodGet, jiraIssueSEC101URL, nil)
	if err != nil {
		return nil, err
	}
	jiraResp, err := transportClient.Do(jiraHTTPReq)
	if err != nil {
		var consentErr *auth.ConsentRequiredError
		if errors.As(err, &consentErr) {
			ch := &ConsentChallenge{
				Provider:    ProviderAtlassianJira,
				Persona:     req.Persona,
				Scopes:      defaultScopesForProvider(ProviderAtlassianJira),
				AuthURI:     consentErr.AuthURI,
				Nonce:       consentErr.Nonce,
				ResourceRef: "SEC-101",
			}
			trace = append(trace, BoundaryTraceEvent{
				Order:     1,
				Boundary:  BoundaryIdentity3LO,
				Shield:    "Token Broker (3LO)",
				Component: "adk/v2/auth.Transport",
				Action:    "jira_get_issue(SEC-101)",
				Verdict:   VerdictChallenge,
				Detail:    fmt.Sprintf("Missing 3LO OAuth grant for persona %q on provider %q; emitted adk_request_credential ConsentChallenge", req.Persona, ProviderAtlassianJira),
				Timestamp: time.Now().UTC(),
			})
			card := A2UICard{
				SurfaceID: "card-consent-s2",
				MimeType:  "application/json+a2ui",
				Version:   "0.9",
				Type:      CardConsentChallenge,
				Title:     "Per-User 3LO OAuth Consent Required",
				Subtitle:  "Boundary 3: Identity & 3LO Token Broker (adk_request_credential)",
				Severity:  "WARNING",
				Body:      fmt.Sprintf("Operator persona %q has not granted %q access (%s) in this session. Authorize 3LO access to continue.", req.Persona, ProviderAtlassianJira, strings.Join(ch.Scopes, ", ")),
				Fields: map[string]string{
					"Persona":  string(req.Persona),
					"Provider": string(ProviderAtlassianJira),
					"Scopes":   strings.Join(ch.Scopes, ", "),
					"Resource": "SEC-101",
				},
				Actions: []A2UICardAction{
					{
						ID:       "act-oauth-grant",
						Label:    fmt.Sprintf("Authorize %s as %s (3LO)", ProviderAtlassianJira, req.Persona),
						Kind:     "oauth_consent",
						Endpoint: fmt.Sprintf("/api/sessions/%s/oauth/grant", req.SessionID),
						Payload: map[string]string{
							"persona":  string(req.Persona),
							"provider": string(ProviderAtlassianJira),
							"nonce":    ch.Nonce,
						},
					},
				},
			}
			return &TurnResult{
				SessionID:        req.SessionID,
				Persona:          req.Persona,
				ScenarioID:       req.ScenarioID,
				Posture:          req.Posture,
				Outcome:          OutcomeConsentRequired,
				AssistantText:    fmt.Sprintf("Paused tool execution: %s requires per-user 3LO OAuth consent from %s before accessing SEC-101.", ProviderAtlassianJira, req.Persona),
				Cards:            []A2UICard{card},
				BoundaryTrace:    trace,
				ConsentChallenge: ch,
				WireRecords:      wireRecords,
			}, nil
		}
		return nil, err
	}
	defer jiraResp.Body.Close()

	// If Jira returned 403 Forbidden (Blue Mode with PersonaBob)
	if jiraResp.StatusCode == http.StatusForbidden {
		trace = append(trace, BoundaryTraceEvent{
			Order:     1,
			Boundary:  BoundaryIdentity3LO,
			Shield:    "Token Broker (3LO)",
			Component: "adk/v2/auth.Transport",
			Action:    "jira_get_issue(SEC-101)",
			Verdict:   VerdictBlocked,
			Detail:    fmt.Sprintf("Injected %s's scoped 3LO bearer token on the HTTP wire; Atlassian Jira denied access to SEC-101 with 403 Forbidden (Zero Confused Deputy)", req.Persona),
			Metadata: map[string]string{
				"persona":    string(req.Persona),
				"provider":   string(ProviderAtlassianJira),
				"httpStatus": "403",
			},
			Timestamp: time.Now().UTC(),
		})
		card := A2UICard{
			SurfaceID: "card-acl-denial-s2",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardAclDenial,
			Title:     "Downstream 403 Forbidden — Confused Deputy Prevented",
			Subtitle:  "Boundary 3: Per-Persona 3LO Token Broker via auth.Transport",
			Severity:  "HIGH",
			Body:      "Token Broker attached Bob's personal 3LO OAuth credential onto the outbound Jira request instead of the agent's shared identity. Jira enforced per-user ACLs and blocked access to restricted SecOps issue SEC-101.",
			Fields: map[string]string{
				"Active Persona":    "bob (External Contractor)",
				"Target Resource":   "Jira Issue SEC-101 (Restricted SecOps)",
				"Allowed Scope":     "PUB-202 only",
				"Downstream Status": "403 Forbidden",
			},
		}
		return &TurnResult{
			SessionID:     req.SessionID,
			Persona:       req.Persona,
			ScenarioID:    req.ScenarioID,
			Posture:       req.Posture,
			Outcome:       OutcomeBlocked,
			AssistantText: "Access denied (403 Forbidden): Persona 'bob' (External Contractor) is not authorized to read restricted SecOps Jira issue SEC-101.",
			Cards:         []A2UICard{card},
			BoundaryTrace: trace,
			WireRecords:   wireRecords,
		}, nil
	}

	// Step 2: Outbound call to GitHub for private security advisory GHSA-sec-101
	ghCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID:             req.SessionID,
		Persona:               req.Persona,
		Provider:              ProviderGitHub,
		Scopes:                defaultScopesForProvider(ProviderGitHub),
		BypassBrokerRedMode:   !req.Posture.TokenBrokerEnabled,
		RequireCold3LOConsent: req.RequireCold3LOConsent,
	})
	ghHTTPReq, err := http.NewRequestWithContext(ghCtx, http.MethodGet, githubAdvisorySEC101URL, nil)
	if err != nil {
		return nil, err
	}
	ghResp, err := transportClient.Do(ghHTTPReq)
	if err != nil {
		return nil, err
	}
	defer ghResp.Body.Close()

	// Red Mode: Confused Deputy exploit when TokenBrokerEnabled is false
	if !req.Posture.TokenBrokerEnabled {
		trace = append(trace, BoundaryTraceEvent{
			Order:     1,
			Boundary:  BoundaryIdentity3LO,
			Shield:    "Token Broker (3LO)",
			Component: "StaticToken(shared-service-account-root-token)",
			Action:    "jira_get_issue(SEC-101) + github_get_security_advisory(GHSA-sec-101)",
			Verdict:   VerdictBypassedRed,
			Detail:    fmt.Sprintf("CONFUSED DEPUTY EXPLOIT: Per-User 3LO Token Broker disabled; outbound requests for %q used shared root service token and leaked restricted SEC-101!", req.Persona),
			Timestamp: time.Now().UTC(),
		})
		card := A2UICard{
			SurfaceID: "card-exploited-s2",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardIncidentSummary,
			Title:     "RED MODE EXPLOITED: Confused Deputy Leaked Restricted SEC-101 to Contractor",
			Subtitle:  "Unscoped Shared Service Account Token Used on Wire",
			Severity:  "DANGER",
			Body:      "Because the Per-User 3LO Token Broker shield was disabled, the agent authenticated to Jira and GitHub using its shared root service token instead of Bob's 3LO credential, leaking restricted SecOps issue SEC-101 and private advisory GHSA-sec-101.",
			Fields: map[string]string{
				"Invoking Persona": string(req.Persona),
				"Wire Credential":  "shared-service-account-root-token (Confused Deputy)",
				"Leaked Issue":     "SEC-101: P0 OAuth Token Exfiltration Investigation",
				"Leaked Advisory":  "GHSA-sec-101 (Private Repository)",
			},
		}
		return &TurnResult{
			SessionID:     req.SessionID,
			Persona:       req.Persona,
			ScenarioID:    req.ScenarioID,
			Posture:       req.Posture,
			Outcome:       OutcomeExploitedRed,
			AssistantText: fmt.Sprintf("RED MODE CONFUSED DEPUTY: Retrieved restricted SecOps Jira issue SEC-101 and private GitHub advisory GHSA-sec-101 for %s using shared-service-account-root-token.", req.Persona),
			Cards:         []A2UICard{card},
			BoundaryTrace: trace,
			WireRecords:   wireRecords,
		}, nil
	}

	// Blue Mode Defended Success (PersonaAlice)
	trace = append(trace, BoundaryTraceEvent{
		Order:     1,
		Boundary:  BoundaryIdentity3LO,
		Shield:    "Token Broker (3LO)",
		Component: "adk/v2/auth.Transport",
		Action:    "jira_get_issue(SEC-101) + github_get_security_advisory(GHSA-sec-101)",
		Verdict:   VerdictAllowed,
		Detail:    fmt.Sprintf("Injected %s's per-provider 3LO OAuth tokens on HTTP transport outside LLM context window; verified 200 OK for SEC-101 and GHSA-sec-101", req.Persona),
		Timestamp: time.Now().UTC(),
	})

	card := A2UICard{
		SurfaceID: "card-summary-s2",
		MimeType:  "application/json+a2ui",
		Version:   "0.9",
		Type:      CardIncidentSummary,
		Title:     "Restricted Incident SEC-101 Correlated via Per-User 3LO Token Broker",
		Subtitle:  "Boundary 3: Wire-Level Credential Injection (adk/v2/auth.Transport)",
		Severity:  "SUCCESS",
		Body:      "Authenticated to Atlassian Jira and GitHub using Alice's isolated 3LO credentials at the HTTP RoundTripper layer. Zero bearer tokens entered the Gemini prompt context.",
		Fields: map[string]string{
			"Authorized Persona": "alice (SecOps Lead)",
			"Jira Issue":         "SEC-101 (200 OK via 3LO)",
			"GitHub Advisory":    "GHSA-sec-101 (200 OK via 3LO)",
			"LLM Context Token":  "NONE (Injected on HTTP wire via auth.Transport)",
		},
	}

	return &TurnResult{
		SessionID:     req.SessionID,
		Persona:       req.Persona,
		ScenarioID:    req.ScenarioID,
		Posture:       req.Posture,
		Outcome:       OutcomeDefendedSuccess,
		AssistantText: "Correlated restricted SecOps Jira issue SEC-101 with private GitHub security advisory GHSA-sec-101 using Alice's 3LO credentials injected at the HTTP transport boundary.",
		Cards:         []A2UICard{card},
		BoundaryTrace: trace,
		WireRecords:   wireRecords,
	}, nil
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
