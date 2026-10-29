package aegis_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gke-demos/agent-security/internal/aegis"
)

var base64URL43Pattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestPKCEVault_Slice1_ColdConsentChallengeAndWorkspaceScopes(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	var iface aegis.AegisRuntime = rt

	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	wantWorkspaceScopes := []string{
		"openid",
		"email",
		"https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/drive.readonly",
		"https://www.googleapis.com/auth/calendar.readonly",
	}

	// 1. Cold 3LO ExecuteTurn across Gmail (Scenario 01), Jira (Scenario 02), and GitHub (Scenario 02 with GitHub revoked)
	revokeBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:  aegis.PersonaAlice,
		Provider: aegis.ProviderGitHub,
	})
	revResp, err := http.Post(srv.URL+"/api/sessions/pkce-s1-github/oauth/revoke", "application/json", bytes.NewReader(revokeBody))
	if err != nil {
		t.Fatalf("POST oauth/revoke github: %v", err)
	}
	revResp.Body.Close()

	turnCases := []struct {
		name         string
		sessionID    string
		scenarioID   aegis.ScenarioID
		prompt       string
		requireCold  bool
		wantProvider aegis.ProviderID
		wantScopes   []string
	}{
		{
			name:         "GoogleWorkspaceGmail",
			sessionID:    "pkce-s1-gmail",
			scenarioID:   aegis.Scenario01PromptInjectionAndPII,
			prompt:       "Triage the latest customer P0 escalation email in Gmail.",
			requireCold:  true,
			wantProvider: aegis.ProviderGoogleGmail,
			wantScopes:   wantWorkspaceScopes,
		},
		{
			name:         "AtlassianJira",
			sessionID:    "pkce-s1-jira",
			scenarioID:   aegis.Scenario02ConfusedDeputy3LO,
			prompt:       "Fetch restricted security issue SEC-101 from Jira.",
			requireCold:  true,
			wantProvider: aegis.ProviderAtlassianJira,
			wantScopes:   []string{"read:jira-work", "write:jira-work"},
		},
		{
			name:         "GitHub",
			sessionID:    "pkce-s1-github",
			scenarioID:   aegis.Scenario02ConfusedDeputy3LO,
			prompt:       "Fetch private GitHub security advisory GHSA-sec-101.",
			requireCold:  false,
			wantProvider: aegis.ProviderGitHub,
			wantScopes:   []string{"repo", "security_events"},
		},
	}

	seenChallenges := map[string]bool{}
	for _, tc := range turnCases {
		t.Run("ColdTurn_"+tc.name, func(t *testing.T) {
			res, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
				SessionID:             tc.sessionID,
				Persona:               aegis.PersonaAlice,
				ScenarioID:            tc.scenarioID,
				Posture:               aegis.AllBluePosture(),
				Prompt:                tc.prompt,
				RequireCold3LOConsent: tc.requireCold,
			})
			if err != nil {
				t.Fatalf("ExecuteTurn(%s) error: %v", tc.name, err)
			}
			if res.Outcome != aegis.OutcomeConsentRequired {
				t.Fatalf("expected OutcomeConsentRequired, got %q", res.Outcome)
			}
			ch := res.ConsentChallenge
			if ch == nil {
				t.Fatalf("expected non-nil ConsentChallenge")
			}
			if ch.Provider != tc.wantProvider {
				t.Fatalf("expected provider %q, got %q", tc.wantProvider, ch.Provider)
			}
			if !reflect.DeepEqual(ch.Scopes, tc.wantScopes) {
				t.Fatalf("expected scopes %v, got %v", tc.wantScopes, ch.Scopes)
			}
			if ch.CodeChallengeMethod != "S256" {
				t.Fatalf("expected CodeChallengeMethod == S256, got %q", ch.CodeChallengeMethod)
			}
			if !base64URL43Pattern.MatchString(ch.CodeChallenge) {
				t.Fatalf("expected 43-char base64url CodeChallenge without padding, got %q (len=%d)", ch.CodeChallenge, len(ch.CodeChallenge))
			}
			if seenChallenges[ch.CodeChallenge] {
				t.Fatalf("expected unique random PKCE CodeChallenge per challenge, got duplicate %q", ch.CodeChallenge)
			}
			seenChallenges[ch.CodeChallenge] = true

			if ch.ExpiresInSeconds != 900 {
				t.Fatalf("expected ExpiresInSeconds == 900 (15m), got %d", ch.ExpiresInSeconds)
			}

			parsedURI, err := url.Parse(ch.AuthURI)
			if err != nil {
				t.Fatalf("invalid AuthURI %q: %v", ch.AuthURI, err)
			}
			if gotCC := parsedURI.Query().Get("code_challenge"); gotCC != ch.CodeChallenge {
				t.Fatalf("AuthURI code_challenge = %q, want %q (authUri=%s)", gotCC, ch.CodeChallenge, ch.AuthURI)
			}
			if gotCCM := parsedURI.Query().Get("code_challenge_method"); gotCCM != "S256" {
				t.Fatalf("AuthURI code_challenge_method = %q, want S256 (authUri=%s)", gotCCM, ch.AuthURI)
			}

			// Verify ConsentChallengeCard label & PKCE metadata
			var foundCard *aegis.A2UICard
			for i := range res.Cards {
				if res.Cards[i].Type == aegis.CardConsentChallenge {
					foundCard = &res.Cards[i]
					break
				}
			}
			if foundCard == nil {
				t.Fatalf("expected ConsentChallengeCard in res.Cards, got %+v", res.Cards)
			}
			if len(foundCard.Actions) == 0 {
				t.Fatalf("expected ConsentChallengeCard action")
			}
			wantLabel := "Authorize " + string(tc.wantProvider) + " as alice (OAuth 2.0 + PKCE)"
			if foundCard.Actions[0].Label != wantLabel {
				t.Fatalf("expected action label %q, got %q", wantLabel, foundCard.Actions[0].Label)
			}
		})
	}

	// 2. GET /oauth/{provider}/authorize for all 3 3LO providers
	for _, provider := range []aegis.ProviderID{aegis.ProviderGoogleGmail, aegis.ProviderGitHub, aegis.ProviderAtlassianJira} {
		t.Run("HTTPAuthorize_"+string(provider), func(t *testing.T) {
			resp, err := http.Get(srv.URL + "/oauth/" + string(provider) + "/authorize?session_id=http-auth-s1&persona=bob")
			if err != nil {
				t.Fatalf("GET authorize error: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
			}
			var ch aegis.ConsentChallenge
			if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
				t.Fatalf("decode ConsentChallenge: %v", err)
			}
			if ch.CodeChallengeMethod != "S256" {
				t.Fatalf("expected CodeChallengeMethod S256, got %q", ch.CodeChallengeMethod)
			}
			if !base64URL43Pattern.MatchString(ch.CodeChallenge) {
				t.Fatalf("expected 43-char base64url CodeChallenge, got %q", ch.CodeChallenge)
			}
			if ch.ExpiresInSeconds != 900 {
				t.Fatalf("expected ExpiresInSeconds 900, got %d", ch.ExpiresInSeconds)
			}
			if provider == aegis.ProviderGoogleGmail && !reflect.DeepEqual(ch.Scopes, wantWorkspaceScopes) {
				t.Fatalf("expected Google Workspace SSO scopes %v, got %v", wantWorkspaceScopes, ch.Scopes)
			}
			u, err := url.Parse(ch.AuthURI)
			if err != nil {
				t.Fatalf("parse AuthURI: %v", err)
			}
			if u.Query().Get("code_challenge") != ch.CodeChallenge || u.Query().Get("code_challenge_method") != "S256" {
				t.Fatalf("AuthURI missing S256 PKCE query params: %s", ch.AuthURI)
			}
		})
	}
}

func makeClientPKCEPair(t *testing.T) (verifier string, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func TestPKCEVault_Slice2_HandshakeVerificationReplayAndTokenExchange(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	var iface aegis.AegisRuntime = rt

	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	// 1. Reject plain / non-S256 code_challenge_method on /authorize with 400 Bad Request
	plainResp, err := http.Get(srv.URL + "/oauth/github/authorize?session_id=pkce-s2&persona=alice&code_challenge=plainval&code_challenge_method=plain")
	if err != nil {
		t.Fatalf("GET authorize plain: %v", err)
	}
	plainResp.Body.Close()
	if plainResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for code_challenge_method=plain, got %d", plainResp.StatusCode)
	}

	// 2. Client-bound S256 PKCE flow via POST /api/sessions/{id}/oauth/grant & GET /oauth/{provider}/callback
	revokeBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:  aegis.PersonaAlice,
		Provider: aegis.ProviderGitHub,
	})
	revResp, err := http.Post(srv.URL+"/api/sessions/pkce-s2/oauth/revoke", "application/json", bytes.NewReader(revokeBody))
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	revResp.Body.Close()

	verifier, challenge := makeClientPKCEPair(t)
	authResp, err := http.Get(srv.URL + "/oauth/github/authorize?session_id=pkce-s2&persona=alice&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET authorize S256: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from authorize, got %d", authResp.StatusCode)
	}
	var ch aegis.ConsentChallenge
	if err := json.NewDecoder(authResp.Body).Decode(&ch); err != nil {
		t.Fatalf("decode ConsentChallenge: %v", err)
	}
	if ch.CodeChallenge != challenge || ch.CodeChallengeMethod != "S256" {
		t.Fatalf("expected echoed client CodeChallenge %q (S256), got %q (%q)", challenge, ch.CodeChallenge, ch.CodeChallengeMethod)
	}

	// 2a. Missing code_verifier on client-bound challenge -> 400 Bad Request
	missingResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s2&persona=alice&code=c1&state=" + url.QueryEscape(ch.Nonce))
	if err != nil {
		t.Fatalf("GET callback missing verifier: %v", err)
	}
	missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when code_verifier is missing on client-bound PKCE, got %d", missingResp.StatusCode)
	}

	// 2a-ii. Tampered code_verifier on GET /oauth/github/callback -> 400 Bad Request
	tamperedCBResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s2&persona=alice&code=c1&state=" + url.QueryEscape(ch.Nonce) + "&code_verifier=tampered_callback_verifier_0000000000000000")
	if err != nil {
		t.Fatalf("GET callback tampered verifier: %v", err)
	}
	tamperedCBResp.Body.Close()
	if tamperedCBResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for tampered code_verifier on GET /callback, got %d", tamperedCBResp.StatusCode)
	}

	// 2b. Tampered code_verifier on POST /oauth/grant -> 400 Bad Request
	tamperedBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderGitHub,
		Nonce:        ch.Nonce,
		CodeVerifier: "tampered_verifier_that_does_not_match_sha256_challenge",
	})
	tamperedResp, err := http.Post(srv.URL+"/api/sessions/pkce-s2/oauth/grant", "application/json", bytes.NewReader(tamperedBody))
	if err != nil {
		t.Fatalf("POST grant tampered: %v", err)
	}
	tamperedResp.Body.Close()
	if tamperedResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for tampered codeVerifier, got %d", tamperedResp.StatusCode)
	}

	// 2c. Tampered code_verifier on CompleteOAuthConsent -> error
	if _, err := iface.CompleteOAuthConsent(ctx, aegis.OAuthCallback{
		SessionID:    "pkce-s2",
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderGitHub,
		Nonce:        ch.Nonce,
		CodeVerifier: "tampered_verifier_via_runtime_seam_00000000000",
	}); err == nil {
		t.Fatalf("expected error from CompleteOAuthConsent on tampered CodeVerifier, got nil")
	}

	// Verify GitHub is still NOT granted after rejected PKCE attempts
	snapBefore, err := iface.GetSessionState(ctx, "pkce-s2")
	if err != nil {
		t.Fatalf("GetSessionState: %v", err)
	}
	for _, p := range snapBefore.GrantedProviders[aegis.PersonaAlice] {
		if p == aegis.ProviderGitHub {
			t.Fatalf("expected github to remain ungranted after tampered PKCE attempts")
		}
	}

	// 2d. Valid code_verifier on POST /oauth/grant -> 200 OK and grants access
	validBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderGitHub,
		Nonce:        ch.Nonce,
		CodeVerifier: verifier,
	})
	validResp, err := http.Post(srv.URL+"/api/sessions/pkce-s2/oauth/grant", "application/json", bytes.NewReader(validBody))
	if err != nil {
		t.Fatalf("POST grant valid: %v", err)
	}
	validResp.Body.Close()
	if validResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for valid S256 codeVerifier, got %d", validResp.StatusCode)
	}

	// 2e. Replay of consumed nonce -> 400 Bad Request (both HTTP and CompleteOAuthConsent)
	replayResp, err := http.Post(srv.URL+"/api/sessions/pkce-s2/oauth/grant", "application/json", bytes.NewReader(validBody))
	if err != nil {
		t.Fatalf("POST grant replay: %v", err)
	}
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when replaying consumed PKCE challenge nonce, got %d", replayResp.StatusCode)
	}
	if _, err := iface.CompleteOAuthConsent(ctx, aegis.OAuthCallback{
		SessionID:    "pkce-s2",
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderGitHub,
		Nonce:        ch.Nonce,
		CodeVerifier: verifier,
	}); err == nil {
		t.Fatalf("expected error when replaying consumed PKCE nonce via CompleteOAuthConsent")
	}

	// 3. Live OAuth code exchange via OAuthTokenEndpointOverride sends code_verifier in POST form
	var receivedForms []url.Values
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(raw))
		receivedForms = append(receivedForms, vals)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_live_pkce_exchanged_token_123"}`))
	}))
	defer tokenSrv.Close()

	liveRT := aegis.NewRuntime(aegis.RuntimeConfig{
		GitHubOAuthClientID:        "gh-client-id",
		GitHubOAuthClientSecret:    "gh-client-secret",
		OAuthTokenEndpointOverride: tokenSrv.URL,
		HTTPClient:                 tokenSrv.Client(),
	})
	liveAppSrv := httptest.NewServer(aegis.NewHTTPHandler(liveRT))
	defer liveAppSrv.Close()

	// 3a. Client-bound PKCE callback exchanges code + code_verifier
	cbVerifier, cbChallenge := makeClientPKCEPair(t)
	liveAuthResp, err := http.Get(liveAppSrv.URL + "/oauth/github/authorize?session_id=live-pkce-sess&persona=alice&code_challenge=" + url.QueryEscape(cbChallenge) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("live authorize: %v", err)
	}
	var liveCh aegis.ConsentChallenge
	_ = json.NewDecoder(liveAuthResp.Body).Decode(&liveCh)
	liveAuthResp.Body.Close()

	cbResp, err := http.Get(liveAppSrv.URL + "/oauth/github/callback?session_id=live-pkce-sess&persona=alice&code=auth_code_pkce_1&state=" + url.QueryEscape(liveCh.Nonce) + "&code_verifier=" + url.QueryEscape(cbVerifier))
	if err != nil {
		t.Fatalf("live callback: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from live PKCE callback, got %d", cbResp.StatusCode)
	}
	if len(receivedForms) != 1 {
		t.Fatalf("expected 1 token exchange POST, got %d", len(receivedForms))
	}
	if got := receivedForms[0].Get("code_verifier"); got != cbVerifier {
		t.Fatalf("expected token exchange POST form code_verifier=%q, got %q", cbVerifier, got)
	}
	if got := receivedForms[0].Get("grant_type"); got != "authorization_code" {
		t.Fatalf("expected grant_type=authorization_code, got %q", got)
	}
}

func TestPKCEVault_Slice3_EphemeralVaultTTLMetadataAndAutoPruning(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	var iface aegis.AegisRuntime = rt

	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	// 1. Grant a custom secret token via S256 PKCE and verify SessionSnapshot exposes
	// EphemeralGrants metadata (15m default TTL) while NEVER leaking raw bearer tokens.
	secretToken := "ephemeral-pkce-vault-bearer-sentinel-999"
	verifier, challenge := makeClientPKCEPair(t)
	authResp, err := http.Get(srv.URL + "/oauth/google_gmail/authorize?session_id=pkce-s3-meta&persona=alice&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	var ch aegis.ConsentChallenge
	_ = json.NewDecoder(authResp.Body).Decode(&ch)
	authResp.Body.Close()

	grantReqBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderGoogleGmail,
		AccessToken:  secretToken,
		Nonce:        ch.Nonce,
		CodeVerifier: verifier,
	})
	grantResp, err := http.Post(srv.URL+"/api/sessions/pkce-s3-meta/oauth/grant", "application/json", bytes.NewReader(grantReqBody))
	if err != nil {
		t.Fatalf("POST grant: %v", err)
	}
	rawSnapBytes, _ := io.ReadAll(grantResp.Body)
	grantResp.Body.Close()
	if grantResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from grant, got %d: %s", grantResp.StatusCode, string(rawSnapBytes))
	}

	// Security assertion: raw bearer token MUST NEVER appear in serialized SessionSnapshot JSON
	if strings.Contains(string(rawSnapBytes), secretToken) {
		t.Fatalf("SECURITY VIOLATION: raw bearer token leaked in SessionSnapshot JSON: %s", string(rawSnapBytes))
	}

	// Also verify GET /api/sessions/{sessionId} never leaks raw token and exposes EphemeralPKCEGrant
	sessResp, err := http.Get(srv.URL + "/api/sessions/pkce-s3-meta")
	if err != nil {
		t.Fatalf("GET session: %v", err)
	}
	sessRaw, _ := io.ReadAll(sessResp.Body)
	sessResp.Body.Close()
	if strings.Contains(string(sessRaw), secretToken) {
		t.Fatalf("SECURITY VIOLATION: raw bearer token leaked in GET /api/sessions response")
	}

	var snap aegis.SessionSnapshot
	if err := json.Unmarshal(sessRaw, &snap); err != nil {
		t.Fatalf("unmarshal SessionSnapshot: %v", err)
	}
	aliceGrants := snap.EphemeralGrants[aegis.PersonaAlice]
	var gmailGrant *aegis.EphemeralPKCEGrant
	for i := range aliceGrants {
		if aliceGrants[i].Provider == aegis.ProviderGoogleGmail {
			gmailGrant = &aliceGrants[i]
			break
		}
	}
	if gmailGrant == nil {
		t.Fatalf("expected google_gmail in snap.EphemeralGrants[alice], got %+v", aliceGrants)
	}
	if gmailGrant.AuthMethod != "oauth2_pkce_s256" {
		t.Fatalf("expected AuthMethod == oauth2_pkce_s256, got %q", gmailGrant.AuthMethod)
	}
	if !gmailGrant.PKCEVerified {
		t.Fatalf("expected PKCEVerified == true")
	}
	if gmailGrant.CodeChallengeMethod != "S256" {
		t.Fatalf("expected CodeChallengeMethod == S256, got %q", gmailGrant.CodeChallengeMethod)
	}
	if gmailGrant.TTLRemainingSeconds <= 840 || gmailGrant.TTLRemainingSeconds > 900 {
		t.Fatalf("expected default 15m TTLRemainingSeconds in (840, 900], got %d", gmailGrant.TTLRemainingSeconds)
	}
	if gmailGrant.ExpiresAt.Sub(gmailGrant.IssuedAt) != 15*time.Minute {
		t.Fatalf("expected ExpiresAt - IssuedAt == 15m, got %v", gmailGrant.ExpiresAt.Sub(gmailGrant.IssuedAt))
	}

	// 2. Deterministic TTL expiration & automatic pruning:
	// Revoke Jira for Alice, re-grant with TTLSeconds: 1 via S256 PKCE, verify immediate warm turn succeeds,
	// sleep >1s, verify automatic pruning from GrantedProviders & EphemeralGrants, and verify next turn
	// pauses with cold OutcomeConsentRequired + ConsentChallengeCard!
	if _, err := http.Post(srv.URL+"/api/sessions/pkce-s3-ttl/oauth/revoke", "application/json",
		bytes.NewReader([]byte(`{"persona":"alice","provider":"atlassian_jira"}`))); err != nil {
		t.Fatalf("revoke jira: %v", err)
	}

	ttlVerifier, ttlChallenge := makeClientPKCEPair(t)
	ttlAuthResp, err := http.Get(srv.URL + "/oauth/atlassian_jira/authorize?session_id=pkce-s3-ttl&persona=alice&code_challenge=" + url.QueryEscape(ttlChallenge) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("authorize jira: %v", err)
	}
	var ttlCh aegis.ConsentChallenge
	_ = json.NewDecoder(ttlAuthResp.Body).Decode(&ttlCh)
	ttlAuthResp.Body.Close()

	consentRes, err := iface.CompleteOAuthConsent(ctx, aegis.OAuthCallback{
		SessionID:    "pkce-s3-ttl",
		Persona:      aegis.PersonaAlice,
		Provider:     aegis.ProviderAtlassianJira,
		Nonce:        ttlCh.Nonce,
		CodeVerifier: ttlVerifier,
		TTLSeconds:   1,
	})
	if err != nil {
		t.Fatalf("CompleteOAuthConsent with TTLSeconds=1: %v", err)
	}
	if !consentRes.Granted {
		t.Fatalf("expected Granted == true")
	}

	// Immediate turn while 1s grant is active -> DEFENDED_SUCCESS
	warmTurn, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "pkce-s3-ttl",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Fetch restricted security issue SEC-101 from Jira.",
	})
	if err != nil {
		t.Fatalf("warm ExecuteTurn error: %v", err)
	}
	if warmTurn.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("expected OutcomeDefendedSuccess while 1s grant is active, got %q", warmTurn.Outcome)
	}

	// Wait for 1s ephemeral grant TTL to expire
	time.Sleep(1150 * time.Millisecond)

	expiredSnap, err := iface.GetSessionState(ctx, "pkce-s3-ttl")
	if err != nil {
		t.Fatalf("GetSessionState after TTL expiry: %v", err)
	}
	for _, p := range expiredSnap.GrantedProviders[aegis.PersonaAlice] {
		if p == aegis.ProviderAtlassianJira {
			t.Fatalf("expected expired atlassian_jira grant to be automatically pruned from GrantedProviders, got %v", expiredSnap.GrantedProviders[aegis.PersonaAlice])
		}
	}
	for _, g := range expiredSnap.EphemeralGrants[aegis.PersonaAlice] {
		if g.Provider == aegis.ProviderAtlassianJira {
			t.Fatalf("expected expired atlassian_jira grant to be automatically pruned from EphemeralGrants, got %+v", expiredSnap.EphemeralGrants[aegis.PersonaAlice])
		}
	}

	// Next 3LO tool call MUST emit a cold ConsentChallengeCard without manual revoke!
	postExpiryTurn, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "pkce-s3-ttl",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Fetch restricted security issue SEC-101 from Jira.",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn after TTL expiry error: %v", err)
	}
	if postExpiryTurn.Outcome != aegis.OutcomeConsentRequired {
		t.Fatalf("expected OutcomeConsentRequired after ephemeral token TTL expired, got %q", postExpiryTurn.Outcome)
	}
	if postExpiryTurn.ConsentChallenge == nil || postExpiryTurn.ConsentChallenge.Provider != aegis.ProviderAtlassianJira {
		t.Fatalf("expected fresh ConsentChallenge for atlassian_jira, got %+v", postExpiryTurn.ConsentChallenge)
	}
}

func TestPKCEVault_Slice4_StaticAssetsWebCryptoPKCEAndZeroPATGuardrails(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	// 1. Fetch index.html
	htmlResp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	htmlBytes, _ := io.ReadAll(htmlResp.Body)
	htmlResp.Body.Close()
	html := string(htmlBytes)

	// Guardrail: Zero password/PAT <input> fields in HTML (only #input-prompt text input and checkboxes)
	inputTagRe := regexp.MustCompile(`(?i)<input\b[^>]*>`)
	for _, tag := range inputTagRe.FindAllString(html, -1) {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, `type="password"`) || strings.Contains(lower, "pat") || strings.Contains(lower, "personal-access-token") {
			t.Fatalf("SECURITY VIOLATION: forbidden PAT/password <input> found in index.html: %s", tag)
		}
		if !strings.Contains(lower, `id="input-prompt"`) && !strings.Contains(lower, `type="checkbox"`) {
			t.Fatalf("unexpected <input> element in index.html (must not add PAT token inputs): %s", tag)
		}
	}

	// Verify 3LO OAuth Token Vault chips render PKCE · S256 · <TTL> metadata & Unified Google Workspace SSO label
	for _, wantHTML := range []string{
		"PKCE · S256 ·",
		"provider-pkce-meta",
		"Google Workspace",
	} {
		if !strings.Contains(html, wantHTML) {
			t.Errorf("index.html missing expected PKCE vault UI snippet %q", wantHTML)
		}
	}

	// 2. Fetch /static/app.js
	jsResp, err := http.Get(srv.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js: %v", err)
	}
	jsBytes, _ := io.ReadAll(jsResp.Body)
	jsResp.Body.Close()
	js := string(jsBytes)

	// Verify Web Crypto S256 PKCE handshake (/oauth/{provider}/authorize -> /oauth/{provider}/callback) + ephemeralGrants TTL badge + Connect (PKCE) button label in app.js
	for _, wantJS := range []string{
		"crypto.subtle.digest",
		"SHA-256",
		"getRandomValues",
		"code_challenge_method=S256",
		"/callback?session_id=",
		"&code_verifier=",
		"codeVerifier",
		"Connect (PKCE)",
		"ephemeralGrants",
		"ttlRemainingSeconds",
		"PKCE · S256 ·",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing required Web Crypto S256 PKCE / TTL snippet %q", wantJS)
		}
	}
	if strings.Contains(js, "Connect (OAuth + PKCE)") {
		t.Errorf("app.js vault connect button must be labeled 'Connect (PKCE)' per ADR-0012 Decision 4, found 'Connect (OAuth + PKCE)'")
	}
	if strings.Contains(js, "/oauth/grant") {
		t.Errorf("app.js authorizeProviderWithPKCE must complete handshake via GET /oauth/{provider}/callback rather than POST /oauth/grant")
	}

	// Guardrail: Zero sessionStorage, zero non-theme localStorage writes, zero unsafe DOM sinks
	if strings.Contains(js, "sessionStorage") {
		t.Errorf("SECURITY VIOLATION: app.js must never touch sessionStorage")
	}
	localStorageSetRe := regexp.MustCompile(`localStorage\.setItem\(\s*["']([^"']+)["']`)
	for _, m := range localStorageSetRe.FindAllStringSubmatch(js, -1) {
		if len(m) > 1 && m[1] != "aegis_theme" {
			t.Errorf("SECURITY VIOLATION: localStorage.setItem called for key %q (only aegis_theme is permitted)", m[1])
		}
	}
	for _, forbiddenSink := range []string{
		".innerHTML",
		".outerHTML",
		"insertAdjacentHTML",
		"document.write(",
		"window.prompt(",
		"alert(",
	} {
		if strings.Contains(js, forbiddenSink) {
			t.Errorf("SECURITY VIOLATION: forbidden sink/dialog %q found in app.js", forbiddenSink)
		}
	}
}

func TestPKCEVault_Slice5_CallbackStateRequiredAuthMethodsAndChallengeSuperseding(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	var iface aegis.AegisRuntime = rt

	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	// 1. Warm session seed stamps AuthMethod="warm_session_seed", PKCEVerified=false, CodeChallengeMethod=""
	warmSnap, err := iface.GetSessionState(ctx, "pkce-s5-warm")
	if err != nil {
		t.Fatalf("GetSessionState(pkce-s5-warm): %v", err)
	}
	if len(warmSnap.EphemeralGrants[aegis.PersonaAlice]) == 0 {
		t.Fatalf("expected warm session grants for alice")
	}
	for _, g := range warmSnap.EphemeralGrants[aegis.PersonaAlice] {
		if g.AuthMethod != "warm_session_seed" || g.PKCEVerified || g.CodeChallengeMethod != "" {
			t.Fatalf("warm session grant %s = (%q, pkceVerified=%v, method=%q), want (warm_session_seed, false, \"\")",
				g.Provider, g.AuthMethod, g.PKCEVerified, g.CodeChallengeMethod)
		}
	}

	// 2. GET /oauth/{provider}/callback without state/nonce or with unknown state MUST return 400 Bad Request
	revokeBody, _ := json.Marshal(aegis.OAuthGrantRequest{
		Persona:  aegis.PersonaAlice,
		Provider: aegis.ProviderGitHub,
	})
	revResp, err := http.Post(srv.URL+"/api/sessions/pkce-s5-cb/oauth/revoke", "application/json", bytes.NewReader(revokeBody))
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	revResp.Body.Close()

	noStateResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s5-cb&persona=alice&code=unverified_code")
	if err != nil {
		t.Fatalf("GET callback without state: %v", err)
	}
	noStateResp.Body.Close()
	if noStateResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /oauth/github/callback without state status = %d, want 400 Bad Request", noStateResp.StatusCode)
	}

	forgedStateResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s5-cb&persona=alice&code=unverified_code&state=forged_unissued_nonce")
	if err != nil {
		t.Fatalf("GET callback with forged state: %v", err)
	}
	forgedStateResp.Body.Close()
	if forgedStateResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /oauth/github/callback with forged state status = %d, want 400 Bad Request", forgedStateResp.StatusCode)
	}

	snapAfterBadCB, err := iface.GetSessionState(ctx, "pkce-s5-cb")
	if err != nil {
		t.Fatalf("GetSessionState(pkce-s5-cb): %v", err)
	}
	for _, p := range snapAfterBadCB.GrantedProviders[aegis.PersonaAlice] {
		if p == aegis.ProviderGitHub {
			t.Fatalf("github must remain ungranted after unverified /callback requests")
		}
	}

	// 3. Initiating a second PKCE challenge for the same (sessionID, persona, provider) supersedes the older pending challenge
	v1, c1 := makeClientPKCEPair(t)
	auth1Resp, err := http.Get(srv.URL + "/oauth/github/authorize?session_id=pkce-s5-cb&persona=alice&code_challenge=" + url.QueryEscape(c1) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET authorize #1: %v", err)
	}
	var ch1 aegis.ConsentChallenge
	_ = json.NewDecoder(auth1Resp.Body).Decode(&ch1)
	auth1Resp.Body.Close()

	v2, c2 := makeClientPKCEPair(t)
	auth2Resp, err := http.Get(srv.URL + "/oauth/github/authorize?session_id=pkce-s5-cb&persona=alice&code_challenge=" + url.QueryEscape(c2) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET authorize #2: %v", err)
	}
	var ch2 aegis.ConsentChallenge
	_ = json.NewDecoder(auth2Resp.Body).Decode(&ch2)
	auth2Resp.Body.Close()

	supersededResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s5-cb&persona=alice&code=code1&state=" + url.QueryEscape(ch1.Nonce) + "&code_verifier=" + url.QueryEscape(v1))
	if err != nil {
		t.Fatalf("GET callback superseded ch1: %v", err)
	}
	supersededResp.Body.Close()
	if supersededResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected superseded PKCE challenge #1 to fail with 400 Bad Request, got %d", supersededResp.StatusCode)
	}

	validCBResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-s5-cb&persona=alice&code=code2&state=" + url.QueryEscape(ch2.Nonce) + "&code_verifier=" + url.QueryEscape(v2))
	if err != nil {
		t.Fatalf("GET callback active ch2: %v", err)
	}
	var cbSnap aegis.SessionSnapshot
	_ = json.NewDecoder(validCBResp.Body).Decode(&cbSnap)
	validCBResp.Body.Close()
	if validCBResp.StatusCode != http.StatusOK {
		t.Fatalf("expected active PKCE challenge #2 callback to succeed with 200 OK, got %d", validCBResp.StatusCode)
	}
	var ghGrant *aegis.EphemeralPKCEGrant
	for i := range cbSnap.EphemeralGrants[aegis.PersonaAlice] {
		if cbSnap.EphemeralGrants[aegis.PersonaAlice][i].Provider == aegis.ProviderGitHub {
			ghGrant = &cbSnap.EphemeralGrants[aegis.PersonaAlice][i]
			break
		}
	}
	if ghGrant == nil || !ghGrant.PKCEVerified || ghGrant.AuthMethod != "oauth2_pkce_s256" || ghGrant.CodeChallengeMethod != "S256" {
		t.Fatalf("expected S256 PKCE verified github grant after /callback, got %+v", ghGrant)
	}

	// 4. Non-PKCE grants accurately stamp PKCEVerified=false and distinct AuthMethod values:
	// 4a. POST /api/fixtures/seed -> "fixture_seed"
	seedResp, err := http.Post(srv.URL+"/api/fixtures/seed", "application/json", bytes.NewReader([]byte(`{"sessionId":"pkce-s5-seed"}`)))
	if err != nil {
		t.Fatalf("POST /api/fixtures/seed: %v", err)
	}
	seedResp.Body.Close()
	seedSnap, err := iface.GetSessionState(ctx, "pkce-s5-seed")
	if err != nil {
		t.Fatalf("GetSessionState(pkce-s5-seed): %v", err)
	}
	for _, g := range seedSnap.EphemeralGrants[aegis.PersonaAlice] {
		if g.AuthMethod != "fixture_seed" || g.PKCEVerified || g.CodeChallengeMethod != "" {
			t.Fatalf("fixture_seed grant %s = (%q, pkceVerified=%v, method=%q), want (fixture_seed, false, \"\")",
				g.Provider, g.AuthMethod, g.PKCEVerified, g.CodeChallengeMethod)
		}
	}

	// 4b. Direct runtime grant via POST /api/sessions/{id}/oauth/grant without PKCE -> "direct_grant" (and cannot spoof oauth2_pkce_s256)
	directResp, err := http.Post(srv.URL+"/api/sessions/pkce-s5-direct/oauth/grant", "application/json",
		strings.NewReader(`{"persona":"alice","provider":"atlassian_jira","accessToken":"direct-jira-tok","authMethod":"oauth2_pkce_s256"}`))
	if err != nil {
		t.Fatalf("POST direct /oauth/grant: %v", err)
	}
	var directSnap aegis.SessionSnapshot
	_ = json.NewDecoder(directResp.Body).Decode(&directSnap)
	directResp.Body.Close()
	if directResp.StatusCode != http.StatusOK {
		t.Fatalf("POST direct /oauth/grant status = %d, want 200", directResp.StatusCode)
	}
	var jiraDirect *aegis.EphemeralPKCEGrant
	for i := range directSnap.EphemeralGrants[aegis.PersonaAlice] {
		if directSnap.EphemeralGrants[aegis.PersonaAlice][i].Provider == aegis.ProviderAtlassianJira {
			jiraDirect = &directSnap.EphemeralGrants[aegis.PersonaAlice][i]
			break
		}
	}
	if jiraDirect == nil || jiraDirect.AuthMethod != "direct_grant" || jiraDirect.PKCEVerified || jiraDirect.CodeChallengeMethod != "" {
		t.Fatalf("direct_grant = %+v, want AuthMethod=direct_grant, PKCEVerified=false, CodeChallengeMethod=\"\"", jiraDirect)
	}

	// 4c. POST /a2a serverSideOauth2 Bearer passthrough -> "a2a_server_side_oauth2", PKCEVerified=false
	a2aBody := `{"jsonrpc":"2.0","id":"a2a-auth-meta-1","method":"message/send","params":{"contextId":"pkce-s5-a2a","metadata":{"persona":"alice","scenarioId":"SCENARIO-01"},"message":{"role":"user","parts":[{"kind":"text","text":"Triage clean escalation."}]}}}`
	a2aReq, err := http.NewRequest(http.MethodPost, srv.URL+"/a2a", strings.NewReader(a2aBody))
	if err != nil {
		t.Fatalf("NewRequest(/a2a): %v", err)
	}
	a2aReq.Header.Set("Content-Type", "application/json")
	a2aReq.Header.Set("Authorization", "Bearer 3lo-alice-google_gmail-a2a-forwarded")
	a2aResp, err := http.DefaultClient.Do(a2aReq)
	if err != nil {
		t.Fatalf("POST /a2a: %v", err)
	}
	_, _ = io.ReadAll(a2aResp.Body)
	a2aResp.Body.Close()

	a2aSnap, err := iface.GetSessionState(ctx, "pkce-s5-a2a")
	if err != nil {
		t.Fatalf("GetSessionState(pkce-s5-a2a): %v", err)
	}
	var sawA2AGrant bool
	for _, g := range a2aSnap.EphemeralGrants[aegis.PersonaAlice] {
		if g.Provider == aegis.ProviderGoogleGmail || g.Provider == aegis.ProviderGCPIAM {
			sawA2AGrant = true
			if g.AuthMethod != "a2a_server_side_oauth2" || g.PKCEVerified || g.CodeChallengeMethod != "" {
				t.Fatalf("a2a_server_side_oauth2 grant %s = %+v, want AuthMethod=a2a_server_side_oauth2, PKCEVerified=false", g.Provider, g)
			}
		} else if g.AuthMethod != "warm_session_seed" || g.PKCEVerified {
			t.Fatalf("untouched warm grant %s = %+v, want warm_session_seed", g.Provider, g)
		}
	}
	if !sawA2AGrant {
		t.Fatalf("expected a2a_server_side_oauth2 grant in pkce-s5-a2a, got %+v", a2aSnap.EphemeralGrants)
	}
}

func TestPKCEVault_PureJSSHA256FallbackAndRFC7636Vector(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := httptest.NewServer(aegis.NewHTTPHandler(rt))
	defer srv.Close()

	jsResp, err := http.Get(srv.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js: %v", err)
	}
	jsBytes, _ := io.ReadAll(jsResp.Body)
	jsResp.Body.Close()
	js := string(jsBytes)

	for _, wantSnippet := range []string{
		"function sha256Bytes(",
		"0x6a09e667",
		"0x428a2f98",
		"window.crypto.subtle",
		"typeof window.crypto.subtle.digest === \"function\"",
	} {
		if !strings.Contains(js, wantSnippet) {
			t.Errorf("app.js missing pure-JS SHA-256 fallback snippet %q", wantSnippet)
		}
	}

	// RFC 7636 Appendix B test vector:
	// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	const (
		rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	sum := sha256.Sum256([]byte(rfc7636Verifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != rfc7636Challenge {
		t.Fatalf("RFC 7636 Appendix B Go baseline mismatch: got %q, want %q", got, rfc7636Challenge)
	}

	// Verify the server-side PKCE flow accepts the RFC 7636 Appendix B vector end-to-end
	authResp, err := http.Get(srv.URL + "/oauth/github/authorize?session_id=pkce-rfc7636&persona=alice&code_challenge=" + url.QueryEscape(rfc7636Challenge) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET /oauth/github/authorize: %v", err)
	}
	var ch aegis.ConsentChallenge
	if err := json.NewDecoder(authResp.Body).Decode(&ch); err != nil {
		authResp.Body.Close()
		t.Fatalf("decode ConsentChallenge: %v", err)
	}
	authResp.Body.Close()

	cbResp, err := http.Get(srv.URL + "/oauth/github/callback?session_id=pkce-rfc7636&persona=alice&code=rfc7636_code&state=" + url.QueryEscape(ch.Nonce) + "&code_verifier=" + url.QueryEscape(rfc7636Verifier))
	if err != nil {
		t.Fatalf("GET /oauth/github/callback: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/github/callback with RFC 7636 Appendix B vector status = %d, want 200 OK", cbResp.StatusCode)
	}
}
