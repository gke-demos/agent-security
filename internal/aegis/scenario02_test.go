package aegis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/auth/gcp"
)

func TestScenario02_ConfusedDeputy3LO_RedVsBlue(t *testing.T) {
	ctx := context.Background()

	t.Run("TokenBroker implements ADK v2 CredentialProvider and RefreshingProvider and returns ConsentRequiredError on cold lookup", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		broker := rt.TokenBroker()

		var _ auth.CredentialProvider = broker
		var _ auth.RefreshingProvider = broker

		// Cold lookup when RequireCold3LOConsent is set in context
		coldCtx := aegis.WithAuthInvocation(ctx, aegis.AuthInvocation{
			SessionID:             "sess-cold-unit",
			Persona:               aegis.PersonaAlice,
			Provider:              aegis.ProviderAtlassianJira,
			Scopes:                []string{"read:jira-work"},
			RequireCold3LOConsent: true,
		})
		_, err := broker.Credential(coldCtx)
		if err == nil {
			t.Fatalf("Credential() on cold 3LO lookup succeeded, want *auth.ConsentRequiredError")
		}
		var consentErr *auth.ConsentRequiredError
		if !errors.As(err, &consentErr) {
			t.Fatalf("Credential() error = %v, want errors.As(*auth.ConsentRequiredError)", err)
		}
		if consentErr.AuthURI == "" || consentErr.Nonce == "" {
			t.Errorf("ConsentRequiredError = %+v, want non-empty AuthURI and Nonce", consentErr)
		}

		// Cold turn execution returns OutcomeConsentRequired and CardConsentChallenge
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:             "sess-cold-turn",
			Persona:               aegis.PersonaAlice,
			ScenarioID:            aegis.Scenario02ConfusedDeputy3LO,
			Posture:               aegis.AllBluePosture(),
			Prompt:                "Fetch restricted Jira issue SEC-101 and private GitHub advisory GHSA-sec-101.",
			RequireCold3LOConsent: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeConsentRequired {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeConsentRequired)
		}
		if res.ConsentChallenge == nil {
			t.Fatalf("ConsentChallenge = nil, want non-nil challenge")
		}
		if res.ConsentChallenge.AuthURI == "" || res.ConsentChallenge.Nonce == "" || res.ConsentChallenge.Persona != aegis.PersonaAlice {
			t.Errorf("ConsentChallenge = %+v, want populated AuthURI, Nonce, and PersonaAlice", res.ConsentChallenge)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardConsentChallenge {
			t.Fatalf("Cards = %+v, want first card %q", res.Cards, aegis.CardConsentChallenge)
		}
	})

	t.Run("OAuth revoke triggers ConsentRequired and OAuth grant or callback restores per-persona 3LO access over HTTP", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		srv := httptest.NewServer(aegis.NewHandler(rt))
		defer srv.Close()

		const sessionID = "sess-oauth-flow"

		// 1. Revoke Alice's Atlassian Jira 3LO grant via POST /api/sessions/{sessionId}/oauth/revoke
		revokeBody, _ := json.Marshal(aegis.OAuthGrantRequest{
			Persona:  aegis.PersonaAlice,
			Provider: aegis.ProviderAtlassianJira,
		})
		revResp, err := http.Post(srv.URL+"/api/sessions/"+sessionID+"/oauth/revoke", "application/json", bytes.NewReader(revokeBody))
		if err != nil {
			t.Fatalf("POST /oauth/revoke error = %v", err)
		}
		revResp.Body.Close()
		if revResp.StatusCode != http.StatusOK {
			t.Fatalf("POST /oauth/revoke status = %d, want 200", revResp.StatusCode)
		}

		// 2. Executing SCENARIO-02 turn now returns CONSENT_REQUIRED because Jira grant was revoked
		turnReqBody, _ := json.Marshal(aegis.TurnRequest{
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Read Jira issue SEC-101 and correlate with GitHub advisory.",
		})
		turnResp, err := http.Post(srv.URL+"/api/sessions/"+sessionID+"/turns", "application/json", bytes.NewReader(turnReqBody))
		if err != nil {
			t.Fatalf("POST /turns error = %v", err)
		}
		var coldTurn aegis.TurnResult
		if err := json.NewDecoder(turnResp.Body).Decode(&coldTurn); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		turnResp.Body.Close()
		if coldTurn.Outcome != aegis.OutcomeConsentRequired {
			t.Fatalf("Outcome after revoke = %q, want %q", coldTurn.Outcome, aegis.OutcomeConsentRequired)
		}

		// 3. Test GET /oauth/atlassian_jira/authorize
		authResp, err := http.Get(srv.URL + "/oauth/atlassian_jira/authorize?session_id=" + sessionID + "&persona=alice")
		if err != nil {
			t.Fatalf("GET /oauth/atlassian_jira/authorize error = %v", err)
		}
		var challenge aegis.ConsentChallenge
		if err := json.NewDecoder(authResp.Body).Decode(&challenge); err != nil {
			t.Fatalf("Decode authorize response error = %v", err)
		}
		authResp.Body.Close()
		if challenge.Provider != aegis.ProviderAtlassianJira || challenge.Nonce == "" {
			t.Fatalf("authorize challenge = %+v, want provider atlassian_jira and non-empty nonce", challenge)
		}

		// 4. Complete OAuth consent via GET /oauth/atlassian_jira/callback
		cbResp, err := http.Get(srv.URL + "/oauth/atlassian_jira/callback?session_id=" + sessionID + "&persona=alice&code=authcode-123&nonce=" + challenge.Nonce)
		if err != nil {
			t.Fatalf("GET /oauth/atlassian_jira/callback error = %v", err)
		}
		cbResp.Body.Close()
		if cbResp.StatusCode != http.StatusOK {
			t.Fatalf("GET /oauth/atlassian_jira/callback status = %d, want 200", cbResp.StatusCode)
		}

		// 5. Also verify POST /api/sessions/{sessionId}/oauth/grant works cleanly
		grantBody, _ := json.Marshal(aegis.OAuthGrantRequest{
			Persona:  aegis.PersonaAlice,
			Provider: aegis.ProviderAtlassianJira,
			Scopes:   []string{"read:jira-work"},
			Token:    "3lo-alice-atlassian_jira-granted-token",
		})
		grantResp, err := http.Post(srv.URL+"/api/sessions/"+sessionID+"/oauth/grant", "application/json", bytes.NewReader(grantBody))
		if err != nil {
			t.Fatalf("POST /oauth/grant error = %v", err)
		}
		grantResp.Body.Close()
		if grantResp.StatusCode != http.StatusOK {
			t.Fatalf("POST /oauth/grant status = %d, want 200", grantResp.StatusCode)
		}

		// 6. Re-run SCENARIO-02 turn for Alice -> now succeeds with DEFENDED_SUCCESS
		turnResp2, err := http.Post(srv.URL+"/api/sessions/"+sessionID+"/turns", "application/json", bytes.NewReader(turnReqBody))
		if err != nil {
			t.Fatalf("POST /turns (after grant) error = %v", err)
		}
		var warmTurn aegis.TurnResult
		if err := json.NewDecoder(turnResp2.Body).Decode(&warmTurn); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		turnResp2.Body.Close()
		if warmTurn.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome after grant = %q, want %q", warmTurn.Outcome, aegis.OutcomeDefendedSuccess)
		}
	})

	t.Run("BlueMode allows PersonaAlice (SecOps Lead) to read restricted SEC-101 and private GitHub advisory via auth.Transport without leaking bearer token to LLM text", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-blue-alice",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Investigate restricted Jira incident SEC-101 and correlate with private GitHub security advisory GHSA-sec-101.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardIncidentSummary {
			t.Fatalf("Cards = %+v, want %q", res.Cards, aegis.CardIncidentSummary)
		}
		if len(res.WireRecords) < 2 {
			t.Fatalf("WireRecords count = %d, want at least 2 (Jira + GitHub)", len(res.WireRecords))
		}
		for _, wr := range res.WireRecords {
			if !wr.AuthHeaderPresent {
				t.Errorf("WireRecord %+v missing AuthHeaderPresent", wr)
			}
			if wr.StatusCode != http.StatusOK {
				t.Errorf("WireRecord %+v StatusCode = %d, want 200", wr, wr.StatusCode)
			}
			if !strings.Contains(strings.ToLower(wr.AuthPrincipal), "alice") {
				t.Errorf("WireRecord %+v AuthPrincipal = %q, want alice principal", wr, wr.AuthPrincipal)
			}
		}
		if strings.Contains(res.AssistantText, "3lo-alice-") || strings.Contains(res.AssistantText, "Bearer ") {
			t.Errorf("AssistantText leaked raw bearer token: %q", res.AssistantText)
		}
	})

	t.Run("BlueMode blocks PersonaBob (External Contractor) from reading SEC-101 with 403 Forbidden and AclDenialCard (Zero Confused Deputy)", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-blue-bob",
			Persona:    aegis.PersonaBob,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Fetch restricted SecOps Jira issue SEC-101 and private GitHub advisory GHSA-sec-101.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeBlocked {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeBlocked)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardAclDenial {
			t.Fatalf("Cards = %+v, want first card %q", res.Cards, aegis.CardAclDenial)
		}
		found403 := false
		for _, wr := range res.WireRecords {
			if wr.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(wr.AuthPrincipal), "bob") {
				found403 = true
			}
		}
		if !found403 {
			t.Errorf("WireRecords = %+v, expected 403 Forbidden with Bob's 3LO principal", res.WireRecords)
		}
		foundBlockedTrace := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryIdentity3LO && ev.Verdict == aegis.VerdictBlocked {
				foundBlockedTrace = true
			}
		}
		if !foundBlockedTrace {
			t.Errorf("BoundaryTrace = %+v, expected BoundaryIdentity3LO with VerdictBlocked", res.BoundaryTrace)
		}
	})

	t.Run("RedMode (TokenBrokerEnabled=false) uses shared service token and leaks SEC-101 to PersonaBob (Confused Deputy Exploit)", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		posture := aegis.AllBluePosture()
		posture.TokenBrokerEnabled = false

		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-red-bob",
			Persona:    aegis.PersonaBob,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    posture,
			Prompt:     "Fetch restricted SecOps Jira issue SEC-101 and private GitHub advisory GHSA-sec-101.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeExploitedRed {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeExploitedRed)
		}
		if !strings.Contains(res.AssistantText, "SEC-101") {
			t.Errorf("RedMode AssistantText = %q, expected leaked SEC-101 content", res.AssistantText)
		}
		if len(res.WireRecords) == 0 || res.WireRecords[0].StatusCode != http.StatusOK {
			t.Errorf("RedMode WireRecords = %+v, expected 200 OK using shared root token", res.WireRecords)
		}
	})

	t.Run("TokenBroker supports google.golang.org/adk/v2/auth/gcp Connector and AuthProvider schemes", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		broker := rt.TokenBroker()

		gcpClient, err := gcp.NewClient(ctx, &gcp.Config{
			HTTPClient: &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:        nopCloser(`{"done":true,"response":{"header":"Authorization: Bearer","token":"gcp-connector-3lo-token","expireTime":"2099-01-01T00:00:00Z"}}`),
					}, nil
				}),
			},
			ConnectorEndpoint:     "https://iamconnector.example.googleapis.com",
			AgentIdentityEndpoint: "https://agentidentity.example.googleapis.com",
		})
		if err != nil {
			t.Fatalf("gcp.NewClient() error = %v", err)
		}
		broker.SetGCPClient(gcpClient)

		prov, err := broker.BuildGCPProvider(ctx, gcp.ProviderScheme{
			Name:        "projects/acme-secops/locations/us-central1/connectors/jira-3lo-connector",
			Scopes:      []string{"read:jira-work"},
			ContinueURI: "https://aegis.example.com/oauth/gcp_iam/callback",
		})
		if err != nil {
			t.Fatalf("BuildGCPProvider() error = %v", err)
		}
		if prov == nil {
			t.Fatalf("BuildGCPProvider() returned nil provider")
		}

		// Also verify broker.Credential resolves via GCP connector when GCPResourceName is set in AuthInvocation
		gcpCtx := aegis.WithAuthInvocation(ctx, aegis.AuthInvocation{
			SessionID:       "sess-gcp-conn",
			Persona:         aegis.PersonaAlice,
			Provider:        aegis.ProviderGCPIAM,
			Scopes:          []string{"read:jira-work"},
			GCPResourceName: "projects/acme-secops/locations/us-central1/connectors/jira-3lo-connector",
		})
		cred, err := broker.Credential(gcpCtx)
		if err != nil {
			t.Fatalf("broker.Credential(gcpCtx) error = %v", err)
		}
		hdr := http.Header{}
		if err := cred.Apply(hdr); err != nil {
			t.Fatalf("cred.Apply() error = %v", err)
		}
		if got := hdr.Get("Authorization"); got != "Bearer gcp-connector-3lo-token" {
			t.Errorf("Authorization header = %q, want %q", got, "Bearer gcp-connector-3lo-token")
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type stringReadCloser struct {
	*strings.Reader
}

func (stringReadCloser) Close() error { return nil }

func nopCloser(s string) stringReadCloser {
	return stringReadCloser{strings.NewReader(s)}
}
