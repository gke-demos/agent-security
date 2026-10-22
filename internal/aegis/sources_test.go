package aegis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteTurn_DefaultFixtureProvenance(t *testing.T) {
	ctx := context.Background()
	rt := NewRuntime(RuntimeConfig{})

	res, err := rt.ExecuteTurn(ctx, TurnRequest{
		SessionID:  "prov-test-s1",
		Persona:    PersonaAlice,
		ScenarioID: Scenario02ConfusedDeputy3LO,
		Posture:    AllBluePosture(),
		Prompt:     "Verify provenance defaults on Scenario 02",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn error: %v", err)
	}
	if len(res.BoundaryTrace) == 0 {
		t.Fatalf("expected non-empty BoundaryTrace")
	}
	for i, ev := range res.BoundaryTrace {
		if ev.Provenance != ProvenanceFixture {
			t.Errorf("BoundaryTrace[%d].Provenance = %q, want %q", i, ev.Provenance, ProvenanceFixture)
		}
	}
	if len(res.WireRecords) == 0 {
		t.Fatalf("expected non-empty WireRecords")
	}
	for i, wr := range res.WireRecords {
		if wr.Provenance != ProvenanceFixture {
			t.Errorf("WireRecords[%d].Provenance = %q, want %q", i, wr.Provenance, ProvenanceFixture)
		}
	}

	// Also test ResolveConfirmation provenance default
	s3Res, err := rt.ExecuteTurn(ctx, TurnRequest{
		SessionID:  "prov-test-s3",
		Persona:    PersonaAlice,
		ScenarioID: Scenario03AgentGatewayAndStepUp,
		Posture:    AllBluePosture(),
		Prompt:     "Trigger step-up confirmation",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn S3 error: %v", err)
	}
	if s3Res.StepUpConfirmation == nil {
		t.Fatalf("expected StepUpConfirmation")
	}
	confirmedRes, err := rt.ResolveConfirmation(ctx, ConfirmationResolution{
		SessionID:      "prov-test-s3",
		ConfirmationID: s3Res.StepUpConfirmation.ConfirmationID,
		Confirmed:      true,
	})
	if err != nil {
		t.Fatalf("ResolveConfirmation error: %v", err)
	}
	for i, ev := range confirmedRes.BoundaryTrace {
		if ev.Provenance != ProvenanceFixture {
			t.Errorf("ResolveConfirmation BoundaryTrace[%d].Provenance = %q, want %q", i, ev.Provenance, ProvenanceFixture)
		}
	}
	for i, wr := range confirmedRes.WireRecords {
		if wr.Provenance != ProvenanceFixture {
			t.Errorf("ResolveConfirmation WireRecords[%d].Provenance = %q, want %q", i, wr.Provenance, ProvenanceFixture)
		}
	}
}

func TestGetSourcesStatus_FixtureVsLiveAndHTTPEndpoint(t *testing.T) {
	ctx := context.Background()

	// 1. Default unconfigured Runtime reports FIXTURE for all 8 External Sources in exact order
	fixtureRT := NewRuntime(RuntimeConfig{})
	statuses, err := fixtureRT.GetSourcesStatus(ctx)
	if err != nil {
		t.Fatalf("GetSourcesStatus error: %v", err)
	}

	wantOrder := []ExternalSourceID{
		SourceVertexGemini,
		SourceModelArmorSDP,
		SourceGCPObservability,
		SourceAgentRegistry,
		SourceGitHub,
		SourceGoogleGmail,
		SourceAtlassianJira,
		SourceSubstrateSandbox,
	}
	if len(statuses) != len(wantOrder) {
		t.Fatalf("len(statuses) = %d, want %d", len(statuses), len(wantOrder))
	}
	for i, wantID := range wantOrder {
		if statuses[i].ID != wantID {
			t.Errorf("statuses[%d].ID = %q, want %q", i, statuses[i].ID, wantID)
		}
		if statuses[i].Provenance != ProvenanceFixture {
			t.Errorf("fixture statuses[%d] (%s).Provenance = %q, want %q", i, statuses[i].ID, statuses[i].Provenance, ProvenanceFixture)
		}
		if statuses[i].Name == "" || statuses[i].Boundary == "" || statuses[i].Endpoint == "" || statuses[i].Detail == "" {
			t.Errorf("statuses[%d] has empty metadata fields: %+v", i, statuses[i])
		}
	}

	// 2. Configured Runtime reports LIVE for all 8 External Sources and serves GET /api/sources/status
	liveRT := NewRuntime(RuntimeConfig{
		VertexLiveLLM:       true,
		GeminiEndpoint:      "https://us-central1-aiplatform.googleapis.com",
		ModelArmorEndpoint:  "https://modelarmor.us-central1.rep.googleapis.com",
		DLPEndpoint:         "https://dlp.googleapis.com",
		GCPProjectID:        "demo-sec-project",
		GCPLocation:         "us-central1",
		GKEClusterName:      "demo-sec-cluster",
		AgentRegistryURL:    "https://agentregistry.googleapis.com",
		GitHubAPIURL:        "https://api.github.com",
		GitHubTargetRepo:    "gke-demos/aegis-checkout-target",
		AliceGitHubToken:    "gho_live_alice_token",
		GmailAPIURL:         "https://gmail.googleapis.com",
		AliceGmailToken:     "gmail_tok_live_alice",
		JiraBaseURL:         "https://acme-sec.atlassian.net",
		AliceJiraToken:      "atlassian_live_alice",
		SubstrateGatewayURL: "http://127.0.0.1:8088",
		LiveSubstrate:       true,
	})

	srv := httptest.NewServer(NewHandler(liveRT))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/sources/status")
	if err != nil {
		t.Fatalf("GET /api/sources/status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sources/status status = %d, want 200", resp.StatusCode)
	}

	var payload struct {
		Sources []SourceStatus `json:"sources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /api/sources/status: %v", err)
	}
	if len(payload.Sources) != len(wantOrder) {
		t.Fatalf("len(payload.Sources) = %d, want %d", len(payload.Sources), len(wantOrder))
	}
	for i, src := range payload.Sources {
		if src.ID != wantOrder[i] {
			t.Errorf("payload.Sources[%d].ID = %q, want %q", i, src.ID, wantOrder[i])
		}
		if src.Provenance != ProvenanceLive {
			t.Errorf("live payload.Sources[%d] (%s).Provenance = %q, want %q", i, src.ID, src.Provenance, ProvenanceLive)
		}
	}
}

func TestRuntimeConfigFromEnv(t *testing.T) {
	t.Setenv("MODEL_ARMOR_ENDPOINT", "https://modelarmor.env.example")
	t.Setenv("DLP_ENDPOINT", "https://dlp.env.example")
	t.Setenv("AGENT_REGISTRY_URL", "https://registry.env.example")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "env-gcp-project")
	t.Setenv("GOOGLE_CLOUD_LOCATION", "europe-west1")
	t.Setenv("GKE_CLUSTER_NAME", "env-gke-cluster")
	t.Setenv("VERTEX_LIVE_LLM", "true")
	t.Setenv("GEMINI_ENDPOINT", "https://gemini.env.example")
	t.Setenv("GITHUB_API_URL", "https://github.env.example")
	t.Setenv("GITHUB_TARGET_REPO", "gke-demos/aegis-checkout-target")
	t.Setenv("GMAIL_API_URL", "https://gmail.env.example")
	t.Setenv("JIRA_BASE_URL", "https://jira.env.example")
	t.Setenv("JIRA_RESTRICTED_KEY", "SEC-999")
	t.Setenv("JIRA_PUBLIC_KEY", "PUB-888")
	t.Setenv("SUBSTRATE_GATEWAY_URL", "http://127.0.0.1:8088")
	t.Setenv("LIVE_SUBSTRATE", "true")
	t.Setenv("ALICE_GITHUB_TOKEN", "alice-gh-tok")
	t.Setenv("BOB_GITHUB_TOKEN", "bob-gh-tok")
	t.Setenv("ALICE_GMAIL_TOKEN", "alice-gm-tok")
	t.Setenv("BOB_GMAIL_TOKEN", "bob-gm-tok")
	t.Setenv("ALICE_JIRA_TOKEN", "alice-jr-tok")
	t.Setenv("BOB_JIRA_TOKEN", "bob-jr-tok")
	t.Setenv("GITHUB_OAUTH_CLIENT_ID", "gh-cid")
	t.Setenv("GITHUB_OAUTH_CLIENT_SECRET", "gh-csec")
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "gg-cid")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "gg-csec")
	t.Setenv("JIRA_OAUTH_CLIENT_ID", "jr-cid")
	t.Setenv("JIRA_OAUTH_CLIENT_SECRET", "jr-csec")

	cfg := RuntimeConfigFromEnv()
	if cfg.ModelArmorEndpoint != "https://modelarmor.env.example" ||
		cfg.DLPEndpoint != "https://dlp.env.example" ||
		cfg.AgentRegistryURL != "https://registry.env.example" ||
		cfg.GCPProjectID != "env-gcp-project" ||
		cfg.GCPLocation != "europe-west1" ||
		cfg.GKEClusterName != "env-gke-cluster" ||
		!cfg.VertexLiveLLM ||
		cfg.GeminiEndpoint != "https://gemini.env.example" ||
		cfg.GitHubAPIURL != "https://github.env.example" ||
		cfg.GitHubTargetRepo != "gke-demos/aegis-checkout-target" ||
		cfg.GmailAPIURL != "https://gmail.env.example" ||
		cfg.JiraBaseURL != "https://jira.env.example" ||
		cfg.JiraRestrictedKey != "SEC-999" ||
		cfg.JiraPublicKey != "PUB-888" ||
		cfg.SubstrateGatewayURL != "http://127.0.0.1:8088" ||
		!cfg.LiveSubstrate ||
		cfg.AliceGitHubToken != "alice-gh-tok" ||
		cfg.BobGitHubToken != "bob-gh-tok" ||
		cfg.AliceGmailToken != "alice-gm-tok" ||
		cfg.BobGmailToken != "bob-gm-tok" ||
		cfg.AliceJiraToken != "alice-jr-tok" ||
		cfg.BobJiraToken != "bob-jr-tok" ||
		cfg.GitHubOAuthClientID != "gh-cid" ||
		cfg.GitHubOAuthClientSecret != "gh-csec" ||
		cfg.GoogleOAuthClientID != "gg-cid" ||
		cfg.GoogleOAuthClientSecret != "gg-csec" ||
		cfg.JiraOAuthClientID != "jr-cid" ||
		cfg.JiraOAuthClientSecret != "jr-csec" {
		t.Fatalf("RuntimeConfigFromEnv mismatch: %+v", cfg)
	}
}

func TestTokenBroker_EnvPersonaSeedingAndLiveOAuthCallbackExchange(t *testing.T) {
	ctx := context.Background()

	var receivedForm string
	oauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("OAuth token endpoint method = %s, want POST", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		receivedForm = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_exchanged_live_oauth_token_777","token_type":"bearer"}`))
	}))
	defer oauthSrv.Close()

	rt := NewRuntime(RuntimeConfig{
		GCPProjectID:               "demo-sec-project",
		AliceGitHubToken:           "gho_seeded_alice_111",
		BobGitHubToken:             "gho_seeded_bob_222",
		AliceGmailToken:            "gmail_tok_seeded_alice_333",
		BobGmailToken:              "gmail_tok_seeded_bob_444",
		AliceJiraToken:             "jira_seeded_alice_555",
		BobJiraToken:               "jira_seeded_bob_666",
		GitHubOAuthClientID:        "gh-client-id-live",
		GitHubOAuthClientSecret:    "gh-client-secret-live",
		OAuthTokenEndpointOverride: oauthSrv.URL + "/login/oauth/access_token",
		HTTPClient:                 oauthSrv.Client(),
	})

	// 1. Verify pre-seeded Alice and Bob tokens (including ProviderGCPIAM ADC token) are returned by TokenBroker.Credential
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "adc-seeded-gcp-iam-token-999")
	rt = NewRuntime(rt.Config())
	cases := []struct {
		persona   PersonaID
		provider  ProviderID
		wantToken string
	}{
		{PersonaAlice, ProviderGitHub, "Bearer gho_seeded_alice_111"},
		{PersonaBob, ProviderGitHub, "Bearer gho_seeded_bob_222"},
		{PersonaAlice, ProviderGoogleGmail, "Bearer gmail_tok_seeded_alice_333"},
		{PersonaBob, ProviderGoogleGmail, "Bearer gmail_tok_seeded_bob_444"},
		{PersonaAlice, ProviderAtlassianJira, "Bearer jira_seeded_alice_555"},
		{PersonaBob, ProviderAtlassianJira, "Bearer jira_seeded_bob_666"},
		{PersonaAlice, ProviderGCPIAM, "Bearer adc-seeded-gcp-iam-token-999"},
	}

	for _, tc := range cases {
		invCtx := WithAuthInvocation(ctx, AuthInvocation{
			SessionID: "seeded-sess",
			Persona:   tc.persona,
			Provider:  tc.provider,
		})
		cred, err := rt.TokenBroker().Credential(invCtx)
		if err != nil {
			t.Fatalf("Credential(%s, %s) error: %v", tc.persona, tc.provider, err)
		}
		hdr := http.Header{}
		if err := cred.Apply(hdr); err != nil {
			t.Fatalf("cred.Apply error: %v", err)
		}
		if got := hdr.Get("Authorization"); got != tc.wantToken {
			t.Errorf("Credential(%s, %s) Authorization = %q, want %q", tc.persona, tc.provider, got, tc.wantToken)
		}
	}

	// 2. Verify GET /oauth/github/callback exchanges code via HTTP POST and stores real access_token
	appSrv := httptest.NewServer(NewHandler(rt))
	defer appSrv.Close()

	cbResp, err := http.Get(appSrv.URL + "/oauth/github/callback?session_id=oauth-exchange-sess&persona=alice&code=auth_code_xyz&state=nonce_99")
	if err != nil {
		t.Fatalf("GET /oauth/github/callback: %v", err)
	}
	defer cbResp.Body.Close()

	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/github/callback status = %d, want 200", cbResp.StatusCode)
	}
	if !strings.Contains(receivedForm, "code=auth_code_xyz") || !strings.Contains(receivedForm, "client_id=gh-client-id-live") || !strings.Contains(receivedForm, "client_secret=gh-client-secret-live") {
		t.Errorf("OAuth token exchange POST body = %q, want code, client_id, and client_secret", receivedForm)
	}

	exchangedCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID: "oauth-exchange-sess",
		Persona:   PersonaAlice,
		Provider:  ProviderGitHub,
	})
	exchangedCred, err := rt.TokenBroker().Credential(exchangedCtx)
	if err != nil {
		t.Fatalf("Credential after OAuth callback error: %v", err)
	}
	hdr := http.Header{}
	_ = exchangedCred.Apply(hdr)
	if got := hdr.Get("Authorization"); got != "Bearer gho_exchanged_live_oauth_token_777" {
		t.Errorf("Exchanged Authorization = %q, want %q", got, "Bearer gho_exchanged_live_oauth_token_777")
	}

	// 3. Verify dynamic non-fixture 3LO grant promotes SaaS connector and GetSourcesStatus to ProvenanceLive even without Alice*Token env vars
	dynamicRT := NewRuntime(RuntimeConfig{})
	dynamicRT.TokenBroker().Grant(ctx, OAuthGrantRequest{
		SessionID: "dyn-sess",
		Persona:   PersonaAlice,
		Provider:  ProviderGitHub,
		Token:     "gho_dynamic_live_grant_token",
	})
	if got := NewGitHubConnector(dynamicRT).Provenance(); got != ProvenanceLive {
		t.Errorf("NewGitHubConnector(dynamicRT).Provenance() = %q, want %q", got, ProvenanceLive)
	}
	dynStatuses, err := dynamicRT.GetSourcesStatus(ctx)
	if err != nil {
		t.Fatalf("dynamicRT.GetSourcesStatus error: %v", err)
	}
	for _, st := range dynStatuses {
		if st.ID == SourceGitHub && st.Provenance != ProvenanceLive {
			t.Errorf("dynamicRT SourceGitHub Provenance = %q, want %q", st.Provenance, ProvenanceLive)
		}
	}
}
