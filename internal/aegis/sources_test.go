package aegis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		SourceAgentPlatformGemini,
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
		AgentPlatformLiveLLM: true,
		GeminiEndpoint:       "https://us-central1-aiplatform.googleapis.com",
		ModelArmorEndpoint:   "https://modelarmor.us-central1.rep.googleapis.com",
		DLPEndpoint:          "https://dlp.googleapis.com",
		GCPProjectID:         "demo-sec-project",
		GCPLocation:          "us-central1",
		GKEClusterName:       "demo-sec-cluster",
		AgentRegistryURL:     "https://agentregistry.googleapis.com",
		GitHubAPIURL:         "https://api.github.com",
		GitHubTargetRepo:     "gke-demos/aegis-checkout-target",
		AliceGitHubToken:     "gho_live_alice_token",
		GmailAPIURL:          "https://gmail.googleapis.com",
		AliceGmailToken:      "gmail_tok_live_alice",
		JiraBaseURL:          "https://acme-sec.atlassian.net",
		AliceJiraToken:       "atlassian_live_alice",
		SubstrateGatewayURL:  "http://127.0.0.1:8088",
		LiveSubstrate:        true,
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

func TestGetSourcesStatus_StageSafeSanitizationPreservesOutboundRuntimeConfig(t *testing.T) {
	const (
		secretProjectID = "sec-stage-proj-94821"
		secretCluster   = "sec-stage-gke-cluster-01"
	)

	// 1. Auto-discovered regional endpoints via ConfigFromEnvWithLookup
	env := map[string]string{
		"GOOGLE_CLOUD_PROJECT":    secretProjectID,
		"GOOGLE_CLOUD_LOCATION":   "europe-west4",
		"GKE_CLUSTER_NAME":        secretCluster,
		"AGENT_PLATFORM_LIVE_LLM": "true",
		"LIVE_GITHUB":             "true",
		"GITHUB_TARGET_REPO":      "gke-demos/aegis-checkout-target",
		"ALICE_GMAIL_TOKEN":       "gmail_tok_stage_safe_alice",
		"JIRA_BASE_URL":           "https://acme-sec.atlassian.net",
		"ALICE_JIRA_TOKEN":        "jira_tok_stage_safe_alice",
		"SUBSTRATE_GATEWAY_URL":   "http://127.0.0.1:8088",
		"LIVE_SUBSTRATE":          "true",
	}
	cfg := ConfigFromEnvWithLookup(
		func(k string) string { return env[k] },
		func() string { return "gho_stage_safe_cli_token" },
	)

	// Outbound RuntimeConfig fields MUST remain 100% intact for real cloud calls.
	wantMA := "https://modelarmor.europe-west4.rep.googleapis.com/v1/projects/" + secretProjectID + "/locations/europe-west4/templates/aegis-prompt-screen:sanitizeUserPrompt"
	if cfg.ModelArmorEndpoint != wantMA {
		t.Fatalf("cfg.ModelArmorEndpoint = %q, want %q", cfg.ModelArmorEndpoint, wantMA)
	}
	wantDLP := "https://dlp.googleapis.com/v2/projects/" + secretProjectID + "/locations/global/content:deidentify"
	if cfg.DLPEndpoint != wantDLP {
		t.Fatalf("cfg.DLPEndpoint = %q, want %q", cfg.DLPEndpoint, wantDLP)
	}
	wantReg := "https://agentregistry.googleapis.com/v1alpha/projects/" + secretProjectID + "/locations/global"
	if cfg.AgentRegistryURL != wantReg {
		t.Fatalf("cfg.AgentRegistryURL = %q, want %q", cfg.AgentRegistryURL, wantReg)
	}
	if cfg.GCPProjectID != secretProjectID || cfg.GKEClusterName != secretCluster {
		t.Fatalf("RuntimeConfig project/cluster mutated: got (%q, %q)", cfg.GCPProjectID, cfg.GKEClusterName)
	}

	rt := NewRuntime(cfg)
	// Verify runtime.Config() also retains raw outbound URLs
	if rt.Config().ModelArmorEndpoint != wantMA || rt.Config().AgentRegistryURL != wantReg {
		t.Fatalf("rt.Config() mutated outbound URLs: %+v", rt.Config())
	}

	srv := httptest.NewServer(NewHTTPHandler(rt))
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		srv.Close()
		t.Fatalf("test server URL %q must bind strictly to 127.0.0.1", srv.URL)
	}
	t.Cleanup(srv.Close)

	// Check GET /api/sources/status
	sourcesResp, err := http.Get(srv.URL + "/api/sources/status")
	if err != nil {
		t.Fatalf("GET /api/sources/status: %v", err)
	}
	sourcesBody, err := io.ReadAll(sourcesResp.Body)
	sourcesResp.Body.Close()
	if err != nil {
		t.Fatalf("read /api/sources/status: %v", err)
	}
	if sourcesResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/sources/status status = %d, want 200", sourcesResp.StatusCode)
	}
	sourcesRaw := string(sourcesBody)
	if strings.Contains(sourcesRaw, secretProjectID) {
		t.Errorf("/api/sources/status leaked GCPProjectID %q: %s", secretProjectID, sourcesRaw)
	}
	if strings.Contains(sourcesRaw, secretCluster) {
		t.Errorf("/api/sources/status leaked GKEClusterName %q: %s", secretCluster, sourcesRaw)
	}

	var decoded struct {
		Sources []SourceStatus `json:"sources"`
	}
	if err := json.Unmarshal(sourcesBody, &decoded); err != nil {
		t.Fatalf("unmarshal /api/sources/status: %v", err)
	}
	byID := map[ExternalSourceID]SourceStatus{}
	for _, s := range decoded.Sources {
		byID[s.ID] = s
	}

	wantMADisplay := "https://modelarmor.europe-west4.rep.googleapis.com/v1 · Template aegis-prompt-screen"
	if got := byID[SourceModelArmorSDP].Endpoint; got != wantMADisplay {
		t.Errorf("ModelArmorSDP stage-safe Endpoint = %q, want %q", got, wantMADisplay)
	}
	wantRegDisplay := "https://agentregistry.googleapis.com/v1alpha · Global Catalog"
	if got := byID[SourceAgentRegistry].Endpoint; got != wantRegDisplay {
		t.Errorf("AgentRegistry stage-safe Endpoint = %q, want %q", got, wantRegDisplay)
	}
	wantObsDetail := "Live Cloud Logging & GKE cluster telemetry (Active GKE Context)"
	if got := byID[SourceGCPObservability].Detail; got != wantObsDetail {
		t.Errorf("GCPObservability stage-safe Detail = %q, want %q", got, wantObsDetail)
	}

	// Check GET /api/about/catalog also contains zero occurrences of project ID or cluster name
	catResp, err := http.Get(srv.URL + "/api/about/catalog")
	if err != nil {
		t.Fatalf("GET /api/about/catalog: %v", err)
	}
	catBody, err := io.ReadAll(catResp.Body)
	catResp.Body.Close()
	if err != nil {
		t.Fatalf("read /api/about/catalog: %v", err)
	}
	if catResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/about/catalog status = %d, want 200", catResp.StatusCode)
	}
	catRaw := string(catBody)
	if strings.Contains(catRaw, secretProjectID) {
		t.Errorf("/api/about/catalog leaked GCPProjectID %q: %s", secretProjectID, catRaw)
	}
	if strings.Contains(catRaw, secretCluster) {
		t.Errorf("/api/about/catalog leaked GKEClusterName %q: %s", secretCluster, catRaw)
	}

	// 2. Custom endpoints containing raw project/cluster identifiers are also stripped/redacted
	customRT := NewRuntime(RuntimeConfig{
		GCPProjectID:         secretProjectID,
		GKEClusterName:       secretCluster,
		AgentPlatformLiveLLM: true,
		GeminiEndpoint:       "https://us-central1-aiplatform.googleapis.com/v1/projects/" + secretProjectID + "/locations/us-central1",
		SubstrateGatewayURL:  "https://gateway." + secretCluster + ".internal/" + secretProjectID,
		LiveSubstrate:        true,
	})
	customStatuses, err := customRT.GetSourcesStatus(context.Background())
	if err != nil {
		t.Fatalf("customRT.GetSourcesStatus: %v", err)
	}
	for _, st := range customStatuses {
		joined := st.Name + " | " + st.Endpoint + " | " + st.Detail
		if strings.Contains(joined, secretProjectID) || strings.Contains(joined, secretCluster) {
			t.Errorf("custom SourceStatus %s leaked project/cluster identifier: %q", st.ID, joined)
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
	t.Setenv("AGENT_PLATFORM_LIVE_LLM", "true")
	t.Setenv("GEMINI_ENDPOINT", "https://gemini.env.example")
	t.Setenv("GITHUB_API_URL", "https://github.env.example")
	t.Setenv("GITHUB_TARGET_REPO", "gke-demos/aegis-checkout-target")
	t.Setenv("GMAIL_API_URL", "https://gmail.env.example")
	t.Setenv("JIRA_BASE_URL", "https://jira.env.example")
	t.Setenv("JIRA_RESTRICTED_KEY", "SEC-999")
	t.Setenv("JIRA_PUBLIC_KEY", "PUB-888")
	t.Setenv("SUBSTRATE_GATEWAY_URL", "http://127.0.0.1:8088")
	t.Setenv("SUBSTRATE_TARGET_ACTOR", "aegis-system/remediator-custom")
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
		!cfg.AgentPlatformLiveLLM ||
		cfg.GeminiEndpoint != "https://gemini.env.example" ||
		cfg.GitHubAPIURL != "https://github.env.example" ||
		cfg.GitHubTargetRepo != "gke-demos/aegis-checkout-target" ||
		cfg.GmailAPIURL != "https://gmail.env.example" ||
		cfg.JiraBaseURL != "https://jira.env.example" ||
		cfg.JiraRestrictedKey != "SEC-999" ||
		cfg.JiraPublicKey != "PUB-888" ||
		cfg.SubstrateGatewayURL != "http://127.0.0.1:8088" ||
		cfg.SubstrateTargetActor != "aegis-system/remediator-custom" ||
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

func TestConfigFromEnv_AutoDefaultsAndGitHubTokenResolution(t *testing.T) {
	// 1. Auto-default regional endpoints when GOOGLE_CLOUD_PROJECT is set and GOOGLE_CLOUD_LOCATION is empty
	env1 := map[string]string{
		"GOOGLE_CLOUD_PROJECT": "aegis-zero-click-proj",
		"LIVE_GITHUB":          "true",
	}
	cfg1 := ConfigFromEnvWithLookup(func(k string) string { return env1[k] }, func() string { return "gho_resolved_from_cli_123" })
	if cfg1.GCPLocation != "us-central1" {
		t.Errorf("cfg1.GCPLocation = %q, want us-central1", cfg1.GCPLocation)
	}
	wantMA := "https://modelarmor.us-central1.rep.googleapis.com/v1/projects/aegis-zero-click-proj/locations/us-central1/templates/aegis-prompt-screen:sanitizeUserPrompt"
	if cfg1.ModelArmorEndpoint != wantMA {
		t.Errorf("cfg1.ModelArmorEndpoint = %q, want %q", cfg1.ModelArmorEndpoint, wantMA)
	}
	wantDLP := "https://dlp.googleapis.com/v2/projects/aegis-zero-click-proj/locations/global/content:deidentify"
	if cfg1.DLPEndpoint != wantDLP {
		t.Errorf("cfg1.DLPEndpoint = %q, want %q", cfg1.DLPEndpoint, wantDLP)
	}
	wantReg := "https://agentregistry.googleapis.com/v1alpha/projects/aegis-zero-click-proj/locations/global"
	if cfg1.AgentRegistryURL != wantReg {
		t.Errorf("cfg1.AgentRegistryURL = %q, want %q", cfg1.AgentRegistryURL, wantReg)
	}
	if cfg1.AliceGitHubToken != "gho_resolved_from_cli_123" {
		t.Errorf("cfg1.AliceGitHubToken = %q, want gho_resolved_from_cli_123", cfg1.AliceGitHubToken)
	}
	if cfg1.SubstrateTargetActor != "aegis-system/remediator-1" {
		t.Errorf("cfg1.SubstrateTargetActor = %q, want aegis-system/remediator-1", cfg1.SubstrateTargetActor)
	}

	// 2. Custom GOOGLE_CLOUD_LOCATION flows into regional ModelArmorEndpoint
	env2 := map[string]string{
		"GOOGLE_CLOUD_PROJECT":  "aegis-eu-proj",
		"GOOGLE_CLOUD_LOCATION": "europe-west4",
	}
	cfg2 := ConfigFromEnvWithLookup(func(k string) string { return env2[k] }, nil)
	wantEUMA := "https://modelarmor.europe-west4.rep.googleapis.com/v1/projects/aegis-eu-proj/locations/europe-west4/templates/aegis-prompt-screen:sanitizeUserPrompt"
	if cfg2.ModelArmorEndpoint != wantEUMA {
		t.Errorf("cfg2.ModelArmorEndpoint = %q, want %q", cfg2.ModelArmorEndpoint, wantEUMA)
	}

	// 3. ConfigFromEnv() with t.Setenv and injectable defaultGitHubCLITokenResolver
	t.Setenv("GOOGLE_CLOUD_PROJECT", "aegis-live-proj")
	t.Setenv("GOOGLE_CLOUD_LOCATION", "")
	t.Setenv("MODEL_ARMOR_ENDPOINT", "")
	t.Setenv("DLP_ENDPOINT", "")
	t.Setenv("AGENT_REGISTRY_URL", "")
	t.Setenv("LIVE_GITHUB", "true")
	t.Setenv("ALICE_GITHUB_TOKEN", "")

	origResolver := defaultGitHubCLITokenResolver
	defaultGitHubCLITokenResolver = func() string { return "gho_injected_default_resolver" }
	defer func() { defaultGitHubCLITokenResolver = origResolver }()

	cfg3 := ConfigFromEnv()
	if cfg3.AliceGitHubToken != "gho_injected_default_resolver" {
		t.Errorf("cfg3.AliceGitHubToken = %q, want gho_injected_default_resolver", cfg3.AliceGitHubToken)
	}
	if cfg3.ModelArmorEndpoint == "" || cfg3.DLPEndpoint == "" || cfg3.AgentRegistryURL == "" {
		t.Errorf("expected auto-defaulted endpoints in cfg3: %+v", cfg3)
	}

	// 4. Explicit ALICE_GITHUB_TOKEN prevents ghTokenFn from ever executing
	ghCalled := false
	cfgExplicit := ConfigFromEnvWithLookup(func(k string) string {
		switch k {
		case "LIVE_GITHUB":
			return "true"
		case "ALICE_GITHUB_TOKEN":
			return "gho_explicit_token_from_env"
		default:
			return ""
		}
	}, func() string {
		ghCalled = true
		return "gho_should_not_be_used"
	})
	if ghCalled {
		t.Errorf("expected ghTokenFn not to be called when ALICE_GITHUB_TOKEN is explicitly provided")
	}
	if cfgExplicit.AliceGitHubToken != "gho_explicit_token_from_env" {
		t.Errorf("cfgExplicit.AliceGitHubToken = %q, want gho_explicit_token_from_env", cfgExplicit.AliceGitHubToken)
	}

	// 5. resolveGitHubCLIToken skips CLI execution when running under go test unless AEGIS_LIVE_EVALS=true AND ALICE_GITHUB_TOKEN is unset
	t.Setenv("AEGIS_LIVE_EVALS", "")
	if got := resolveGitHubCLIToken(); got != "" {
		t.Errorf("resolveGitHubCLIToken() under go test = %q, want empty string", got)
	}
	t.Setenv("AEGIS_LIVE_EVALS", "true")
	t.Setenv("ALICE_GITHUB_TOKEN", "gho_already_configured")
	if got := resolveGitHubCLIToken(); got != "" {
		t.Errorf("resolveGitHubCLIToken() with AEGIS_LIVE_EVALS=true and explicit ALICE_GITHUB_TOKEN = %q, want empty string (hermetic)", got)
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

	// 2. Verify GET /oauth/github/callback exchanges code + code_verifier via HTTP POST and stores real access_token
	appSrv := httptest.NewServer(NewHandler(rt))
	defer appSrv.Close()

	authInitResp, err := http.Get(appSrv.URL + "/oauth/github/authorize?session_id=oauth-exchange-sess&persona=alice")
	if err != nil {
		t.Fatalf("GET /oauth/github/authorize: %v", err)
	}
	var authInitCh ConsentChallenge
	if err := json.NewDecoder(authInitResp.Body).Decode(&authInitCh); err != nil {
		authInitResp.Body.Close()
		t.Fatalf("decode /oauth/github/authorize: %v", err)
	}
	authInitResp.Body.Close()

	cbResp, err := http.Get(appSrv.URL + "/oauth/github/callback?session_id=oauth-exchange-sess&persona=alice&code=auth_code_xyz&state=" + authInitCh.Nonce)
	if err != nil {
		t.Fatalf("GET /oauth/github/callback: %v", err)
	}
	defer cbResp.Body.Close()

	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/github/callback status = %d, want 200", cbResp.StatusCode)
	}
	if !strings.Contains(receivedForm, "code=auth_code_xyz") || !strings.Contains(receivedForm, "client_id=gh-client-id-live") || !strings.Contains(receivedForm, "client_secret=gh-client-secret-live") || !strings.Contains(receivedForm, "code_verifier=") {
		t.Errorf("OAuth token exchange POST body = %q, want code, client_id, client_secret, and code_verifier", receivedForm)
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

	// 4. Verify runtime 3LO token injection via OAuthGrantRequest.AccessToken (HTTP POST /oauth/grant and CompleteOAuthConsent)
	// transitions Gmail and Jira Cloud from FIXTURE to LIVE.
	seedRT := NewRuntime(RuntimeConfig{})
	seedSrv := httptest.NewServer(NewHandler(seedRT))
	defer seedSrv.Close()

	if got := NewGmailConnector(seedRT).Provenance(); got != ProvenanceFixture {
		t.Fatalf("initial GmailConnector.Provenance() = %q, want FIXTURE", got)
	}
	if got := NewJiraConnector(seedRT).Provenance(); got != ProvenanceFixture {
		t.Fatalf("initial JiraConnector.Provenance() = %q, want FIXTURE", got)
	}

	gmailGrantBody := `{"persona":"alice","provider":"google_gmail","accessToken":"gmail_tok_runtime_seeded_3lo"}`
	gmailGrantResp, err := http.Post(seedSrv.URL+"/api/sessions/runtime-seed-sess/oauth/grant", "application/json", strings.NewReader(gmailGrantBody))
	if err != nil {
		t.Fatalf("POST /oauth/grant (gmail accessToken): %v", err)
	}
	gmailGrantResp.Body.Close()
	if gmailGrantResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/grant status = %d, want 200", gmailGrantResp.StatusCode)
	}

	if _, err := seedRT.CompleteOAuthConsent(ctx, OAuthGrantRequest{
		SessionID:   "runtime-seed-sess",
		Persona:     PersonaAlice,
		Provider:    ProviderAtlassianJira,
		AccessToken: "atlassian_3lo_runtime_seeded_jira_token",
	}); err != nil {
		t.Fatalf("CompleteOAuthConsent (jira accessToken): %v", err)
	}

	if !seedRT.TokenBroker().HasNonFixtureGrant(ProviderGoogleGmail) {
		t.Errorf("HasNonFixtureGrant(google_gmail) = false, want true")
	}
	if !seedRT.TokenBroker().HasNonFixtureGrant(ProviderAtlassianJira) {
		t.Errorf("HasNonFixtureGrant(atlassian_jira) = false, want true")
	}
	if got := NewGmailConnector(seedRT).Provenance(); got != ProvenanceLive {
		t.Errorf("GmailConnector.Provenance() after accessToken grant = %q, want LIVE", got)
	}
	if got := NewJiraConnector(seedRT).Provenance(); got != ProvenanceLive {
		t.Errorf("JiraConnector.Provenance() after accessToken grant = %q, want LIVE", got)
	}

	seedStatuses, err := seedRT.GetSourcesStatus(ctx)
	if err != nil {
		t.Fatalf("seedRT.GetSourcesStatus: %v", err)
	}
	for _, st := range seedStatuses {
		if (st.ID == SourceGoogleGmail || st.ID == SourceAtlassianJira) && st.Provenance != ProvenanceLive {
			t.Errorf("seedRT source %s Provenance = %q, want LIVE", st.ID, st.Provenance)
		}
	}
}

func TestInspectAgentIdentitySPIFFE_AndStageSafeSourceStatusEnrichment(t *testing.T) {
	ctx := context.Background()

	// 1. Verify default SPIFFECredentialBundlePath when SPIFFE_CREDENTIAL_BUNDLE_PATH is unset
	cfgDefault := ConfigFromEnvWithLookup(func(string) string { return "" }, nil)
	const wantDefaultSPIFFEPath = "/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem"
	if cfgDefault.SPIFFECredentialBundlePath != wantDefaultSPIFFEPath {
		t.Fatalf("cfgDefault.SPIFFECredentialBundlePath = %q, want %q", cfgDefault.SPIFFECredentialBundlePath, wantDefaultSPIFFEPath)
	}

	// 2. Verify custom env vars for Phase 6 runtime config
	envCustom := map[string]string{
		"SPIFFE_CREDENTIAL_BUNDLE_PATH":   "/tmp/custom-spiffe-bundle.pem",
		"GCP_AUTH_PROVIDER_ID":            "projects/987654321098/locations/global/authProviders/aegis-github-provider",
		"AGENT_GATEWAY_INGRESS_URL":       "https://agent-ingress.example.internal",
		"AGENT_GATEWAY_EGRESS_PROXY_URL":  "http://10.128.0.50:443",
		"AGENT_GATEWAY_ROOT_CA_PATH":      "/etc/ssl/certs/agent-gateway-ca.pem",
	}
	cfgCustom := ConfigFromEnvWithLookup(func(k string) string { return envCustom[k] }, nil)
	if cfgCustom.SPIFFECredentialBundlePath != "/tmp/custom-spiffe-bundle.pem" ||
		cfgCustom.GCPAuthProviderID != "projects/987654321098/locations/global/authProviders/aegis-github-provider" ||
		cfgCustom.AgentGatewayIngressURL != "https://agent-ingress.example.internal" ||
		cfgCustom.AgentGatewayEgressProxyURL != "http://10.128.0.50:443" ||
		cfgCustom.AgentGatewayRootCAPath != "/etc/ssl/certs/agent-gateway-ca.pem" {
		t.Fatalf("cfgCustom Phase 6 fields mismatch: %+v", cfgCustom)
	}

	// 3. When SPIFFE bundle path does not exist, InspectAgentIdentitySPIFFE returns verified=false
	rtMissing := NewRuntime(RuntimeConfig{
		SPIFFECredentialBundlePath: filepath.Join(t.TempDir(), "nonexistent.pem"),
	})
	if raw, san, ok := rtMissing.InspectAgentIdentitySPIFFE(); ok || raw != "" || san != "" {
		t.Fatalf("InspectAgentIdentitySPIFFE on missing file = (%q, %q, %v), want ('', '', false)", raw, san, ok)
	}

	// 4. Generate a synthetic X.509 SVID certificate bundle with a real GKE Agent Identity SPIFFE URI SAN
	rawSPIFFE := "spiffe://agents.global.org-123456789012.system.id.goog/resources/container/projects/987654321098/locations/us-central1-a/clusters/my-secret-gke-cluster/ns/aegis-system/sa/aegis-sre"
	bundlePath, err := WriteSyntheticSPIFFECredentialBundle(t.TempDir(), rawSPIFFE)
	if err != nil {
		t.Fatalf("WriteSyntheticSPIFFECredentialBundle: %v", err)
	}

	rtVerified := NewRuntime(RuntimeConfig{
		GCPProjectID:               "my-secret-gcp-project",
		GKEClusterName:             "my-secret-gke-cluster",
		SPIFFECredentialBundlePath: bundlePath,
		GCPAuthProviderID:          "projects/987654321098/locations/global/authProviders/aegis-github-provider",
	})
	gotRaw, gotSanitized, gotOK := rtVerified.InspectAgentIdentitySPIFFE()
	if !gotOK {
		t.Fatalf("InspectAgentIdentitySPIFFE verified = false, want true")
	}
	if gotRaw != rawSPIFFE {
		t.Errorf("InspectAgentIdentitySPIFFE rawURI = %q, want %q", gotRaw, rawSPIFFE)
	}
	wantSanitized := "spiffe://agents.global.org-${ORG_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre"
	if gotSanitized != wantSanitized {
		t.Errorf("InspectAgentIdentitySPIFFE sanitizedURI = %q, want %q", gotSanitized, wantSanitized)
	}

	// 5. Verify GetSourcesStatus enriches SourceAgentRegistry (and SourceGCPObservability) with stage-safe SPIFFE summary
	// and enriches 3LO sources with stage-safe GCPAuthProviderID without leaking raw org ID or project number
	statuses, err := rtVerified.GetSourcesStatus(ctx)
	if err != nil {
		t.Fatalf("rtVerified.GetSourcesStatus: %v", err)
	}
	byID := map[ExternalSourceID]SourceStatus{}
	for _, st := range statuses {
		byID[st.ID] = st
		combined := st.Name + " | " + st.Endpoint + " | " + st.Detail
		if strings.Contains(combined, "123456789012") || strings.Contains(combined, "987654321098") || strings.Contains(combined, "my-secret-gke-cluster") || strings.Contains(combined, "my-secret-gcp-project") {
			t.Errorf("SourceStatus %s leaked raw org/project/cluster identifier: %q", st.ID, combined)
		}
	}
	if !strings.Contains(byID[SourceAgentRegistry].Detail, wantSanitized) {
		t.Errorf("SourceAgentRegistry.Detail = %q, want it to contain sanitized SPIFFE URI %q", byID[SourceAgentRegistry].Detail, wantSanitized)
	}
	if !strings.Contains(byID[SourceGCPObservability].Detail, wantSanitized) {
		t.Errorf("SourceGCPObservability.Detail = %q, want it to contain sanitized SPIFFE URI %q", byID[SourceGCPObservability].Detail, wantSanitized)
	}
	wantSanitizedProvider := "projects/${PROJECT_NUMBER}/locations/global/authProviders/aegis-github-provider"
	for _, srcID := range []ExternalSourceID{SourceGitHub, SourceGoogleGmail, SourceAtlassianJira} {
		if !strings.Contains(byID[srcID].Detail, wantSanitizedProvider) {
			t.Errorf("Source %s Detail = %q, want it to contain stage-safe GCPAuthProviderID %q", srcID, byID[srcID].Detail, wantSanitizedProvider)
		}
	}

	// 6. Verify un-slashed projects/<id>/locations/... and projects/<number>/locations/... are scrubbed by sanitizeStageSafeText
	gotUnslashedID := sanitizeStageSafeText("projects/my-secret-proj/locations/us-central1/authProviders/github", RuntimeConfig{})
	const wantUnslashedID = "projects/${PROJECT_ID}/locations/us-central1/authProviders/github"
	if gotUnslashedID != wantUnslashedID {
		t.Errorf("sanitizeStageSafeText(unslashed project id) = %q, want %q", gotUnslashedID, wantUnslashedID)
	}
	gotSlashedID := sanitizeStageSafeText("/projects/my-secret-proj/locations/us-central1/authProviders/github", RuntimeConfig{})
	const wantSlashedID = "/projects/${PROJECT_ID}/locations/us-central1/authProviders/github"
	if gotSlashedID != wantSlashedID {
		t.Errorf("sanitizeStageSafeText(slashed project id) = %q, want %q", gotSlashedID, wantSlashedID)
	}
	gotUnslashedNum := sanitizeStageSafeText("projects/123456789/locations/global/authProviders/github", RuntimeConfig{})
	const wantUnslashedNum = "projects/${PROJECT_NUMBER}/locations/global/authProviders/github"
	if gotUnslashedNum != wantUnslashedNum {
		t.Errorf("sanitizeStageSafeText(unslashed project number) = %q, want %q", gotUnslashedNum, wantUnslashedNum)
	}
}

func TestConfigFromEnv_LiveSaaS8Of8Provenance(t *testing.T) {
	ctx := context.Background()

	// 1. LIVE_SAAS=true auto-defaults GmailAPIURL, JiraBaseURL, and Alice/Bob 3LO persona tokens
	envLiveSaaS := map[string]string{
		"GOOGLE_CLOUD_PROJECT":    "aegis-8of8-proj",
		"GKE_CLUSTER_NAME":        "aegis-8of8-cluster",
		"AGENT_PLATFORM_LIVE_LLM": "true",
		"LIVE_GITHUB":             "true",
		"LIVE_SUBSTRATE":          "true",
		"SUBSTRATE_GATEWAY_URL":   "http://127.0.0.1:8088",
		"LIVE_SAAS":               "true",
	}
	cfg := ConfigFromEnvWithLookup(
		func(k string) string { return envLiveSaaS[k] },
		func() string { return "gho_live_cli_token_8of8" },
	)

	if cfg.GmailAPIURL != "http://127.0.0.1:8080/api/targets/gmail/v1" {
		t.Fatalf("cfg.GmailAPIURL = %q, want %q", cfg.GmailAPIURL, "http://127.0.0.1:8080/api/targets/gmail/v1")
	}
	if cfg.JiraBaseURL != "http://127.0.0.1:8080/api/targets/jira" {
		t.Fatalf("cfg.JiraBaseURL = %q, want %q", cfg.JiraBaseURL, "http://127.0.0.1:8080/api/targets/jira")
	}
	if cfg.AliceGmailToken != "gmail_tok_aegis_live_alice_3lo" || cfg.BobGmailToken != "gmail_tok_aegis_live_bob_3lo" {
		t.Fatalf("Gmail tokens = (%q, %q), want auto-defaulted live tokens", cfg.AliceGmailToken, cfg.BobGmailToken)
	}
	if cfg.AliceJiraToken != "atatt3x_aegis_live_alice_jira_3lo" || cfg.BobJiraToken != "atatt3x_aegis_live_bob_jira_3lo" {
		t.Fatalf("Jira tokens = (%q, %q), want auto-defaulted live tokens", cfg.AliceJiraToken, cfg.BobJiraToken)
	}

	rt := NewRuntime(cfg)
	statuses, err := rt.GetSourcesStatus(ctx)
	if err != nil {
		t.Fatalf("GetSourcesStatus: %v", err)
	}
	if len(statuses) != 8 {
		t.Fatalf("len(statuses) = %d, want 8", len(statuses))
	}
	for i, st := range statuses {
		if st.Provenance != ProvenanceLive {
			t.Errorf("statuses[%d] (%s).Provenance = %q, want %q (8/8 LIVE)", i, st.ID, st.Provenance, ProvenanceLive)
		}
	}

	// 2. Custom PORT and explicit GMAIL_API_URL / JIRA_BASE_URL overrides are respected
	envOverride := map[string]string{
		"LIVE_SAAS":     "true",
		"PORT":          "9090",
		"GMAIL_API_URL": "https://gmail.googleapis.com/gmail/v1",
	}
	cfgOverride := ConfigFromEnvWithLookup(func(k string) string { return envOverride[k] }, nil)
	if cfgOverride.GmailAPIURL != "https://gmail.googleapis.com/gmail/v1" {
		t.Errorf("cfgOverride.GmailAPIURL = %q, want explicit override preserved", cfgOverride.GmailAPIURL)
	}
	if cfgOverride.JiraBaseURL != "http://127.0.0.1:9090/api/targets/jira" {
		t.Errorf("cfgOverride.JiraBaseURL = %q, want http://127.0.0.1:9090/api/targets/jira", cfgOverride.JiraBaseURL)
	}
}

func TestPhase8_DeploymentManifestREADMEAndStageRunbook8Of8Sync(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	requiredSnippets := map[string][]string{
		"manifests/02-aegis-deployment.yaml": {
			`name: LIVE_SAAS`,
			`value: "true"`,
			`name: GMAIL_API_URL`,
			`http://127.0.0.1:8080/api/targets/gmail/v1`,
			`name: JIRA_BASE_URL`,
			`http://127.0.0.1:8080/api/targets/jira`,
		},
		"README.md": {
			"ADR-0016",
			"0016",
			"ADR Index (16)",
			"FullDuplexStreamed",
			"StreamedBodyResponse",
			"8/8 LIVE",
			"/api/targets/gmail/v1",
			"/api/targets/jira",
		},
		"docs/stage-runbook.md": {
			"ADR-0016",
			"16",
			"FullDuplexStreamed",
			"StreamedBodyResponse",
			"8/8 LIVE",
		},
	}

	forbiddenStrings := []string{
		"mofi" + "labs",
		"ate" + "-cluster",
		"gke-ate" + "-cluster",
		"vertex" + " ai",
		"fluid" + " compute",
	}

	for relPath, snippets := range requiredSnippets {
		rawBytes, err := os.ReadFile(filepath.Join(repoRoot, relPath))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", relPath, err)
		}
		content := string(rawBytes)
		lower := strings.ToLower(content)
		for _, forbidden := range forbiddenStrings {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains forbidden personal/retired term %q", relPath, forbidden)
			}
		}
		for _, snip := range snippets {
			if !strings.Contains(content, snip) {
				t.Errorf("%s missing expected Phase 8 snippet %q", relPath, snip)
			}
		}
	}
}


