package aegis_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func TestLiveGCP_ModelArmorAndCloudSDP_ADCAndProvenance(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "adc-test-modelarmor-sdp-token-123")

	var modelArmorAuthHeader, dlpAuthHeader string
	var modelArmorQuotaProj, dlpQuotaProj string
	var modelArmorHits, dlpHits int

	maSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelArmorHits++
		modelArmorAuthHeader = r.Header.Get("Authorization")
		modelArmorQuotaProj = r.Header.Get("x-goog-user-project")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sanitizationResult": {
				"filterMatchState": "NO_MATCH_FOUND"
			}
		}`))
	}))
	defer maSrv.Close()

	dlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dlpHits++
		dlpAuthHeader = r.Header.Get("Authorization")
		dlpQuotaProj = r.Header.Get("x-goog-user-project")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"result": {
				"findings": [
					{"infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"}},
					{"infoType": {"name": "GCP_API_KEY"}}
				]
			},
			"item": {
				"value": "Sanitized by live Cloud SDP: [REDACTED_SSN] and [REDACTED_API_KEY]."
			}
		}`))
	}))
	defer dlpSrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		GCPProjectID:       "demo-proj",
		ModelArmorEndpoint: maSrv.URL + "/v1/projects/demo-proj/locations/us-central1/templates/aegis:sanitizeUserPrompt",
		DLPEndpoint:        dlpSrv.URL + "/v2/projects/demo-proj/content:deidentify",
		HTTPClient:         maSrv.Client(),
	})

	inspection := rt.Guard().InspectAndSanitize(ctx, "Customer SSN 123-45-6789 and key AIzaSyD-CustomerLeakedKey999", aegis.AllBluePosture())
	if modelArmorHits == 0 || dlpHits == 0 {
		t.Fatalf("expected live hits to Model Armor (%d) and DLP (%d)", modelArmorHits, dlpHits)
	}
	if modelArmorAuthHeader != "Bearer adc-test-modelarmor-sdp-token-123" {
		t.Errorf("Model Armor Authorization = %q, want Bearer adc-test-modelarmor-sdp-token-123", modelArmorAuthHeader)
	}
	if modelArmorQuotaProj != "demo-proj" {
		t.Errorf("Model Armor x-goog-user-project = %q, want demo-proj", modelArmorQuotaProj)
	}
	if dlpAuthHeader != "Bearer adc-test-modelarmor-sdp-token-123" {
		t.Errorf("Cloud DLP Authorization = %q, want Bearer adc-test-modelarmor-sdp-token-123", dlpAuthHeader)
	}
	if dlpQuotaProj != "demo-proj" {
		t.Errorf("Cloud DLP x-goog-user-project = %q, want demo-proj", dlpQuotaProj)
	}
	if inspection.Provenance != aegis.ProvenanceLive {
		t.Errorf("inspection.Provenance = %q, want %q", inspection.Provenance, aegis.ProvenanceLive)
	}

	turnRes, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:    "sess-live-ma-sdp",
		Persona:      aegis.PersonaAlice,
		ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
		Posture:      aegis.AllBluePosture(),
		Prompt:       "Triage clean customer escalation with live Model Armor and Cloud SDP.",
		CleanPIIOnly: true,
	})
	if err != nil {
		t.Fatalf("ExecuteTurn() error = %v", err)
	}
	foundLiveReasoningGuard := false
	for _, ev := range turnRes.BoundaryTrace {
		if ev.Boundary == aegis.BoundaryReasoningGuard {
			if ev.Provenance != aegis.ProvenanceLive {
				t.Errorf("BoundaryReasoningGuard trace event Provenance = %q, want %q", ev.Provenance, aegis.ProvenanceLive)
			}
			foundLiveReasoningGuard = true
		}
	}
	if !foundLiveReasoningGuard {
		t.Fatalf("expected BoundaryReasoningGuard trace event in %+v", turnRes.BoundaryTrace)
	}

	// Verify unconfigured Runtime Guard returns ProvenanceFixture
	fixtureRT := aegis.NewRuntime(aegis.RuntimeConfig{})
	fixtureInsp := fixtureRT.Guard().InspectAndSanitize(ctx, "clean text", aegis.AllBluePosture())
	if fixtureInsp.Provenance != aegis.ProvenanceFixture && !strings.EqualFold(string(fixtureInsp.Provenance), string(aegis.ProvenanceFixture)) {
		t.Errorf("fixture inspection.Provenance = %q, want %q", fixtureInsp.Provenance, aegis.ProvenanceFixture)
	}

	// Verify configured but unreachable ModelArmorEndpoint falls back to local policy engine and records ProvenanceFixture on BoundaryReasoningGuard trace events
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer failSrv.Close()

	fallbackGuardRT := aegis.NewRuntime(aegis.RuntimeConfig{
		ModelArmorEndpoint: failSrv.URL + "/v1/projects/demo-proj/locations/us-central1/templates/aegis:sanitizeUserPrompt",
		DLPEndpoint:        failSrv.URL + "/v2/projects/demo-proj/content:deidentify",
		HTTPClient:         failSrv.Client(),
	})
	fallbackTurnRes, err := fallbackGuardRT.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:    "sess-fallback-ma-sdp",
		Persona:      aegis.PersonaAlice,
		ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
		Posture:      aegis.AllBluePosture(),
		Prompt:       "Triage customer escalation when Model Armor endpoint returns 502.",
		CleanPIIOnly: true,
	})
	if err != nil {
		t.Fatalf("fallbackGuardRT.ExecuteTurn() error = %v", err)
	}
	for _, ev := range fallbackTurnRes.BoundaryTrace {
		if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Provenance != aegis.ProvenanceFixture {
			t.Errorf("unreachable ModelArmor/DLP fallback BoundaryReasoningGuard trace Provenance = %q, want %q", ev.Provenance, aegis.ProvenanceFixture)
		}
	}
}

func TestLiveGCP_ObservabilityAndAgentRegistry_Scenario03And05(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "adc-test-observability-registry-token-456")

	var (
		registryHits      int
		loggingHits       int
		gkeHits           int
		loggingAuth       string
		gkeAuth           string
		registryAuth      string
		loggingQuotaProj  string
		gkeQuotaProj      string
		registryQuotaProj string
	)

	gcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/mcpServers"):
			registryHits++
			registryAuth = r.Header.Get("Authorization")
			registryQuotaProj = r.Header.Get("x-goog-user-project")
			_, _ = w.Write([]byte(`{
				"mcpServers": [
					{
						"name": "projects/demo-sec-proj/locations/us-central1/mcpServers/logging-mcp",
						"mcpServerId": "logging-mcp",
						"displayName": "Cloud Logging MCP",
						"interfaces": [{"url": "https://logging.googleapis.com/mcp", "protocolBinding": "JSONRPC"}],
						"tools": [{"name": "logging.entries.list", "annotations": {"readOnlyHint": true}}]
					},
					{
						"name": "projects/demo-sec-proj/locations/us-central1/mcpServers/container-mcp",
						"mcpServerId": "container-mcp",
						"displayName": "GKE Container MCP",
						"interfaces": [{"url": "https://container.googleapis.com/mcp", "protocolBinding": "JSONRPC"}],
						"tools": [{"name": "container.clusters.get", "annotations": {"readOnlyHint": true}}]
					}
				]
			}`))
		case strings.HasSuffix(r.URL.Path, "/agents"):
			registryHits++
			_, _ = w.Write([]byte(`{
				"agents": [
					{
						"name": "projects/demo-sec-proj/locations/us-central1/agents/sandbox-remediator",
						"displayName": "Sandbox Remediator",
						"version": "0.5.0"
					}
				]
			}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v2/entries:list":
			loggingHits++
			loggingAuth = r.Header.Get("Authorization")
			loggingQuotaProj = r.Header.Get("x-goog-user-project")
			_, _ = w.Write([]byte(`{
				"entries": [
					{
						"logName": "projects/demo-sec-proj/logs/checkout-service",
						"severity": "ERROR",
						"textPayload": "HTTP 502 nil pointer dereference in checkout RetryPolicy"
					}
				]
			}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/demo-sec-proj/locations/us-central1/clusters/demo-gke-cluster":
			gkeHits++
			gkeAuth = r.Header.Get("Authorization")
			gkeQuotaProj = r.Header.Get("x-goog-user-project")
			_, _ = w.Write([]byte(`{
				"name": "demo-gke-cluster",
				"location": "us-central1",
				"status": "RUNNING",
				"currentNodeCount": 3
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gcpSrv.Close()

	t.Setenv("GCP_LOGGING_BASE_URL", gcpSrv.URL)
	t.Setenv("GCP_GKE_BASE_URL", gcpSrv.URL)

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		AgentRegistryURL: gcpSrv.URL,
		GCPProjectID:     "demo-sec-proj",
		GCPLocation:      "us-central1",
		GKEClusterName:   "demo-gke-cluster",
		HTTPClient:       gcpSrv.Client(),
	})

	for _, scenarioID := range []aegis.ScenarioID{
		aegis.Scenario03AgentGatewayAndStepUp,
		aegis.Scenario05FullChainZeroTrust,
	} {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-live-obs-" + string(scenarioID),
			Persona:    aegis.PersonaAlice,
			ScenarioID: scenarioID,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Inspect GKE cluster and Cloud Logging via governed Agent Gateway.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(%s) error = %v", scenarioID, err)
		}

		// Verify live BoundaryPlatformGovernance trace events have ProvenanceLive
		var sawLiveGov bool
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryPlatformGovernance && ev.Verdict == aegis.VerdictAllowed {
				if ev.Provenance != aegis.ProvenanceLive {
					t.Errorf("%s BoundaryPlatformGovernance event Provenance = %q, want %q (%+v)",
						scenarioID, ev.Provenance, aegis.ProvenanceLive, ev)
				}
				sawLiveGov = true
			}
		}
		if !sawLiveGov {
			t.Errorf("%s expected BoundaryPlatformGovernance VerdictAllowed with ProvenanceLive in %+v", scenarioID, res.BoundaryTrace)
		}

		// Verify live OutboundWireRecords for logging.entries.list and container.clusters.get
		var sawLiveLoggingWire, sawLiveGKEWire bool
		for _, wr := range res.WireRecords {
			if wr.Provider == aegis.ProviderGCPIAM && wr.ToolName == "logging.entries.list" && wr.Provenance == aegis.ProvenanceLive {
				sawLiveLoggingWire = true
			}
			if wr.Provider == aegis.ProviderGCPIAM && wr.ToolName == "container.clusters.get" && wr.Provenance == aegis.ProvenanceLive {
				sawLiveGKEWire = true
			}
		}
		if !sawLiveLoggingWire || !sawLiveGKEWire {
			t.Errorf("%s expected live wire records for logging.entries.list (%v) and container.clusters.get (%v) in %+v",
				scenarioID, sawLiveLoggingWire, sawLiveGKEWire, res.WireRecords)
		}
	}

	if registryHits == 0 || loggingHits == 0 || gkeHits == 0 {
		t.Fatalf("expected live hits to registry (%d), logging (%d), and GKE (%d)", registryHits, loggingHits, gkeHits)
	}
	if loggingAuth != "Bearer adc-test-observability-registry-token-456" {
		t.Errorf("Logging Authorization = %q, want Bearer adc-test-observability-registry-token-456", loggingAuth)
	}
	if loggingQuotaProj != "demo-sec-proj" {
		t.Errorf("Logging x-goog-user-project = %q, want demo-sec-proj", loggingQuotaProj)
	}
	if gkeAuth != "Bearer adc-test-observability-registry-token-456" {
		t.Errorf("GKE Authorization = %q, want Bearer adc-test-observability-registry-token-456", gkeAuth)
	}
	if gkeQuotaProj != "demo-sec-proj" {
		t.Errorf("GKE x-goog-user-project = %q, want demo-sec-proj", gkeQuotaProj)
	}
	if registryAuth != "Bearer adc-test-observability-registry-token-456" {
		t.Errorf("Agent Registry Authorization = %q, want Bearer adc-test-observability-registry-token-456", registryAuth)
	}
	if registryQuotaProj != "demo-sec-proj" {
		t.Errorf("Agent Registry x-goog-user-project = %q, want demo-sec-proj", registryQuotaProj)
	}

	// Verify DiscoverGovernedResources with /locations/global AgentRegistryURL queries /locations/global/mcpServers with x-goog-user-project
	var sawGlobalPath bool
	var globalQuotaProj string
	globalRegSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/locations/global/mcpServers") {
			sawGlobalPath = true
			globalQuotaProj = r.Header.Get("x-goog-user-project")
			_, _ = w.Write([]byte(`{"mcpServers":[{"name":"projects/demo-sec-proj/locations/global/mcpServers/logging-mcp","mcpServerId":"logging-mcp","displayName":"Cloud Logging MCP"}]}`))
			return
		}
		if strings.Contains(r.URL.Path, "/locations/global/agents") {
			_, _ = w.Write([]byte(`{"agents":[]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer globalRegSrv.Close()

	globalRT := aegis.NewRuntime(aegis.RuntimeConfig{
		AgentRegistryURL: globalRegSrv.URL + "/v1alpha/projects/demo-sec-proj/locations/global",
		GCPProjectID:     "demo-sec-proj",
		GCPLocation:      "us-central1",
		HTTPClient:       globalRegSrv.Client(),
	})
	cat, prov, err := aegis.NewAgentRegistryConnector(globalRT).DiscoverGovernedResources(ctx)
	if err != nil {
		t.Fatalf("DiscoverGovernedResources(global) error = %v", err)
	}
	if prov != aegis.ProvenanceLive || !sawGlobalPath {
		t.Errorf("DiscoverGovernedResources(global) prov=%q sawGlobalPath=%v, want LIVE and true (cat=%+v)", prov, sawGlobalPath, cat)
	}
	if globalQuotaProj != "demo-sec-proj" {
		t.Errorf("global Agent Registry x-goog-user-project = %q, want demo-sec-proj", globalQuotaProj)
	}
}

func TestLiveGCP_ADKLLMAgent_AgentPlatformGeminiSynthesis_AndFallback(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "adc-test-agent-platform-gemini-token-789")

	var (
		geminiHits int
		geminiAuth string
		geminiBody string
	)

	geminiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		geminiHits++
		geminiAuth = r.Header.Get("Authorization")
		buf := new(strings.Builder)
		_, _ = buf.WriteString("")
		raw := make([]byte, 64*1024)
		n, _ := r.Body.Read(raw)
		geminiBody = string(raw[:n])

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [
				{
					"content": {
						"role": "model",
						"parts": [
							{
								"text": "ADK v2 gemini-2.5-flash live synthesis: Triaged checkout-service HTTP 502 incident using SDP-redacted context ([REDACTED_SSN], [REDACTED_API_KEY])."
							}
						]
					},
					"finishReason": "STOP"
				}
			]
		}`))
	}))
	defer geminiSrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		AgentPlatformLiveLLM: true,
		GeminiEndpoint:       geminiSrv.URL + "/v1/projects/demo-sec-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
		GCPProjectID:         "demo-sec-proj",
		GCPLocation:          "us-central1",
		HTTPClient:           geminiSrv.Client(),
	})

	// 1. Defended success turn runs ADK v2 llmagent over sanitized input and records ProvenanceLive
	res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:    "sess-live-gemini-s1",
		Persona:      aegis.PersonaAlice,
		ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
		Posture:      aegis.AllBluePosture(),
		Prompt:       "Synthesize an incident summary for the clean customer escalation.",
		CleanPIIOnly: true,
	})
	if err != nil {
		t.Fatalf("ExecuteTurn(CleanPIIOnly) error = %v", err)
	}
	if res.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
	}
	if geminiHits == 0 {
		t.Fatalf("expected ADK v2 llmagent to query GeminiEndpoint, got 0 hits")
	}
	if geminiAuth != "Bearer adc-test-agent-platform-gemini-token-789" {
		t.Errorf("Gemini Authorization = %q, want Bearer adc-test-agent-platform-gemini-token-789", geminiAuth)
	}
	if strings.Contains(geminiBody, "123-45-6789") || strings.Contains(geminiBody, "AIzaSyD-CustomerLeakedKey999") {
		t.Errorf("Gemini request body leaked raw PII/API key: %s", geminiBody)
	}
	if !strings.Contains(geminiBody, "[REDACTED_SSN]") {
		t.Errorf("Gemini request body missing SDP redacted token [REDACTED_SSN]: %s", geminiBody)
	}
	if !strings.Contains(res.AssistantText, "ADK v2 gemini-2.5-flash live synthesis:") {
		t.Errorf("AssistantText = %q, want synthesized response from ADK v2 llmagent", res.AssistantText)
	}

	foundADKTrace := false
	for _, ev := range res.BoundaryTrace {
		if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Component == "ADK v2 llmagent (gemini-2.5-flash)" {
			if ev.Provenance != aegis.ProvenanceLive {
				t.Errorf("ADK v2 llmagent trace Provenance = %q, want %q", ev.Provenance, aegis.ProvenanceLive)
			}
			foundADKTrace = true
		}
	}
	if !foundADKTrace {
		t.Errorf("expected BoundaryReasoningGuard trace event with Component 'ADK v2 llmagent (gemini-2.5-flash)' in %+v", res.BoundaryTrace)
	}

	// 2. Blocked turn (Prompt Injection intercepted by Model Armor) must NOT invoke Gemini
	hitsBeforeBlocked := geminiHits
	blockedRes, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "sess-live-gemini-blocked",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario01PromptInjectionAndPII,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Triage adversarial customer email.",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn(blocked) error = %v", err)
	}
	if blockedRes.Outcome != aegis.OutcomeBlocked {
		t.Fatalf("blocked Outcome = %q, want %q", blockedRes.Outcome, aegis.OutcomeBlocked)
	}
	if geminiHits != hitsBeforeBlocked {
		t.Errorf("expected Gemini NOT to be called when turn is hard-blocked by Model Armor (hits before=%d, after=%d)", hitsBeforeBlocked, geminiHits)
	}

	// 3. Offline / 503 Gemini endpoint falls back cleanly to deterministic response
	offlineSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer offlineSrv.Close()

	offlineRT := aegis.NewRuntime(aegis.RuntimeConfig{
		AgentPlatformLiveLLM: true,
		GeminiEndpoint:       offlineSrv.URL + "/v1/models/gemini-2.5-flash:generateContent",
		HTTPClient:           offlineSrv.Client(),
	})
	fallbackRes, err := offlineRT.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:    "sess-offline-gemini",
		Persona:      aegis.PersonaAlice,
		ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
		Posture:      aegis.AllBluePosture(),
		Prompt:       "Triage clean customer escalation when Gemini Enterprise Agent Platform is unreachable.",
		CleanPIIOnly: true,
	})
	if err != nil {
		t.Fatalf("ExecuteTurn(offline fallback) error = %v", err)
	}
	if fallbackRes.Outcome != aegis.OutcomeDefendedSuccess || fallbackRes.AssistantText == "" {
		t.Errorf("offline fallback result = %+v, want OutcomeDefendedSuccess with non-empty deterministic AssistantText", fallbackRes)
	}
}


