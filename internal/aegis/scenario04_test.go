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
)

func TestScenario04_AttenuatedA2AFederationAndSubstrateSandbox_RedVsBlue(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})

	t.Run("BlueMode strips upstream 3LO credentials on A2A handoff, enforces gVisor EgressPolicy + atenet MITM, screens peer response, and emits SandboxExecutionCard", func(t *testing.T) {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:            "sess-blue-s4",
			Persona:              aegis.PersonaAlice,
			ScenarioID:           aegis.Scenario04AttenuatedA2ASandbox,
			Posture:              aegis.AllBluePosture(),
			Prompt:               "Delegate checkout v2.4 repository go test verification to Sandbox Remediator.",
			ForwardedBearerToken: "ya29" + ".alice-3lo-upstream-secret-token",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardSandboxExecution {
			t.Fatalf("Cards = %+v, want first card %q", res.Cards, aegis.CardSandboxExecution)
		}
		card := res.Cards[0]
		if card.MimeType != "application/json+a2ui" {
			t.Errorf("Card.MimeType = %q, want application/json+a2ui", card.MimeType)
		}
		if card.Fields["sandboxClass"] != "gvisor" {
			t.Errorf("Card.Fields[sandboxClass] = %q, want gvisor", card.Fields["sandboxClass"])
		}
		if card.Fields["preferredFidelity"] != "SNAPSHOT_FIDELITY_MEMORY" {
			t.Errorf("Card.Fields[preferredFidelity] = %q, want SNAPSHOT_FIDELITY_MEMORY", card.Fields["preferredFidelity"])
		}
		if card.Fields["containerEnvSecrets"] != "0" {
			t.Errorf("Card.Fields[containerEnvSecrets] = %q, want 0", card.Fields["containerEnvSecrets"])
		}

		// Ensure upstream 3LO token never leaked into assistant text or outbound comment preview
		if strings.Contains(res.AssistantText, "ya29"+".alice-3lo-upstream-secret-token") {
			t.Errorf("BlueMode AssistantText leaked upstream 3LO token: %q", res.AssistantText)
		}

		var (
			foundA2AAttenuation   bool
			foundSandboxBlock     bool
			foundPeerScreen       bool
			foundAllowedGitHubMITM bool
			foundBlockedEvilExfil  bool
		)
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryCrossAgentA2A && ev.Verdict == aegis.VerdictAllowed {
				if strings.Contains(ev.Detail, "withoutCredentialParts") || ev.Metadata["credentialsStripped"] == "true" {
					foundA2AAttenuation = true
				}
			}
			if ev.Boundary == aegis.BoundarySandboxEgress && ev.Verdict == aegis.VerdictBlocked {
				if ev.Metadata["sandboxClass"] == "gvisor" &&
					ev.Metadata["preferredFidelity"] == "SNAPSHOT_FIDELITY_MEMORY" &&
					strings.Contains(ev.Detail, "evil.example.com") {
					foundSandboxBlock = true
				}
			}
			if ev.Boundary == aegis.BoundaryReasoningGuard && strings.Contains(ev.Action, "SanitizeUserPrompt") {
				foundPeerScreen = true
			}
		}
		if !foundA2AAttenuation {
			t.Errorf("BoundaryTrace missing BoundaryCrossAgentA2A VerdictAllowed with withoutCredentialParts: %+v", res.BoundaryTrace)
		}
		if !foundSandboxBlock {
			t.Errorf("BoundaryTrace missing BoundarySandboxEgress VerdictBlocked for gvisor/SNAPSHOT_FIDELITY_MEMORY blocking evil.example.com: %+v", res.BoundaryTrace)
		}
		if !foundPeerScreen {
			t.Errorf("BoundaryTrace missing BoundaryReasoningGuard SanitizeUserPrompt peer response screening: %+v", res.BoundaryTrace)
		}

		for _, wr := range res.WireRecords {
			if strings.Contains(wr.URL, "api.github.com") && wr.AuthHeaderPresent && wr.StatusCode == http.StatusOK {
				foundAllowedGitHubMITM = true
			}
			if strings.Contains(wr.URL, "https://evil.example.com/exfil") && wr.StatusCode == http.StatusForbidden {
				foundBlockedEvilExfil = true
			}
		}
		if !foundAllowedGitHubMITM {
			t.Errorf("WireRecords missing allowed api.github.com fetch with atenet Egress MITM header injection: %+v", res.WireRecords)
		}
		if !foundBlockedEvilExfil {
			t.Errorf("WireRecords missing blocked https://evil.example.com/exfil attempt: %+v", res.WireRecords)
		}
	})

	t.Run("RedMode leaks upstream 3LO credentials and container env secrets to evil.example.com", func(t *testing.T) {
		srv := httptest.NewServer(aegis.NewHandler(rt))
		defer srv.Close()

		reqBody, _ := json.Marshal(aegis.TurnRequest{
			SessionID:  "sess-red-s4",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
			Posture:    aegis.AllRedPosture(),
			Prompt:     "Delegate checkout v2.4 repository go test verification to Sandbox Remediator.",
		})
		resp, err := http.Post(srv.URL+"/api/sessions/sess-red-s4/turns", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /api/sessions/sess-red-s4/turns error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}

		var got aegis.TurnResult
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if got.Outcome != aegis.OutcomeExploitedRed {
			t.Fatalf("Outcome = %q, want %q", got.Outcome, aegis.OutcomeExploitedRed)
		}

		foundExfilSuccess := false
		for _, wr := range got.WireRecords {
			if strings.Contains(wr.URL, "https://evil.example.com/exfil") && wr.StatusCode == http.StatusOK {
				foundExfilSuccess = true
			}
		}
		if !foundExfilSuccess {
			t.Errorf("RedMode WireRecords expected successful exfiltration to https://evil.example.com/exfil, got %+v", got.WireRecords)
		}
	})

	t.Run("PromptScreenEnabled=false while SandboxEgressMITMEnabled=true records VerdictBypassedRed on peer response screening", func(t *testing.T) {
		posture := aegis.AllBluePosture()
		posture.PromptScreenEnabled = false

		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-s4-no-prompt-screen",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
			Posture:    posture,
			Prompt:     "Delegate checkout v2.4 repository go test verification to Sandbox Remediator.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		foundPeerBypass := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Verdict == aegis.VerdictBypassedRed && strings.Contains(ev.Action, "SanitizeUserPrompt") {
				foundPeerBypass = true
			}
		}
		if !foundPeerBypass {
			t.Errorf("BoundaryTrace = %+v, expected BoundaryReasoningGuard VerdictBypassedRed when PromptScreenEnabled=false", res.BoundaryTrace)
		}
	})

	t.Run("BlueMode BoundaryReasoningGuard and BoundaryCrossAgentA2A include CLIENT_TO_AGENT gateway posture and probe AGENT_GATEWAY_INGRESS_URL while RedMode bypasses", func(t *testing.T) {
		probeHits := 0
		ingressSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			probeHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"aegis-sre","protocolVersion":"0.2.1"}`))
		}))
		defer ingressSrv.Close()

		ingressRT := aegis.NewRuntime(aegis.RuntimeConfig{
			AgentGatewayIngressURL: ingressSrv.URL,
		})

		blueRes, err := ingressRT.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-s4-ingress-probe-blue",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Delegate checkout v2.4 repository go test verification to Sandbox Remediator.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(blue) error = %v", err)
		}
		if probeHits == 0 {
			t.Errorf("expected AGENT_GATEWAY_INGRESS_URL (%s) to be probed in Blue Mode, got 0 hits", ingressSrv.URL)
		}

		sawB2GatewayPosture := false
		sawB6GatewayPosture := false
		for _, ev := range blueRes.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Verdict != aegis.VerdictBypassedRed {
				if strings.Contains(ev.Detail, "Gateway/aegis-ingress-gateway") &&
					strings.Contains(ev.Detail, "GCPAgentGateway/aegis-client-to-agent-gateway") &&
					strings.Contains(ev.Detail, "GCPAuthzPolicy/aegis-a2a-ingress-policy") &&
					strings.Contains(ev.Detail, ingressSrv.URL) {
					sawB2GatewayPosture = true
				}
			}
			if ev.Boundary == aegis.BoundaryCrossAgentA2A && ev.Verdict == aegis.VerdictAllowed {
				if strings.Contains(ev.Detail, "Gateway/aegis-ingress-gateway") &&
					strings.Contains(ev.Detail, "GCPAgentGateway/aegis-client-to-agent-gateway") &&
					strings.Contains(ev.Detail, "GCPAuthzPolicy/aegis-a2a-ingress-policy") &&
					strings.Contains(ev.Detail, ingressSrv.URL) {
					sawB6GatewayPosture = true
				}
			}
		}
		if !sawB2GatewayPosture {
			t.Errorf("BoundaryReasoningGuard trace missing CLIENT_TO_AGENT gateway posture & ingress URL: %+v", blueRes.BoundaryTrace)
		}
		if !sawB6GatewayPosture {
			t.Errorf("BoundaryCrossAgentA2A trace missing CLIENT_TO_AGENT gateway posture & ingress URL: %+v", blueRes.BoundaryTrace)
		}

		sawIngressProbeWire := false
		for _, wr := range blueRes.WireRecords {
			if strings.Contains(wr.URL, ingressSrv.URL) {
				sawIngressProbeWire = true
			}
			if !strings.Contains(wr.Headers["X-Agent-Gateway-Ingress"], ingressSrv.URL) {
				t.Errorf("WireRecord(%s) X-Agent-Gateway-Ingress = %q, want it to include %q", wr.ToolName, wr.Headers["X-Agent-Gateway-Ingress"], ingressSrv.URL)
			}
		}
		if !sawIngressProbeWire {
			t.Errorf("WireRecords missing probe to AGENT_GATEWAY_INGRESS_URL (%s): %+v", ingressSrv.URL, blueRes.WireRecords)
		}

		// Red Mode must bypass the ingress probe and gateway posture
		probeHits = 0
		redRes, err := ingressRT.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-s4-ingress-probe-red",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
			Posture:    aegis.AllRedPosture(),
			Prompt:     "Delegate checkout v2.4 repository go test verification to Sandbox Remediator.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(red) error = %v", err)
		}
		if probeHits != 0 {
			t.Errorf("expected AGENT_GATEWAY_INGRESS_URL probe to be bypassed in Red Mode, got %d hits", probeHits)
		}
		for _, ev := range redRes.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryCrossAgentA2A && strings.Contains(ev.Detail, "GCPAgentGateway/aegis-client-to-agent-gateway") {
				t.Errorf("RedMode BoundaryCrossAgentA2A unexpectedly included CLIENT_TO_AGENT gateway posture: %+v", ev)
			}
		}
	})
}

func TestGeminiEnterpriseA2AWireCompatibility(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := httptest.NewServer(aegis.NewHandler(rt))
	defer srv.Close()

	t.Run("GET /.well-known/agent-card.json advertises text/plain modes and serverSideOauth2", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/.well-known/agent-card.json")
		if err != nil {
			t.Fatalf("GET /.well-known/agent-card.json error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}

		var card struct {
			Name               string         `json:"name"`
			DefaultInputModes  []string       `json:"defaultInputModes"`
			DefaultOutputModes []string       `json:"defaultOutputModes"`
			SecuritySchemes    map[string]any `json:"securitySchemes"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
			t.Fatalf("Decode agent-card.json error = %v", err)
		}

		hasInputText := false
		hasInputTextPlain := false
		for _, m := range card.DefaultInputModes {
			if m == "text" {
				hasInputText = true
			}
			if m == "text/plain" {
				hasInputTextPlain = true
			}
		}
		if !hasInputText || !hasInputTextPlain {
			t.Errorf("defaultInputModes = %v, want both \"text\" and \"text/plain\"", card.DefaultInputModes)
		}

		hasOutputText := false
		hasOutputTextPlain := false
		for _, m := range card.DefaultOutputModes {
			if m == "text" {
				hasOutputText = true
			}
			if m == "text/plain" {
				hasOutputTextPlain = true
			}
		}
		if !hasOutputText || !hasOutputTextPlain {
			t.Errorf("defaultOutputModes = %v, want both \"text\" and \"text/plain\"", card.DefaultOutputModes)
		}

		if _, ok := card.SecuritySchemes["serverSideOauth2"]; !ok {
			t.Errorf("securitySchemes = %+v, want serverSideOauth2 entry", card.SecuritySchemes)
		}
	})

	t.Run("POST /a2a handles message/send, deduplicates consecutive identical TextParts, binds Bearer token, and emits application/json+a2ui DataPart", func(t *testing.T) {
		rpcPayload := map[string]any{
			"jsonrpc": "2.0",
			"id":      "ge-req-42",
			"method":  "message/send",
			"params": map[string]any{
				"sessionId": "ge-session-04",
				"metadata": map[string]any{
					"scenarioId": string(aegis.Scenario04AttenuatedA2ASandbox),
					"persona":    string(aegis.PersonaAlice),
				},
				"message": map[string]any{
					"role": "user",
					"parts": []map[string]any{
						{"type": "text", "text": "Triage checkout 502"},
						{"type": "text", "text": "Triage checkout 502"},
					},
				},
			},
		}
		rawReq, _ := json.Marshal(rpcPayload)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/a2a", bytes.NewReader(rawReq))
		if err != nil {
			t.Fatalf("NewRequest error = %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer ya29"+".gemini-enterprise-forwarded-token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /a2a error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}

		var rpcResp struct {
			JSONRPC string `json:"jsonrpc"`
			ID      string `json:"id"`
			Result  struct {
				Parts []struct {
					Type     string         `json:"type"`
					MimeType string         `json:"mimeType,omitempty"`
					Text     string         `json:"text,omitempty"`
					Data     map[string]any `json:"data,omitempty"`
				} `json:"parts"`
				Metadata map[string]any `json:"metadata,omitempty"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
			t.Fatalf("Decode A2A JSON-RPC response error = %v", err)
		}
		if rpcResp.JSONRPC != "2.0" || rpcResp.ID != "ge-req-42" {
			t.Errorf("JSON-RPC envelope = (%q, %q), want (2.0, ge-req-42)", rpcResp.JSONRPC, rpcResp.ID)
		}

		if gotPrompt, _ := rpcResp.Result.Metadata["deduplicatedPrompt"].(string); gotPrompt != "Triage checkout 502" {
			t.Errorf("deduplicatedPrompt = %q, want %q", gotPrompt, "Triage checkout 502")
		}
		if gotBound, _ := rpcResp.Result.Metadata["forwardedBearerBound"].(bool); !gotBound {
			t.Errorf("forwardedBearerBound = %v, want true", gotBound)
		}

		var (
			foundTextPart bool
			foundA2UIPart bool
		)
		for _, p := range rpcResp.Result.Parts {
			if p.Type == "text" && p.Text != "" {
				foundTextPart = true
			}
			if p.Type == "data" && p.MimeType == "application/json+a2ui" && p.Data != nil {
				foundA2UIPart = true
			}
		}
		if !foundTextPart {
			t.Errorf("A2A response parts missing text part: %+v", rpcResp.Result.Parts)
		}
		if !foundA2UIPart {
			t.Errorf("A2A response parts missing application/json+a2ui DataPart: %+v", rpcResp.Result.Parts)
		}

		// Verify TokenBroker.Credential resolves the forwarded Bearer token from its CredentialStore
		// for both ProviderGoogleGmail and ProviderGCPIAM.
		for _, prov := range []aegis.ProviderID{aegis.ProviderGoogleGmail, aegis.ProviderGCPIAM} {
			authCtx := aegis.WithAuthInvocation(context.Background(), aegis.AuthInvocation{
				SessionID: "ge-session-04",
				Persona:   aegis.PersonaAlice,
				Provider:  prov,
			})
			cred, err := rt.TokenBroker().Credential(authCtx)
			if err != nil {
				t.Fatalf("TokenBroker().Credential(%s) error = %v", prov, err)
			}
			hdr := http.Header{}
			if err := cred.Apply(hdr); err != nil {
				t.Fatalf("cred.Apply(%s) error = %v", prov, err)
			}
			wantAuth := "Bearer ya29" + ".gemini-enterprise-forwarded-token"
			if gotAuth := hdr.Get("Authorization"); gotAuth != wantAuth {
				t.Errorf("TokenBroker().Credential(%s) Authorization = %q, want %q", prov, gotAuth, wantAuth)
			}
		}
	})
}
