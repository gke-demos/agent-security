package aegis_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func TestLiveSubstrateGateway_AttenuatedA2ADispatchAndProvenance(t *testing.T) {
	ctx := context.Background()

	var (
		receivedReq        aegis.SandboxExecutionRequest
		receivedAuthHeader string
		receivedClassHdr   string
		rawBodyBytes       []byte
	)

	gatewaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("SubstrateGateway method = %s, want POST", r.Method)
		}
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedClassHdr = r.Header.Get("X-Substrate-Sandbox-Class")
		var err error
		rawBodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll body: %v", err)
		}
		if err := json.Unmarshal(rawBodyBytes, &receivedReq); err != nil {
			t.Fatalf("Unmarshal SandboxExecutionRequest: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		resp := aegis.SandboxExecutionResponse{
			Verified:          true,
			SandboxClass:      "gvisor",
			PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
			WorkerPool:        "aegis-remediator-pool",
			SandboxConfig:     "gvisor-default",
			AllowedEgress:     "api.github.com",
			BlockedEgress:     "https://evil.example.com/exfil",
			TestOutput:        "PASS: TestCheckoutHotfix (0.03s) in live Agent Substrate v0.5.0 gVisor Actor",
			Provenance:        aegis.ProvenanceLive,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer gatewaySrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		SubstrateGatewayURL: gatewaySrv.URL,
		GitHubTargetRepo:    "gke-demos/aegis-checkout-target",
		HTTPClient:          gatewaySrv.Client(),
	})

	upstreamSecret := "ya29" + ".alice-upstream-sensitive-3lo-token"
	res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:            "sess-live-substrate-gw",
		Persona:              aegis.PersonaAlice,
		ScenarioID:           aegis.Scenario04AttenuatedA2ASandbox,
		Posture:              aegis.AllBluePosture(),
		Prompt:               "Verify checkout v2.4 patch in live Agent Substrate v0.5.0 gVisor sandbox.",
		ForwardedBearerToken: upstreamSecret,
	})
	if err != nil {
		t.Fatalf("ExecuteTurn() error = %v", err)
	}
	if res.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
	}

	// Verify the live HTTP POST payload sent to SubstrateGatewayURL
	if receivedReq.SandboxClass != "gvisor" {
		t.Errorf("SandboxExecutionRequest.SandboxClass = %q, want gvisor", receivedReq.SandboxClass)
	}
	if receivedReq.PreferredFidelity != "SNAPSHOT_FIDELITY_MEMORY" {
		t.Errorf("SandboxExecutionRequest.PreferredFidelity = %q, want SNAPSHOT_FIDELITY_MEMORY", receivedReq.PreferredFidelity)
	}
	if len(receivedReq.ContainerEnv) != 0 {
		t.Errorf("SandboxExecutionRequest.ContainerEnv = %+v, want 0 secrets in container env", receivedReq.ContainerEnv)
	}
	if len(receivedReq.EgressAllowlist) != 1 || receivedReq.EgressAllowlist[0] != "api.github.com" {
		t.Errorf("SandboxExecutionRequest.EgressAllowlist = %v, want [api.github.com]", receivedReq.EgressAllowlist)
	}
	if !receivedReq.AtenetMITMEnabled {
		t.Errorf("SandboxExecutionRequest.AtenetMITMEnabled = false, want true")
	}
	if receivedClassHdr != "gvisor" {
		t.Errorf("X-Substrate-Sandbox-Class header = %q, want gvisor", receivedClassHdr)
	}
	// Ensure upstream 3LO bearer token was stripped via withoutCredentialParts and never sent to the sandbox gateway
	if strings.Contains(string(rawBodyBytes), upstreamSecret) || strings.Contains(receivedAuthHeader, upstreamSecret) {
		t.Errorf("Upstream 3LO token leaked into live Substrate Gateway request! body=%s auth=%s", string(rawBodyBytes), receivedAuthHeader)
	}

	// Verify BoundaryCrossAgentA2A and BoundarySandboxEgress have ProvenanceLive
	var sawLiveA2A, sawLiveSandbox bool
	for _, ev := range res.BoundaryTrace {
		if ev.Boundary == aegis.BoundaryCrossAgentA2A && ev.Provenance == aegis.ProvenanceLive {
			sawLiveA2A = true
		}
		if ev.Boundary == aegis.BoundarySandboxEgress && ev.Provenance == aegis.ProvenanceLive {
			sawLiveSandbox = true
		}
	}
	if !sawLiveA2A {
		t.Errorf("Expected BoundaryCrossAgentA2A with ProvenanceLive, got %+v", res.BoundaryTrace)
	}
	if !sawLiveSandbox {
		t.Errorf("Expected BoundarySandboxEgress with ProvenanceLive, got %+v", res.BoundaryTrace)
	}

	// Verify OutboundWireRecord recorded for live gateway with ProvenanceLive
	var sawGatewayWire bool
	for _, wr := range res.WireRecords {
		if wr.URL == gatewaySrv.URL && wr.Method == http.MethodPost && wr.Provenance == aegis.ProvenanceLive {
			sawGatewayWire = true
		}
	}
	if !sawGatewayWire {
		t.Errorf("Expected OutboundWireRecord for POST %s with ProvenanceLive, got %+v", gatewaySrv.URL, res.WireRecords)
	}

	// Verify SandboxExecutionCard.Fields["Provenance"] == "LIVE"
	if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardSandboxExecution {
		t.Fatalf("Expected SandboxExecutionCard, got %+v", res.Cards)
	}
	if gotProv := res.Cards[0].Fields["Provenance"]; gotProv != string(aegis.ProvenanceLive) {
		t.Errorf("SandboxExecutionCard.Fields[Provenance] = %q, want %q", gotProv, aegis.ProvenanceLive)
	}
}

func TestLiveSubstrateKubectlBridge_InspectsClusterCRDsAndMarksProvenanceLive(t *testing.T) {
	ctx := context.Background()

	var executedCommands []string
	mockRunner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := name + " " + strings.Join(args, " ")
		executedCommands = append(executedCommands, cmdStr)
		if strings.Contains(cmdStr, "workerpools.ate.dev") {
			return []byte(`{
				"apiVersion": "v1",
				"items": [{
					"apiVersion": "ate.dev/v1alpha1",
					"kind": "WorkerPool",
					"metadata": {"name": "aegis-remediator-pool", "namespace": "aegis-system"},
					"spec": {
						"replicas": 2,
						"sandboxClasses": [{"name": "gvisor", "configRef": {"name": "gvisor-default"}}]
					}
				}]
			}`), nil
		}
		if strings.Contains(cmdStr, "sandboxconfigs.ate.dev") {
			return []byte(`{
				"apiVersion": "ate.dev/v1alpha1",
				"kind": "SandboxConfig",
				"metadata": {"name": "gvisor-default"},
				"spec": {"runtimeClassName": "gvisor"}
			}`), nil
		}
		return []byte(`{}`), nil
	}

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		LiveSubstrate: true,
	})
	rt.SetSubstrateCommandRunner(mockRunner)

	res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "sess-live-substrate-kubectl",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Verify checkout v2.4 patch via kubectl-bridged Agent Substrate v0.5.0 gVisor pool.",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn() error = %v", err)
	}
	if res.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
	}

	var sawWorkerPoolsCmd, sawSandboxConfigCmd bool
	for _, c := range executedCommands {
		if strings.Contains(c, "kubectl get workerpools.ate.dev -A -o json") {
			sawWorkerPoolsCmd = true
		}
		if strings.Contains(c, "kubectl get sandboxconfigs.ate.dev gvisor-default -o json") {
			sawSandboxConfigCmd = true
		}
	}
	if !sawWorkerPoolsCmd || !sawSandboxConfigCmd {
		t.Errorf("Expected kubectl workerpools and sandboxconfigs commands, got %v", executedCommands)
	}

	var sawLiveSandbox bool
	for _, ev := range res.BoundaryTrace {
		if ev.Boundary == aegis.BoundarySandboxEgress && ev.Provenance == aegis.ProvenanceLive {
			sawLiveSandbox = true
			if ev.Metadata["workerPool"] != "aegis-remediator-pool" {
				t.Errorf("Metadata[workerPool] = %q, want aegis-remediator-pool", ev.Metadata["workerPool"])
			}
			if ev.Metadata["sandboxConfig"] != "gvisor-default" {
				t.Errorf("Metadata[sandboxConfig] = %q, want gvisor-default", ev.Metadata["sandboxConfig"])
			}
		}
	}
	if !sawLiveSandbox {
		t.Errorf("Expected BoundarySandboxEgress with ProvenanceLive from kubectl bridge, got %+v", res.BoundaryTrace)
	}
	if gotProv := res.Cards[0].Fields["Provenance"]; gotProv != string(aegis.ProvenanceLive) {
		t.Errorf("SandboxExecutionCard.Fields[Provenance] = %q, want %q", gotProv, aegis.ProvenanceLive)
	}
}

func TestSetupLiveSourcesWizardAndMakefileTargets(t *testing.T) {
	repoRoot := filepath.Clean("../..")
	wizardPath := filepath.Join(repoRoot, "hack", "setup-live-sources.sh")

	info, err := os.Stat(wizardPath)
	if err != nil {
		t.Fatalf("stat %s: %v", wizardPath, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("%s is not executable (mode=%v)", wizardPath, info.Mode())
	}

	// Verify bash -n syntax check passes
	cmd := exec.Command("bash", "-n", wizardPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n %s failed: %v\n%s", wizardPath, err, string(out))
	}

	raw, err := os.ReadFile(wizardPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", wizardPath, err)
	}
	content := string(raw)

	requiredWizardTokens := []string{
		"TOTAL_STAGES=5",
		".env.local",
		"GOOGLE_CLOUD_PROJECT",
		"GOOGLE_CLOUD_LOCATION",
		"GKE_CLUSTER_NAME",
		"VERTEX_LIVE_LLM",
		"MODEL_ARMOR_ENDPOINT",
		"DLP_ENDPOINT",
		"GITHUB_TARGET_REPO",
		"LIVE_GITHUB",
		"ALICE_GITHUB_TOKEN",
		"BOB_GITHUB_TOKEN",
		"JIRA_BASE_URL",
		"ALICE_JIRA_TOKEN",
		"BOB_JIRA_TOKEN",
		"ALICE_GMAIL_TOKEN",
		"LIVE_SUBSTRATE",
		"SUBSTRATE_GATEWAY_URL",
		"run_wizard \"$@\"; exit",
	}
	for _, tok := range requiredWizardTokens {
		if !strings.Contains(content, tok) {
			t.Errorf("hack/setup-live-sources.sh missing expected token %q", tok)
		}
	}

	forbiddenPersonal := []string{
		"ate" + "-cluster",
		"mofi" + "labs",
		"substrate" + "-poc",
	}
	lower := strings.ToLower(content)
	for _, f := range forbiddenPersonal {
		if strings.Contains(lower, f) {
			t.Errorf("hack/setup-live-sources.sh contains forbidden hardcoded personal identifier %q", f)
		}
	}

	// Verify Makefile contains setup-live and run-live targets
	makefileBytes, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("ReadFile Makefile: %v", err)
	}
	makefileContent := string(makefileBytes)
	for _, target := range []string{"setup-live:", "./hack/setup-live-sources.sh", "run-live:", "LIVE_SUBSTRATE=true"} {
		if !strings.Contains(makefileContent, target) {
			t.Errorf("Makefile missing %q", target)
		}
	}
}
