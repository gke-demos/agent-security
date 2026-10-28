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
		if strings.Contains(cmdStr, "get pods -A -l ate.dev/worker-pool=aegis-remediator-pool") {
			return []byte(`{
				"items": [{
					"metadata": {"name": "aegis-remediator-pool-6b5f8-x9z2k", "namespace": "aegis-system"},
					"status": {"phase": "Running", "podIP": "10.28.1.42"}
				}]
			}`), nil
		}
		if strings.Contains(cmdStr, "get actors -a aegis-system -o json") {
			return []byte(`{
				"items": [{
					"metadata": {"name": "sandbox-remediator-actor-01", "namespace": "aegis-system"},
					"status": {"state": "READY"}
				}]
			}`), nil
		}
		if strings.Contains(cmdStr, "get egress-policy default -a aegis-system -o json") {
			return []byte(`{
				"metadata": {"name": "default", "namespace": "aegis-system"},
				"spec": {"defaultAction": "DENY"}
			}`), nil
		}
		if strings.Contains(cmdStr, "exec -n aegis-system aegis-remediator-pool-6b5f8-x9z2k") {
			return []byte("PASS\nok  \tgithub.com/gke-demos/aegis-checkout-target\t0.014s\n"), nil
		}
		return []byte(`{}`), nil
	}

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		LiveSubstrate: true,
	})
	rt.SetSubstrateCommandRunner(mockRunner)

	connector := aegis.NewSubstrateSandboxConnector(rt)
	execResp, execWire, ok := connector.Execute(ctx, aegis.SandboxExecutionRequest{
		SandboxClass:      "gvisor",
		PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
	})
	if !ok || execResp == nil {
		t.Fatalf("connector.Execute() = (%+v, %v), want ok=true", execResp, ok)
	}
	if execResp.Metadata["sandboxPod"] != "aegis-remediator-pool-6b5f8-x9z2k" {
		t.Errorf("Metadata[sandboxPod] = %q, want aegis-remediator-pool-6b5f8-x9z2k", execResp.Metadata["sandboxPod"])
	}
	if execResp.Metadata["workerPodIP"] != "10.28.1.42" {
		t.Errorf("Metadata[workerPodIP] = %q, want 10.28.1.42", execResp.Metadata["workerPodIP"])
	}
	if execResp.Metadata["kubectlAteVerified"] != "true" {
		t.Errorf("Metadata[kubectlAteVerified] = %q, want true", execResp.Metadata["kubectlAteVerified"])
	}
	if execResp.Metadata["actorName"] != "sandbox-remediator-actor-01" {
		t.Errorf("Metadata[actorName] = %q, want sandbox-remediator-actor-01", execResp.Metadata["actorName"])
	}
	if execResp.Metadata["actorState"] != "READY" {
		t.Errorf("Metadata[actorState] = %q, want READY", execResp.Metadata["actorState"])
	}
	var sawKubectlAteWire bool
	for _, wr := range execWire {
		if wr.ToolName == "substrate.kubectl_ate.inspect_actors" && wr.URL == "ate://aegis-system/actors" {
			sawKubectlAteWire = true
		}
	}
	if !sawKubectlAteWire {
		t.Errorf("Expected OutboundWireRecord for substrate.kubectl_ate.inspect_actors (ate://aegis-system/actors), got %+v", execWire)
	}

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

func TestRemediatorActorHandler_HealthzAndSandboxExecute(t *testing.T) {
	// Ensure clean environment for the zero-secrets check
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		k := parts[0]
		if strings.HasPrefix(k, "ALICE_") || strings.HasPrefix(k, "BOB_") || k == "GITHUB_TOKEN" || strings.HasPrefix(k, "GOOGLE_OAUTH_") || strings.HasPrefix(k, "JIRA_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}

	var probedURLs []string
	probeClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			probedURLs = append(probedURLs, r.URL.String())
			status := http.StatusOK
			if strings.Contains(r.URL.Host, "evil.example.com") {
				status = http.StatusForbidden
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	actorSrv := httptest.NewServer(aegis.NewRemediatorActorHandler(probeClient))
	defer actorSrv.Close()

	// 1. Verify GET /healthz and GET /readyz
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := actorSrv.Client().Get(actorSrv.URL + path)
		if err != nil {
			t.Fatalf("GET %s error: %v", path, err)
		}
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			resp.Body.Close()
			t.Fatalf("Decode %s JSON: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
		if body["service"] != "aegis-remediator-actor" || body["status"] != "ok" || body["sandboxClass"] != "gvisor" {
			t.Errorf("GET %s body = %+v, want service=aegis-remediator-actor status=ok sandboxClass=gvisor", path, body)
		}
	}

	// 2. Verify POST /sandbox/execute via SubstrateSandboxConnector
	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		SubstrateGatewayURL: actorSrv.URL + "/sandbox/execute",
		HTTPClient:          actorSrv.Client(),
	})
	execResp, wire, ok := aegis.NewSubstrateSandboxConnector(rt).Execute(context.Background(), aegis.SandboxExecutionRequest{
		APIVersion:        "ate.dev/v1alpha1",
		Kind:              "ActorTemplate",
		SandboxClass:      "gvisor",
		PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
		TargetRepo:        "gke-demos/aegis-checkout-target",
		AtenetMITMEnabled: true,
	})
	if !ok || execResp == nil {
		t.Fatalf("Execute against RemediatorActorHandler failed: ok=%v, resp=%+v", ok, execResp)
	}
	if !execResp.Verified || execResp.Provenance != aegis.ProvenanceLive {
		t.Errorf("execResp = (Verified=%v, Provenance=%q), want (true, LIVE)", execResp.Verified, execResp.Provenance)
	}
	if execResp.BlockedEgress != "https://evil.example.com/exfil" || execResp.AllowedEgress != "api.github.com" {
		t.Errorf("egress = (blocked=%q, allowed=%q), want (https://evil.example.com/exfil, api.github.com)", execResp.BlockedEgress, execResp.AllowedEgress)
	}
	wantTestOut := "=== RUN   TestNullCurrencyGuard\n--- PASS: TestNullCurrencyGuard (0.01s)\nPASS\nok  \tgithub.com/gke-demos/aegis-checkout-target\t0.014s [gVisor Actor Verified]"
	if execResp.TestOutput != wantTestOut {
		t.Errorf("TestOutput = %q, want %q", execResp.TestOutput, wantTestOut)
	}
	if execResp.Metadata["zeroEnvSecretsVerified"] != "true" {
		t.Errorf("Metadata[zeroEnvSecretsVerified] = %q, want true", execResp.Metadata["zeroEnvSecretsVerified"])
	}
	if strings.TrimSpace(execResp.Metadata["kernelSignature"]) == "" {
		t.Errorf("Metadata[kernelSignature] is empty")
	}
	if len(probedURLs) < 2 {
		t.Errorf("Expected probeClient to probe evil.example.com and api.github.com, got %v", probedURLs)
	}
	if len(wire) == 0 {
		t.Errorf("Expected wire records from gateway execution")
	}

	// 3. Verify leaked secret in os.Environ sets zeroEnvSecretsVerified = "false"
	t.Run("DetectsLeakedEnvSecret", func(t *testing.T) {
		t.Setenv("ALICE_GITHUB_TOKEN", "gho_leaked_in_env")
		leakedResp, _, ok := aegis.NewSubstrateSandboxConnector(rt).Execute(context.Background(), aegis.SandboxExecutionRequest{
			SandboxClass:      "gvisor",
			PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
			AtenetMITMEnabled: true,
		})
		if !ok || leakedResp == nil {
			t.Fatalf("Execute failed")
		}
		if leakedResp.Metadata["zeroEnvSecretsVerified"] != "false" {
			t.Errorf("Metadata[zeroEnvSecretsVerified] = %q, want false when ALICE_GITHUB_TOKEN is present", leakedResp.Metadata["zeroEnvSecretsVerified"])
		}
	})
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
		"AGENT_PLATFORM_LIVE_LLM",
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
	for _, target := range []string{"setup-live:", "./hack/setup-live-sources.sh", "run-live:", "LIVE_SUBSTRATE=true", "seed-live:", "./hack/seed-fixtures.sh --live"} {
		if !strings.Contains(makefileContent, target) {
			t.Errorf("Makefile missing %q", target)
		}
	}
}

func TestSubstrateManifests_ValidatedWorkerPoolAndActorTemplateSchema(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	wpManifestPath := filepath.Join(repoRoot, "manifests", "01-agent-substrate-v050.yaml")
	wpRaw, err := os.ReadFile(wpManifestPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", wpManifestPath, err)
	}
	wpContent := string(wpRaw)
	for _, expected := range []string{
		"kind: Namespace",
		"name: aegis-system",
		`ate.dev/api-access: "true"`,
		"apiVersion: ate.dev/v1alpha1",
		"kind: WorkerPool",
		"name: aegis-remediator-pool",
		"sandboxClasses:",
		"name: gvisor",
		"name: gvisor-default",
		"workerImage: ${SUBSTRATE_WORKER_IMAGE}",
		"app.kubernetes.io/name: sandbox-remediator",
		"resources:",
	} {
		if !strings.Contains(wpContent, expected) {
			t.Errorf("manifests/01-agent-substrate-v050.yaml missing %q", expected)
		}
	}

	actorManifestPath := filepath.Join(repoRoot, "manifests", "01b-substrate-actor-template.yaml")
	actorRaw, err := os.ReadFile(actorManifestPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", actorManifestPath, err)
	}
	actorContent := string(actorRaw)
	for _, expected := range []string{
		"apiVersion: ate.dev/v1alpha1",
		"kind: ActorTemplate",
		"sandbox-remediator-template",
		"sandboxClass: gvisor",
		"preferredFidelity: SNAPSHOT_FIDELITY_MEMORY",
		"egress-mitm.ate.dev",
		"--mode=remediator-actor",
		"kind: EgressPolicy",
		"allow-github-archive-via-atenet-mitm",
		"api.github.com",
	} {
		if !strings.Contains(actorContent, expected) {
			t.Errorf("manifests/01b-substrate-actor-template.yaml missing %q", expected)
		}
	}
}
