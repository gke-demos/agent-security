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
		receivedActorHdr   string
		rawBodyBytes       []byte
	)

	gatewaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("SubstrateGateway method = %s, want POST", r.Method)
		}
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedClassHdr = r.Header.Get("X-Substrate-Sandbox-Class")
		receivedActorHdr = r.Header.Get("ate-target-actor")
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
	if receivedActorHdr != "aegis-system/remediator-1" {
		t.Errorf("ate-target-actor header = %q, want aegis-system/remediator-1", receivedActorHdr)
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

	// Verify OutboundWireRecord recorded for live gateway with ProvenanceLive and ate-target-actor header
	var sawGatewayWire bool
	for _, wr := range res.WireRecords {
		if wr.URL == gatewaySrv.URL && wr.Method == http.MethodPost && wr.Provenance == aegis.ProvenanceLive {
			sawGatewayWire = true
			if gotActor := wr.Headers["ate-target-actor"]; gotActor != "aegis-system/remediator-1" {
				t.Errorf("OutboundWireRecord.Headers[ate-target-actor] = %q, want aegis-system/remediator-1", gotActor)
			}
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

func TestLiveSubstrateInCluster_KubernetesServiceHostAutoRoutesToAtenetRouter(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")

	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		k := parts[0]
		if strings.HasPrefix(k, "ALICE_") || strings.HasPrefix(k, "BOB_") || k == "GITHUB_TOKEN" || strings.HasPrefix(k, "GOOGLE_OAUTH_") || strings.HasPrefix(k, "JIRA_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}

	probeClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
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

	var (
		capturedURL         string
		capturedTargetActor string
	)
	inClusterClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			capturedURL = r.URL.String()
			capturedTargetActor = r.Header.Get("ate-target-actor")
			proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, actorSrv.URL+r.URL.Path, r.Body)
			if err != nil {
				return nil, err
			}
			proxyReq.Header = r.Header.Clone()
			return actorSrv.Client().Do(proxyReq)
		}),
	}

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		LiveSubstrate: true,
		HTTPClient:    inClusterClient,
	})

	res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "sess-incluster-atenet-router",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Verify checkout v2.4 patch in-cluster via atenet-router.",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn() error = %v", err)
	}
	if res.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
	}

	const wantInClusterURL = "http://atenet-router.ate-system.svc.cluster.local/sandbox/execute"
	if capturedURL != wantInClusterURL {
		t.Errorf("in-cluster auto-dispatch URL = %q, want %q", capturedURL, wantInClusterURL)
	}
	if capturedTargetActor != "aegis-system/remediator-1" {
		t.Errorf("ate-target-actor header = %q, want aegis-system/remediator-1", capturedTargetActor)
	}

	var sawRouterWire bool
	for _, wr := range res.WireRecords {
		if wr.ToolName == "substrate.gateway.execute_sandbox" && wr.URL == wantInClusterURL {
			sawRouterWire = true
			if wr.Headers["ate-target-actor"] != "aegis-system/remediator-1" {
				t.Errorf("WireRecord Headers[ate-target-actor] = %q, want aegis-system/remediator-1", wr.Headers["ate-target-actor"])
			}
		}
	}
	if !sawRouterWire {
		t.Errorf("Expected OutboundWireRecord for %s, got %+v", wantInClusterURL, res.WireRecords)
	}

	if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardSandboxExecution {
		t.Fatalf("Expected SandboxExecutionCard, got %+v", res.Cards)
	}
	fields := res.Cards[0].Fields
	if fields["Provenance"] != string(aegis.ProvenanceLive) {
		t.Errorf("Fields[Provenance] = %q, want LIVE", fields["Provenance"])
	}
	if fields["targetActor"] != "aegis-system/remediator-1" {
		t.Errorf("Fields[targetActor] = %q, want aegis-system/remediator-1", fields["targetActor"])
	}
	if fields["zeroEnvSecretsVerified"] != "true" {
		t.Errorf("Fields[zeroEnvSecretsVerified] = %q, want true", fields["zeroEnvSecretsVerified"])
	}
	if fields["githubAllowedProbe"] != "http:200" {
		t.Errorf("Fields[githubAllowedProbe] = %q, want http:200", fields["githubAllowedProbe"])
	}
	if !strings.Contains(fields["evilExfilProbe"], "403") && !strings.HasPrefix(fields["evilExfilProbe"], "blocked:") {
		t.Errorf("Fields[evilExfilProbe] = %q, want http:403 or blocked:*", fields["evilExfilProbe"])
	}
	if strings.TrimSpace(fields["kernelSignature"]) == "" {
		t.Errorf("Fields[kernelSignature] is empty")
	}

	// Also verify SCENARIO-05 SandboxExecutionCard surfaces live proof fields
	resS5, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
		SessionID:  "sess-incluster-s5",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario05FullChainZeroTrust,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Run full-chain incident triage in-cluster.",
	})
	if err != nil {
		t.Fatalf("SCENARIO-05 ExecuteTurn() error = %v", err)
	}
	var foundS5SandboxCard bool
	for _, c := range resS5.Cards {
		if c.Type == aegis.CardSandboxExecution {
			foundS5SandboxCard = true
			if c.Fields["Provenance"] != string(aegis.ProvenanceLive) || c.Fields["zeroEnvSecretsVerified"] != "true" || c.Fields["targetActor"] != "aegis-system/remediator-1" {
				t.Errorf("SCENARIO-05 SandboxExecutionCard.Fields missing live proof: %+v", c.Fields)
			}
		}
	}
	if !foundS5SandboxCard {
		t.Errorf("Expected CardSandboxExecution in SCENARIO-05 cards: %+v", resS5.Cards)
	}

	// Verify graceful fallback to verifyClusterViaKubectl if in-cluster atenet-router is unreachable
	t.Run("FallsBackToKubectlWhenInClusterRouterUnreachable", func(t *testing.T) {
		unreachableClient := &http.Client{
			Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return nil, io.EOF
			}),
		}
		fallbackRT := aegis.NewRuntime(aegis.RuntimeConfig{
			LiveSubstrate: true,
			HTTPClient:    unreachableClient,
		})
		var fallbackKubectlCalled bool
		fallbackRT.SetSubstrateCommandRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
			fallbackKubectlCalled = true
			cmdStr := name + " " + strings.Join(args, " ")
			if strings.Contains(cmdStr, "workerpools.ate.dev") {
				return []byte(`{"items": [{"metadata": {"name": "aegis-remediator-pool", "namespace": "aegis-system"}}]}`), nil
			}
			if strings.Contains(cmdStr, "sandboxconfigs.ate.dev") {
				return []byte(`{"metadata": {"name": "gvisor-default"}}`), nil
			}
			return []byte(`{}`), nil
		})
		fbResp, _, fbOK := aegis.NewSubstrateSandboxConnector(fallbackRT).Execute(ctx, aegis.SandboxExecutionRequest{
			SandboxClass:      "gvisor",
			PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
		})
		if !fbOK || fbResp == nil || !fallbackKubectlCalled {
			t.Fatalf("Expected fallback to verifyClusterViaKubectl when router unreachable, got ok=%v called=%v", fbOK, fallbackKubectlCalled)
		}
	})
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

func TestLiveSubstrateKubectlAutoRouterBridge_MergesClusterInspectionAndGuestActorExecution(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		k := parts[0]
		if strings.HasPrefix(k, "ALICE_") || strings.HasPrefix(k, "BOB_") || k == "GITHUB_TOKEN" || strings.HasPrefix(k, "GOOGLE_OAUTH_") || strings.HasPrefix(k, "JIRA_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}

	var receivedActorHdr string
	probeClient := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
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
	guestHandler := aegis.NewRemediatorActorHandler(probeClient)
	routerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedActorHdr = r.Header.Get("ate-target-actor")
		guestHandler.ServeHTTP(w, r)
	}))
	defer routerSrv.Close()

	var executedCommands []string
	mockRunner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		cmdStr := name + " " + strings.Join(args, " ")
		executedCommands = append(executedCommands, cmdStr)
		if strings.Contains(cmdStr, "workerpools.ate.dev") {
			return []byte(`{"items": [{"metadata": {"name": "aegis-remediator-pool", "namespace": "aegis-system"}}]}`), nil
		}
		if strings.Contains(cmdStr, "sandboxconfigs.ate.dev") {
			return []byte(`{"metadata": {"name": "gvisor-default"}}`), nil
		}
		if strings.Contains(cmdStr, "get pods -A -l ate.dev/worker-pool=aegis-remediator-pool") {
			return []byte(`{"items": [{"metadata": {"name": "aegis-remediator-pool-5d86f6d56f-2jhs6", "namespace": "aegis-system"}, "status": {"phase": "Running", "podIP": "10.96.0.124"}}]}`), nil
		}
		if strings.Contains(cmdStr, "get actors -a aegis-system -o json") {
			return []byte("Warning: no --token-file given; acting as system:serviceaccount:ate-system:ate-client\n" + `{
				"actors": [{
					"metadata": {"atespace": "aegis-system", "name": "remediator-1"},
					"status": {
						"state": "ACTOR_STATE_SUSPENDED",
						"workerAssignment": {
							"workerPod": "aegis-remediator-pool-5d86f6d56f-2jhs6",
							"workerPodIps": ["10.96.0.124"]
						}
					}
				}]
			}`), nil
		}
		if strings.Contains(cmdStr, "get egress-policy remediator-1 -a aegis-system -o json") {
			return []byte("Warning: no --token-file given\n" + `{
				"metadata": {"atespace": "aegis-system", "name": "default"},
				"rules": [{"https": {"hostnames": ["api.github.com"], "ports": {"numbers": [443]}}}]
			}`), nil
		}
		return []byte(`{}`), nil
	}

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		LiveSubstrate: true,
		HTTPClient:    routerSrv.Client(),
	})
	rt.SetSubstrateCommandRunner(mockRunner)

	var bridgeClosed bool
	rt.SetSubstrateRouterBridge(func(_ context.Context) (string, func(), error) {
		return routerSrv.URL, func() { bridgeClosed = true }, nil
	})

	execResp, execWire, ok := aegis.NewSubstrateSandboxConnector(rt).Execute(ctx, aegis.SandboxExecutionRequest{
		SandboxClass:      "gvisor",
		PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
		AtenetMITMEnabled: true,
	})
	if !ok || execResp == nil {
		t.Fatalf("Execute() = (%+v, %v), want ok=true", execResp, ok)
	}
	if !bridgeClosed {
		t.Errorf("Expected loopback router bridge cleanup function to be invoked via defer")
	}
	if receivedActorHdr != "aegis-system/remediator-1" {
		t.Errorf("Router received ate-target-actor = %q, want aegis-system/remediator-1", receivedActorHdr)
	}
	if !execResp.Verified {
		t.Errorf("execResp.Verified = false, want true")
	}
	if execResp.Metadata["actorName"] != "remediator-1" {
		t.Errorf("Metadata[actorName] = %q, want remediator-1", execResp.Metadata["actorName"])
	}
	if execResp.Metadata["egressAllowedHosts"] != "api.github.com" {
		t.Errorf("Metadata[egressAllowedHosts] = %q, want api.github.com", execResp.Metadata["egressAllowedHosts"])
	}
	if execResp.Metadata["zeroEnvSecretsVerified"] != "true" {
		t.Errorf("Metadata[zeroEnvSecretsVerified] = %q, want true", execResp.Metadata["zeroEnvSecretsVerified"])
	}
	if execResp.Metadata["githubAllowedProbe"] != "http:200" {
		t.Errorf("Metadata[githubAllowedProbe] = %q, want http:200", execResp.Metadata["githubAllowedProbe"])
	}
	if strings.TrimSpace(execResp.Metadata["kernelSignature"]) == "" {
		t.Errorf("Metadata[kernelSignature] is empty")
	}
	if !strings.Contains(execResp.TestOutput, "[gVisor Actor Verified]") {
		t.Errorf("TestOutput = %q, want [gVisor Actor Verified]", execResp.TestOutput)
	}

	var sawActorEgressCmd bool
	for _, cmd := range executedCommands {
		if strings.Contains(cmd, "get egress-policy remediator-1 -a aegis-system -o json") {
			sawActorEgressCmd = true
		}
	}
	if !sawActorEgressCmd {
		t.Errorf("Expected kubectl-ate get egress-policy remediator-1 -a aegis-system -o json, got %v", executedCommands)
	}

	var sawGatewayWire bool
	for _, wr := range execWire {
		if wr.ToolName == "substrate.gateway.execute_sandbox" && wr.Headers["ate-target-actor"] == "aegis-system/remediator-1" {
			sawGatewayWire = true
		}
	}
	if !sawGatewayWire {
		t.Errorf("Expected substrate.gateway.execute_sandbox wire record with ate-target-actor header, got %+v", execWire)
	}

	t.Run("FallsBackToDefaultEgressPolicyWhenActorHasNoPolicy", func(t *testing.T) {
		var canaryCmds []string
		canaryRT := aegis.NewRuntime(aegis.RuntimeConfig{
			LiveSubstrate:        true,
			SubstrateTargetActor: "aegis-system/canary-actor",
		})
		canaryRT.SetSubstrateCommandRunner(func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmdStr := name + " " + strings.Join(args, " ")
			canaryCmds = append(canaryCmds, cmdStr)
			if strings.Contains(cmdStr, "workerpools.ate.dev") {
				return []byte(`{"items": [{"metadata": {"name": "aegis-remediator-pool", "namespace": "aegis-system"}}]}`), nil
			}
			if strings.Contains(cmdStr, "sandboxconfigs.ate.dev") {
				return []byte(`{"metadata": {"name": "gvisor-default"}}`), nil
			}
			if strings.Contains(cmdStr, "get actors -a aegis-system -o json") {
				return []byte(`{"actors": [{"metadata": {"name": "canary-actor"}, "status": {"state": "ACTOR_STATE_RUNNING"}}]}`), nil
			}
			if strings.Contains(cmdStr, "get egress-policy canary-actor -a aegis-system -o json") {
				return []byte(`actor "canary-actor" in atespace "aegis-system" has no egress policy`), nil
			}
			if strings.Contains(cmdStr, "get egress-policy default -a aegis-system -o json") {
				return []byte(`{"metadata": {"name": "default"}, "spec": {"defaultAction": "DENY"}}`), nil
			}
			return []byte(`{}`), nil
		})
		cResp, _, cOK := aegis.NewSubstrateSandboxConnector(canaryRT).Execute(ctx, aegis.SandboxExecutionRequest{
			SandboxClass: "gvisor",
		})
		if !cOK || cResp == nil {
			t.Fatalf("Execute() failed on canary-actor fallback")
		}
		if cResp.Metadata["egressDefaultAction"] != "DENY" {
			t.Errorf("Metadata[egressDefaultAction] = %q, want DENY from default policy fallback", cResp.Metadata["egressDefaultAction"])
		}
	})
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

	// 3. Verify leaked secret in os.Environ sets zeroEnvSecretsVerified = "false" and Verified = false
	t.Run("DetectsLeakedEnvSecret", func(t *testing.T) {
		for _, envKey := range []string{"ALICE_GITHUB_TOKEN", "GITHUB_PAT", "GOOGLE_APPLICATION_CREDENTIALS", "JIRA_API_TOKEN"} {
			t.Run(envKey, func(t *testing.T) {
				t.Setenv(envKey, "secret_leaked_in_env")
				leakedResp, _, ok := aegis.NewSubstrateSandboxConnector(rt).Execute(context.Background(), aegis.SandboxExecutionRequest{
					SandboxClass:      "gvisor",
					PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
					AtenetMITMEnabled: true,
				})
				if !ok || leakedResp == nil {
					t.Fatalf("Execute failed")
				}
				if leakedResp.Metadata["zeroEnvSecretsVerified"] != "false" {
					t.Errorf("Metadata[zeroEnvSecretsVerified] = %q, want false when %s is present", leakedResp.Metadata["zeroEnvSecretsVerified"], envKey)
				}
				if leakedResp.Verified {
					t.Errorf("leakedResp.Verified = true, want false when %s is present", envKey)
				}
			})
		}
	})

	// 4. Verify when evil.example.com/exfil returns 200 OK despite AtenetMITMEnabled=true, Verified is false and BlockedEgress is empty
	t.Run("DetectsUnblockedEvilEgress", func(t *testing.T) {
		unblockedProbeClient := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
					Request:    req,
				}, nil
			}),
		}
		unblockedSrv := httptest.NewServer(aegis.NewRemediatorActorHandler(unblockedProbeClient))
		defer unblockedSrv.Close()

		unblockedRT := aegis.NewRuntime(aegis.RuntimeConfig{
			SubstrateGatewayURL: unblockedSrv.URL + "/sandbox/execute",
			HTTPClient:          unblockedSrv.Client(),
		})
		unblockedResp, _, ok := aegis.NewSubstrateSandboxConnector(unblockedRT).Execute(context.Background(), aegis.SandboxExecutionRequest{
			SandboxClass:      "gvisor",
			PreferredFidelity: "SNAPSHOT_FIDELITY_MEMORY",
			AtenetMITMEnabled: true,
		})
		if !ok || unblockedResp == nil {
			t.Fatalf("Execute failed")
		}
		if unblockedResp.Verified {
			t.Errorf("unblockedResp.Verified = true, want false when evil.example.com returns 200 OK")
		}
		if unblockedResp.BlockedEgress != "" {
			t.Errorf("unblockedResp.BlockedEgress = %q, want empty string when evil.example.com is not blocked", unblockedResp.BlockedEgress)
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
		"workload: aegis-remediator-pool",
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
		"sandbox-remediator-template",
		"atespace: aegis-system",
		"workload: aegis-remediator-pool",
		"preferredFidelity: SNAPSHOT_FIDELITY_MEMORY",
		"GOLDEN_SNAPSHOT_MODE_ENABLED",
		"cpuMillicores: \"1000\"",
		"memoryBytes: \"536870912\"",
		"systemInfo:",
		"trustBundle:",
		"egress-mitm.ate.dev",
		"system-roots.ate.dev",
		"trust-bundle.pem",
		"containers:",
		"us-central1-docker.pkg.dev/PROJECT_ID/aegis/aegis-server:latest",
		"--mode=remediator-actor",
		"name: PORT",
		`value: "80"`,
		"name: SSL_CERT_FILE",
		"value: /run/ate/trust-bundle.pem",
		"wakeupProbe:",
		"path: /healthz",
		"port: 80",
		"timeoutSeconds: 30",
		"rules:",
		"https:",
		"hostnames:",
		"api.github.com",
		"443",
	} {
		if !strings.Contains(actorContent, expected) {
			t.Errorf("manifests/01b-substrate-actor-template.yaml missing %q", expected)
		}
	}

	deployManifestPath := filepath.Join(repoRoot, "manifests", "02-aegis-deployment.yaml")
	deployRaw, err := os.ReadFile(deployManifestPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", deployManifestPath, err)
	}
	deployContent := string(deployRaw)
	for _, expected := range []string{
		"kind: Deployment",
		"name: aegis-sre",
		"us-central1-docker.pkg.dev/PROJECT_ID/aegis/aegis-server:latest",
		"name: LIVE_SUBSTRATE",
		`value: "true"`,
		"name: SUBSTRATE_GATEWAY_URL",
		"http://atenet-router.ate-system.svc.cluster.local/sandbox/execute",
		"name: SUBSTRATE_TARGET_ACTOR",
		"aegis-system/remediator-1",
	} {
		if !strings.Contains(deployContent, expected) {
			t.Errorf("manifests/02-aegis-deployment.yaml missing %q", expected)
		}
	}
}

func TestLiveSubstrateE2EGate_HonorsLiveEvalsAndLegacyEnv(t *testing.T) {
	if isLiveSubstrateE2EEnabled(func(string) string { return "" }) {
		t.Errorf("expected false when neither AEGIS_LIVE_EVALS nor AEGIS_LIVE_SUBSTRATE_E2E is set")
	}
	if !isLiveSubstrateE2EEnabled(func(k string) string {
		if k == "AEGIS_LIVE_EVALS" {
			return "true"
		}
		return ""
	}) {
		t.Errorf("expected true when AEGIS_LIVE_EVALS=true")
	}
	if !isLiveSubstrateE2EEnabled(func(k string) string {
		if k == "AEGIS_LIVE_SUBSTRATE_E2E" {
			return "true"
		}
		return ""
	}) {
		t.Errorf("expected true when AEGIS_LIVE_SUBSTRATE_E2E=true")
	}
}

func isLiveSubstrateE2EEnabled(getenv func(string) string) bool {
	isTrue := func(v string) bool {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		default:
			return false
		}
	}
	return isTrue(getenv("AEGIS_LIVE_EVALS")) || isTrue(getenv("AEGIS_LIVE_SUBSTRATE_E2E"))
}

func TestLiveSubstrateRealCluster_AutoBridgedAtenetRouter(t *testing.T) {
	if !isLiveSubstrateE2EEnabled(os.Getenv) {
		t.Skip("Skipping live GKE Substrate E2E test: set AEGIS_LIVE_EVALS=true (or AEGIS_LIVE_SUBSTRATE_E2E=true) to verify against active cluster")
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		LiveSubstrate: true,
	})

	res, err := rt.ExecuteTurn(context.Background(), aegis.TurnRequest{
		SessionID:  "live-gke-substrate-e2e",
		Persona:    aegis.PersonaAlice,
		ScenarioID: aegis.Scenario04AttenuatedA2ASandbox,
		Posture:    aegis.AllBluePosture(),
		Prompt:     "Delegate checkout fix verification to Sandbox Remediator in live gVisor sandbox.",
	})
	if err != nil {
		t.Fatalf("ExecuteTurn(SCENARIO-04 live GKE): %v", err)
	}
	if res.Outcome != aegis.OutcomeDefendedSuccess {
		t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
	}
	if len(res.Cards) == 0 {
		t.Fatalf("Expected SandboxExecutionCard, got 0 cards")
	}
	fields := res.Cards[0].Fields
	if fields["Provenance"] != string(aegis.ProvenanceLive) {
		t.Errorf("Fields[Provenance] = %q, want LIVE", fields["Provenance"])
	}
	if !strings.Contains(fields["kernelSignature"], "gvisor") {
		t.Errorf("Fields[kernelSignature] = %q, want substring 'gvisor'", fields["kernelSignature"])
	}
	if fields["zeroEnvSecretsVerified"] != "true" {
		t.Errorf("Fields[zeroEnvSecretsVerified] = %q, want 'true'", fields["zeroEnvSecretsVerified"])
	}
	if fields["githubAllowedProbe"] != "http:200" {
		t.Errorf("Fields[githubAllowedProbe] = %q, want 'http:200'", fields["githubAllowedProbe"])
	}
	if !strings.HasPrefix(fields["evilExfilProbe"], "blocked") {
		t.Errorf("Fields[evilExfilProbe] = %q, want prefix 'blocked'", fields["evilExfilProbe"])
	}
	if fields["targetActor"] != "aegis-system/remediator-1" {
		t.Errorf("Fields[targetActor] = %q, want 'aegis-system/remediator-1'", fields["targetActor"])
	}
	t.Logf("Verified live GKE Actor/remediator-1 auto-bridge: kernel=%q zeroSecrets=%q github=%q evil=%q pod=%q",
		fields["kernelSignature"], fields["zeroEnvSecretsVerified"], fields["githubAllowedProbe"], fields["evilExfilProbe"], fields["sandboxPod"])
}
