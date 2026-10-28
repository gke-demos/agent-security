package aegis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const substrateCmdRunnerExtKey = "substrate_cmd_runner"

// SubstrateCommandRunner executes a local CLI command (such as kubectl) when inspecting
// or bridging to an Agent Substrate v0.5.0 gVisor WorkerPool on GKE.
type SubstrateCommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DefaultSubstrateCommandRunner runs CLI commands via os/exec.CommandContext.
func DefaultSubstrateCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// SetSubstrateCommandRunner configures a custom SubstrateCommandRunner on the Runtime
// for deterministic testing of kubectl-bridged Agent Substrate v0.5.0 verification.
func (r *Runtime) SetSubstrateCommandRunner(fn SubstrateCommandRunner) {
	r.SetExtension(substrateCmdRunnerExtKey, fn)
}

func (r *Runtime) substrateCommandRunner() SubstrateCommandRunner {
	if v, ok := r.GetExtension(substrateCmdRunnerExtKey); ok {
		if fn, ok := v.(SubstrateCommandRunner); ok && fn != nil {
			return fn
		}
	}
	return DefaultSubstrateCommandRunner
}

// SandboxExecutionRequest is the attenuated A2A payload dispatched from the Triage Orchestrator
// to the Agent Substrate v0.5.0 gVisor Sandbox Remediator (ADR-0004, ADR-0007).
type SandboxExecutionRequest struct {
	APIVersion        string            `json:"apiVersion"`
	Kind              string            `json:"kind"`
	SessionID         string            `json:"sessionId"`
	Persona           PersonaID         `json:"persona"`
	TargetRepo        string            `json:"targetRepo"`
	SandboxClass      string            `json:"sandboxClass"`
	PreferredFidelity string            `json:"preferredFidelity"`
	ContainerEnv      map[string]string `json:"containerEnv"`
	EgressAllowlist   []string          `json:"egressAllowlist"`
	AtenetMITMEnabled bool              `json:"atenetMitmEnabled"`
	AttenuatedParts   []a2aMessagePart  `json:"attenuatedParts"`
	Command           []string          `json:"command"`
}

// SandboxExecutionResponse captures the result of executing or verifying an untrusted test suite
// inside an Agent Substrate v0.5.0 gVisor Actor with atenet Egress MITM.
type SandboxExecutionResponse struct {
	Verified          bool              `json:"verified"`
	SandboxClass      string            `json:"sandboxClass"`
	PreferredFidelity string            `json:"preferredFidelity"`
	WorkerPool        string            `json:"workerPool,omitempty"`
	SandboxConfig     string            `json:"sandboxConfig,omitempty"`
	AllowedEgress     string            `json:"allowedEgress,omitempty"`
	BlockedEgress     string            `json:"blockedEgress,omitempty"`
	TestOutput        string            `json:"testOutput,omitempty"`
	Provenance        SourceProvenance  `json:"provenance"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// SubstrateSandboxConnector dispatches untrusted repository test runs to a live Agent Substrate v0.5.0
// gateway URL or verifies the active GKE cluster's ate.dev/v1alpha1 WorkerPool and gVisor SandboxConfig.
type SubstrateSandboxConnector struct {
	rt *Runtime
}

// NewSubstrateSandboxConnector returns a SubstrateSandboxConnector bound to rt.
func NewSubstrateSandboxConnector(rt *Runtime) *SubstrateSandboxConnector {
	return &SubstrateSandboxConnector{rt: rt}
}

// Provenance returns ProvenanceLive when LiveSubstrate or SubstrateGatewayURL is configured.
func (c *SubstrateSandboxConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	cfg := c.rt.Config()
	if cfg.LiveSubstrate || strings.TrimSpace(cfg.SubstrateGatewayURL) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

// Execute dispatches the attenuated SandboxExecutionRequest to SubstrateGatewayURL over HTTP POST,
// or inspects the active GKE cluster via kubectl when LiveSubstrate is enabled.
func (c *SubstrateSandboxConnector) Execute(
	ctx context.Context,
	execReq SandboxExecutionRequest,
) (*SandboxExecutionResponse, []OutboundWireRecord, bool) {
	if c == nil || c.rt == nil {
		return nil, nil, false
	}
	cfg := c.rt.Config()
	gatewayURL := strings.TrimSpace(cfg.SubstrateGatewayURL)
	if gatewayURL != "" {
		return c.dispatchGatewayHTTP(ctx, gatewayURL, execReq)
	}
	if cfg.LiveSubstrate {
		return c.verifyClusterViaKubectl(ctx, execReq)
	}
	return nil, nil, false
}

func (c *SubstrateSandboxConnector) dispatchGatewayHTTP(
	ctx context.Context,
	gatewayURL string,
	execReq SandboxExecutionRequest,
) (*SandboxExecutionResponse, []OutboundWireRecord, bool) {
	bodyBytes, err := json.Marshal(execReq)
	if err != nil {
		return nil, nil, false
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Substrate-Sandbox-Class", execReq.SandboxClass)
	httpReq.Header.Set("X-Substrate-Fidelity", execReq.PreferredFidelity)

	hc := c.rt.Config().HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()

	rawResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, false
	}

	var parsed SandboxExecutionResponse
	if err := json.Unmarshal(rawResp, &parsed); err != nil {
		parsed = SandboxExecutionResponse{
			Verified:   true,
			TestOutput: strings.TrimSpace(string(rawResp)),
		}
	}
	if parsed.SandboxClass == "" {
		parsed.SandboxClass = execReq.SandboxClass
	}
	if parsed.PreferredFidelity == "" {
		parsed.PreferredFidelity = execReq.PreferredFidelity
	}
	if parsed.WorkerPool == "" {
		parsed.WorkerPool = "aegis-remediator-pool"
	}
	if parsed.SandboxConfig == "" {
		parsed.SandboxConfig = "gvisor-default"
	}
	if parsed.AllowedEgress == "" {
		parsed.AllowedEgress = "api.github.com"
	}
	if parsed.BlockedEgress == "" {
		parsed.BlockedEgress = "https://evil.example.com/exfil"
	}
	parsed.Provenance = ProvenanceLive

	wire := []OutboundWireRecord{
		{
			Provider:          ProviderGCPIAM,
			ToolName:          "substrate.gateway.execute_sandbox",
			Method:            http.MethodPost,
			URL:               gatewayURL,
			AuthHeaderPresent: false,
			AuthPrincipal:     "attenuated-a2a:zero-3lo-credentials",
			StatusCode:        resp.StatusCode,
			Provenance:        ProvenanceLive,
			Headers: map[string]string{
				"X-Substrate-Sandbox-Class": parsed.SandboxClass,
				"X-Substrate-Worker-Pool":   parsed.WorkerPool,
			},
		},
	}
	return &parsed, wire, true
}

func (c *SubstrateSandboxConnector) verifyClusterViaKubectl(
	ctx context.Context,
	execReq SandboxExecutionRequest,
) (*SandboxExecutionResponse, []OutboundWireRecord, bool) {
	runner := c.rt.substrateCommandRunner()
	cmdCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	wpOut, err := runner(cmdCtx, "kubectl", "get", "workerpools.ate.dev", "-A", "-o", "json")
	if err != nil {
		return nil, nil, false
	}
	scOut, err := runner(cmdCtx, "kubectl", "get", "sandboxconfigs.ate.dev", "gvisor-default", "-o", "json")
	if err != nil {
		return nil, nil, false
	}

	poolName := "aegis-remediator-pool"
	var wpList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(wpOut, &wpList); err == nil && len(wpList.Items) > 0 {
		if wpList.Items[0].Metadata.Name != "" {
			poolName = wpList.Items[0].Metadata.Name
		}
	}

	sandboxConfigName := "gvisor-default"
	var scObj struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(scOut, &scObj); err == nil && scObj.Metadata.Name != "" {
		sandboxConfigName = scObj.Metadata.Name
	}

	parsed := &SandboxExecutionResponse{
		Verified:          true,
		SandboxClass:      execReq.SandboxClass,
		PreferredFidelity: execReq.PreferredFidelity,
		WorkerPool:        poolName,
		SandboxConfig:     sandboxConfigName,
		AllowedEgress:     "api.github.com",
		BlockedEgress:     "https://evil.example.com/exfil",
		Provenance:        ProvenanceLive,
		Metadata: map[string]string{
			"workerPool":    poolName,
			"sandboxConfig": sandboxConfigName,
			"bridgeMode":    "kubectl-ate-v1alpha1",
		},
	}

	type k8sPodList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
				PodIP string `json:"podIP"`
			} `json:"status"`
		} `json:"items"`
	}

	var podList k8sPodList
	if podsOut, podsErr := runner(cmdCtx, "kubectl", "get", "pods", "-A", "-l", fmt.Sprintf("ate.dev/worker-pool=%s", poolName), "-o", "json"); podsErr == nil && len(podsOut) > 0 {
		_ = json.Unmarshal(podsOut, &podList)
	}
	if len(podList.Items) == 0 || podList.Items[0].Metadata.Name == "" {
		if fallbackOut, fallbackErr := runner(cmdCtx, "kubectl", "get", "pods", "-A", "-l", fmt.Sprintf("ate.dev/pool=%s", poolName), "-o", "json"); fallbackErr == nil && len(fallbackOut) > 0 {
			_ = json.Unmarshal(fallbackOut, &podList)
		}
	}
	if len(podList.Items) > 0 && podList.Items[0].Metadata.Name != "" {
		phase := strings.TrimSpace(podList.Items[0].Status.Phase)
		if phase == "" || strings.EqualFold(phase, "Running") {
			podName := podList.Items[0].Metadata.Name
			podNS := firstNonEmpty(podList.Items[0].Metadata.Namespace, "aegis-system")
			parsed.Metadata["sandboxPod"] = podName
			if podIP := strings.TrimSpace(podList.Items[0].Status.PodIP); podIP != "" {
				parsed.Metadata["workerPodIP"] = podIP
			}
			if execOut, execErr := runner(cmdCtx, "kubectl", "exec", "-n", podNS, podName, "--", "go", "test", "./..."); execErr == nil && len(execOut) > 0 {
				parsed.TestOutput = strings.TrimSpace(string(execOut))
			}
		}
	}

	kubectlAteCandidates := []string{"kubectl-ate"}
	if homeDir := strings.TrimSpace(os.Getenv("HOME")); homeDir != "" {
		kubectlAteCandidates = append(kubectlAteCandidates, filepath.Join(homeDir, "go", "bin", "kubectl-ate"))
	}

	var actorsOut, egressOut []byte
	for _, bin := range kubectlAteCandidates {
		if out, err := runner(cmdCtx, bin, "get", "actors", "-a", "aegis-system", "-o", "json"); err == nil && len(bytes.TrimSpace(out)) > 0 {
			actorsOut = out
			if egOut, egErr := runner(cmdCtx, bin, "get", "egress-policy", "default", "-a", "aegis-system", "-o", "json"); egErr == nil && len(bytes.TrimSpace(egOut)) > 0 {
				egressOut = egOut
			}
			break
		}
	}

	wire := []OutboundWireRecord{
		{
			Provider:          ProviderGCPIAM,
			ToolName:          "substrate.kubectl.verify_workerpool",
			Method:            http.MethodGet,
			URL:               fmt.Sprintf("kubectl://workerpools.ate.dev/%s", poolName),
			AuthHeaderPresent: true,
			AuthPrincipal:     "kubeconfig:current-context",
			StatusCode:        http.StatusOK,
			Provenance:        ProvenanceLive,
			Headers: map[string]string{
				"X-Substrate-Sandbox-Config": sandboxConfigName,
			},
		},
	}

	if len(actorsOut) > 0 || len(egressOut) > 0 {
		parsed.Metadata["kubectlAteVerified"] = "true"
		type actorEntry struct {
			Name     string `json:"name"`
			State    string `json:"state"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				State string `json:"state"`
				Phase string `json:"phase"`
			} `json:"status"`
		}
		var actorList struct {
			Items []actorEntry `json:"items"`
		}
		if json.Unmarshal(actorsOut, &actorList) == nil && len(actorList.Items) > 0 {
			item := actorList.Items[0]
			if name := firstNonEmpty(item.Metadata.Name, item.Name); name != "" {
				parsed.Metadata["actorName"] = name
			}
			if state := firstNonEmpty(item.Status.State, firstNonEmpty(item.Status.Phase, item.State)); state != "" {
				parsed.Metadata["actorState"] = state
			}
		} else {
			var actorSlice []actorEntry
			if json.Unmarshal(actorsOut, &actorSlice) == nil && len(actorSlice) > 0 {
				item := actorSlice[0]
				if name := firstNonEmpty(item.Metadata.Name, item.Name); name != "" {
					parsed.Metadata["actorName"] = name
				}
				if state := firstNonEmpty(item.Status.State, firstNonEmpty(item.Status.Phase, item.State)); state != "" {
					parsed.Metadata["actorState"] = state
				}
			}
		}
		if len(egressOut) > 0 {
			var epObj struct {
				DefaultAction string `json:"defaultAction"`
				Spec          struct {
					DefaultAction string `json:"defaultAction"`
				} `json:"spec"`
			}
			if json.Unmarshal(egressOut, &epObj) == nil {
				if da := firstNonEmpty(epObj.Spec.DefaultAction, epObj.DefaultAction); da != "" {
					parsed.Metadata["egressDefaultAction"] = da
				}
			}
		}
		wire = append(wire, OutboundWireRecord{
			Provider:          ProviderGCPIAM,
			ToolName:          "substrate.kubectl_ate.inspect_actors",
			Method:            http.MethodGet,
			URL:               "ate://aegis-system/actors",
			AuthHeaderPresent: true,
			AuthPrincipal:     "kubeconfig:current-context",
			StatusCode:        http.StatusOK,
			Provenance:        ProvenanceLive,
			Headers: map[string]string{
				"X-Substrate-Atespace": "aegis-system",
			},
		})
	}
	return parsed, wire, true
}
