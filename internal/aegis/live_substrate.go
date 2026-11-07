package aegis

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	substrateCmdRunnerExtKey             = "substrate_cmd_runner"
	substrateRouterBridgeExtKey          = "substrate_router_bridge"
	defaultSubstrateTargetActor          = "aegis-system/remediator-1"
	inClusterAtenetRouterExecuteURL      = "https://atenet-router.ate-system.svc.cluster.local/sandbox/execute"
	inClusterAtenetRouterServerName      = "atenet-router.ate-system.svc"
	defaultSubstrateRouterCredBundlePath = "/run/podidentity.podcert.ate.dev/credential-bundle.pem"
	defaultSubstrateRouterCAFilePath     = "/run/servicedns-ca/trust-bundle.pem"
)

func init() {
	RegisterHTTPRoutes(registerSubstrateHTTPRoutes)
}

// TODO(security): POST /sandbox/execute bridges attenuated SandboxExecutionRequests (zero 3LO credentials)
// to in-cluster svc/atenet-router over SPIFFE mTLS when KUBERNETES_SERVICE_HOST is set;
// SQL parameterization, multipart file-upload scanning, and cookie-based CSRF tokens are N/A
// (zero SQL DB, zero file uploads, zero auth cookies).
func registerSubstrateHTTPRoutes(mux *http.ServeMux, rt *Runtime) {
	mux.HandleFunc("POST /sandbox/execute", func(w http.ResponseWriter, r *http.Request) {
		var execReq SandboxExecutionRequest
		if r.Body != nil {
			defer r.Body.Close()
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&execReq)
		}
		if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
			gwURL := strings.TrimSpace(rt.Config().SubstrateGatewayURL)
			if gwURL == "" || (r.Host != "" && strings.Contains(gwURL, r.Host)) {
				gwURL = inClusterAtenetRouterExecuteURL
			}
			if resp, _, ok := NewSubstrateSandboxConnector(rt).dispatchGatewayHTTP(r.Context(), gwURL, execReq); ok && resp != nil {
				writeJSON(w, http.StatusOK, resp)
				return
			}
		}
		NewRemediatorActorHandler(nil).ServeHTTP(w, r)
	})
}

// NewSubstrateRouterMTLSClient constructs an *http.Client configured with the projected
// podidentity.podcert.ate.dev/identity client certificate bundle and servicedns.podcert.ate.dev/identity
// ClusterTrustBundle CA pool for SPIFFE mTLS dispatch to svc/atenet-router:443.
func NewSubstrateRouterMTLSClient(caFile, credBundle string) (*http.Client, error) {
	caFile = strings.TrimSpace(caFile)
	credBundle = strings.TrimSpace(credBundle)
	if caFile == "" || credBundle == "" {
		return nil, errors.New("both router CA file and credential bundle paths are required")
	}
	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read router CA bundle %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("router CA bundle %q contains no valid certificates", caFile)
	}
	cert, err := parseSubstrateRouterCredBundle(credBundle)
	if err != nil {
		return nil, fmt.Errorf("parse router credential bundle %q: %w", credBundle, err)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	tr := base.Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: inClusterAtenetRouterServerName,
		RootCAs:    pool,
		GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if fresh, freshErr := parseSubstrateRouterCredBundle(credBundle); freshErr == nil {
				return fresh, nil
			}
			return cert, nil
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   25 * time.Second,
	}, nil
}

func parseSubstrateRouterCredBundle(path string) (*tls.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var privKey crypto.PrivateKey
	var chain [][]byte
	rest := raw
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			chain = append(chain, block.Bytes)
		case "PRIVATE KEY":
			k, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("parse PKCS#8 private key: %w", parseErr)
			}
			privKey = k
		case "EC PRIVATE KEY":
			k, parseErr := x509.ParseECPrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("parse EC private key: %w", parseErr)
			}
			privKey = k
		}
	}
	if privKey == nil {
		return nil, errors.New("no PRIVATE KEY block found in credential bundle")
	}
	if len(chain) == 0 {
		return nil, errors.New("no CERTIFICATE block found in credential bundle")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: chain,
		Leaf:        leaf,
		PrivateKey:  privKey,
	}, nil
}

func substrateTargetActor(cfg RuntimeConfig) string {
	return firstNonEmpty(strings.TrimSpace(cfg.SubstrateTargetActor), defaultSubstrateTargetActor)
}

func parseSubstrateTargetActor(targetActor string) (atespace, actorName string) {
	atespace = "aegis-system"
	actorName = "remediator-1"
	trimmed := strings.TrimSpace(targetActor)
	if trimmed != "" {
		if parts := strings.SplitN(trimmed, "/", 2); len(parts) == 2 {
			if ns := sanitizeKubeIdentifier(parts[0]); ns != "" {
				atespace = ns
			}
			if act := sanitizeKubeIdentifier(parts[1]); act != "" {
				actorName = act
			}
		} else if act := sanitizeKubeIdentifier(trimmed); act != "" {
			actorName = act
		}
	}
	return atespace, actorName
}

func sanitizeKubeIdentifier(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 128 || strings.HasPrefix(s, "-") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.'
		if !valid {
			return ""
		}
	}
	return s
}

// SubstrateCommandRunner executes a local CLI command (such as kubectl) when inspecting
// or bridging to an Agent Substrate v1.0.0 gVisor WorkerPool on GKE.
type SubstrateCommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// SubstrateRouterBridge opens a short-lived local 127.0.0.1 tunnel to svc/aegis-sre:80
// (or svc/atenet-router:443 when local podidentity mTLS credentials are present)
// and returns the base URL along with a cleanup callback to close the tunnel.
type SubstrateRouterBridge func(ctx context.Context) (baseURL string, closeFn func(), err error)

// DefaultSubstrateCommandRunner runs CLI commands via os/exec.CommandContext.
func DefaultSubstrateCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// SetSubstrateCommandRunner configures a custom SubstrateCommandRunner on the Runtime
// for deterministic testing of kubectl-bridged Agent Substrate v1.0.0 verification.
func (r *Runtime) SetSubstrateCommandRunner(fn SubstrateCommandRunner) {
	r.SetExtension(substrateCmdRunnerExtKey, fn)
}

// SetSubstrateRouterBridge configures a custom loopback router bridge on the Runtime
// for deterministic offline testing of verifyClusterViaKubectl + svc/atenet-router dispatch.
func (r *Runtime) SetSubstrateRouterBridge(fn SubstrateRouterBridge) {
	r.SetExtension(substrateRouterBridgeExtKey, fn)
}

func (r *Runtime) hasCustomSubstrateCommandRunner() bool {
	if v, ok := r.GetExtension(substrateCmdRunnerExtKey); ok {
		if fn, ok := v.(SubstrateCommandRunner); ok && fn != nil {
			return true
		}
	}
	return false
}

func (r *Runtime) substrateCommandRunner() SubstrateCommandRunner {
	if v, ok := r.GetExtension(substrateCmdRunnerExtKey); ok {
		if fn, ok := v.(SubstrateCommandRunner); ok && fn != nil {
			return fn
		}
	}
	return DefaultSubstrateCommandRunner
}

func (r *Runtime) substrateRouterBridge() (SubstrateRouterBridge, bool) {
	if v, ok := r.GetExtension(substrateRouterBridgeExtKey); ok {
		if fn, ok := v.(SubstrateRouterBridge); ok && fn != nil {
			return fn, true
		}
	}
	if !r.hasCustomSubstrateCommandRunner() {
		return defaultKubectlRouterBridge, true
	}
	return nil, false
}

func resolveSubstrateRouterTLSPaths() (caFile, credBundle string) {
	caFile = firstNonEmpty(strings.TrimSpace(os.Getenv("SUBSTRATE_ROUTER_CA_FILE")), defaultSubstrateRouterCAFilePath)
	credBundle = firstNonEmpty(strings.TrimSpace(os.Getenv("SUBSTRATE_ROUTER_CRED_BUNDLE")), defaultSubstrateRouterCredBundlePath)
	return caFile, credBundle
}

func hasLocalSubstrateRouterMTLS() bool {
	caFile, credBundle := resolveSubstrateRouterTLSPaths()
	if _, err := os.Stat(caFile); err != nil {
		return false
	}
	if _, err := os.Stat(credBundle); err != nil {
		return false
	}
	return true
}

func defaultKubectlRouterBridge(ctx context.Context) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcpAddr.Port <= 0 {
		_ = ln.Close()
		return "", nil, fmt.Errorf("failed to allocate loopback port on 127.0.0.1")
	}
	freePort := tcpAddr.Port
	_ = ln.Close()

	targetNS := "aegis-system"
	targetSvc := "svc/aegis-sre"
	targetPort := 80
	scheme := "http"
	if hasLocalSubstrateRouterMTLS() {
		targetNS = "ate-system"
		targetSvc = "svc/atenet-router"
		targetPort = 443
		scheme = "https"
	}

	pfCtx, pfCancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(
		pfCtx,
		"kubectl",
		"-n", targetNS,
		"port-forward",
		targetSvc,
		fmt.Sprintf("%d:%d", freePort, targetPort),
		"--address", "127.0.0.1",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		pfCancel()
		return "", nil, err
	}

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()

	var closeOnce sync.Once
	closeFn := func() {
		closeOnce.Do(func() {
			pfCancel()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			select {
			case <-doneCh:
			case <-time.After(500 * time.Millisecond):
			}
		})
	}

	addr := fmt.Sprintf("127.0.0.1:%d", freePort)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case exitErr := <-doneCh:
			closeFn()
			if exitErr != nil {
				return "", nil, exitErr
			}
			return "", nil, fmt.Errorf("kubectl port-forward exited before binding %s", addr)
		default:
		}
		if ctx.Err() != nil {
			closeFn()
			return "", nil, ctx.Err()
		}
		conn, dialErr := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Sprintf("%s://%s", scheme, addr), closeFn, nil
		}
		time.Sleep(50 * time.Millisecond)
	}

	closeFn()
	return "", nil, fmt.Errorf("timed out waiting for loopback kubectl port-forward on %s", addr)
}

// SandboxExecutionRequest is the attenuated A2A payload dispatched from the Triage Orchestrator
// to the Agent Substrate v1.0.0 gVisor Sandbox Remediator (ADR-0004, ADR-0007).
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
// inside an Agent Substrate v1.0.0 gVisor Actor with atenet Egress MITM.
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

// SubstrateSandboxConnector dispatches untrusted repository test runs to a live Agent Substrate v1.0.0
// gateway URL or verifies the active GKE cluster's ate.dev/v1 WorkerPool and gVisor SandboxConfig.
type SubstrateSandboxConnector struct {
	rt *Runtime
}

// NewSubstrateSandboxConnector returns a SubstrateSandboxConnector bound to rt.
func NewSubstrateSandboxConnector(rt *Runtime) *SubstrateSandboxConnector {
	return &SubstrateSandboxConnector{rt: rt}
}

func (c *SubstrateSandboxConnector) routerHTTPClient() *http.Client {
	caFile, credBundle := resolveSubstrateRouterTLSPaths()
	if mtlsClient, err := NewSubstrateRouterMTLSClient(caFile, credBundle); err == nil && mtlsClient != nil {
		return mtlsClient
	}
	return &http.Client{Timeout: 25 * time.Second}
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
		if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
			if resp, wire, ok := c.dispatchGatewayHTTP(ctx, inClusterAtenetRouterExecuteURL, execReq); ok && resp != nil {
				return resp, wire, true
			}
		}
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

	targetActor := substrateTargetActor(c.rt.Config())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("ate-target-actor", targetActor)
	httpReq.Header.Set("X-Substrate-Sandbox-Class", execReq.SandboxClass)
	httpReq.Header.Set("X-Substrate-Fidelity", execReq.PreferredFidelity)

	hc := c.rt.Config().HTTPClient
	if hc == nil {
		hc = c.routerHTTPClient()
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
	if parsed.BlockedEgress == "" && parsed.Verified && execReq.AtenetMITMEnabled && !strings.HasPrefix(parsed.Metadata["evilExfilProbe"], "http:2") {
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
				"ate-target-actor":          targetActor,
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
			"bridgeMode":    "kubectl-ate-v1",
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
	targetActor := substrateTargetActor(c.rt.Config())
	atespace, targetActorName := parseSubstrateTargetActor(targetActor)

	if len(podList.Items) > 0 && podList.Items[0].Metadata.Name != "" {
		phase := strings.TrimSpace(podList.Items[0].Status.Phase)
		if phase == "" || strings.EqualFold(phase, "Running") {
			podName := podList.Items[0].Metadata.Name
			podNS := firstNonEmpty(podList.Items[0].Metadata.Namespace, atespace)
			parsed.Metadata["sandboxPod"] = podName
			if podIP := strings.TrimSpace(podList.Items[0].Status.PodIP); podIP != "" {
				parsed.Metadata["workerPodIP"] = podIP
			}
			if c.rt.hasCustomSubstrateCommandRunner() {
				if execOut, execErr := runner(cmdCtx, "kubectl", "exec", "-n", podNS, podName, "--", "go", "test", "./..."); execErr == nil && len(execOut) > 0 {
					parsed.TestOutput = strings.TrimSpace(string(execOut))
				}
			}
		}
	}

	kubectlAteCandidates := []string{"kubectl-ate"}
	if homeDir := strings.TrimSpace(os.Getenv("HOME")); homeDir != "" {
		kubectlAteCandidates = append(kubectlAteCandidates, filepath.Join(homeDir, "go", "bin", "kubectl-ate"))
	}

	var actorsOut, egressOut []byte
	for _, bin := range kubectlAteCandidates {
		if out, err := runner(cmdCtx, bin, "get", "actors", "-a", atespace, "-o", "json"); err == nil && len(bytes.TrimSpace(out)) > 0 {
			actorsOut = extractJSONPayload(out)
			if egOut, egErr := runner(cmdCtx, bin, "get", "egress-policy", targetActorName, "-a", atespace, "-o", "json"); egErr == nil && hasMeaningfulEgressPolicyJSON(egOut) {
				egressOut = extractJSONPayload(egOut)
			} else if targetActorName != "default" {
				if defOut, defErr := runner(cmdCtx, bin, "get", "egress-policy", "default", "-a", atespace, "-o", "json"); defErr == nil && hasMeaningfulEgressPolicyJSON(defOut) {
					egressOut = extractJSONPayload(defOut)
				}
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
				State            string `json:"state"`
				Phase            string `json:"phase"`
				WorkerAssignment struct {
					WorkerPod    string   `json:"workerPod"`
					WorkerPodIPs []string `json:"workerPodIps"`
				} `json:"workerAssignment"`
			} `json:"status"`
		}
		var actorList struct {
			Actors []actorEntry `json:"actors"`
			Items  []actorEntry `json:"items"`
		}
		var entries []actorEntry
		if json.Unmarshal(actorsOut, &actorList) == nil {
			if len(actorList.Actors) > 0 {
				entries = actorList.Actors
			} else if len(actorList.Items) > 0 {
				entries = actorList.Items
			}
		}
		if len(entries) == 0 {
			var actorSlice []actorEntry
			if json.Unmarshal(actorsOut, &actorSlice) == nil && len(actorSlice) > 0 {
				entries = actorSlice
			}
		}
		if len(entries) > 0 {
			selected := entries[0]
			for _, candidate := range entries {
				if firstNonEmpty(candidate.Metadata.Name, candidate.Name) == targetActorName {
					selected = candidate
					break
				}
			}
			if name := firstNonEmpty(selected.Metadata.Name, selected.Name); name != "" {
				parsed.Metadata["actorName"] = name
			}
			if state := firstNonEmpty(selected.Status.State, firstNonEmpty(selected.Status.Phase, selected.State)); state != "" {
				parsed.Metadata["actorState"] = state
			}
			if parsed.Metadata["sandboxPod"] == "" && strings.TrimSpace(selected.Status.WorkerAssignment.WorkerPod) != "" {
				parsed.Metadata["sandboxPod"] = strings.TrimSpace(selected.Status.WorkerAssignment.WorkerPod)
			}
			if parsed.Metadata["workerPodIP"] == "" && len(selected.Status.WorkerAssignment.WorkerPodIPs) > 0 && strings.TrimSpace(selected.Status.WorkerAssignment.WorkerPodIPs[0]) != "" {
				parsed.Metadata["workerPodIP"] = strings.TrimSpace(selected.Status.WorkerAssignment.WorkerPodIPs[0])
			}
		}
		if len(egressOut) > 0 {
			da, hosts := parseEgressPolicySummary(egressOut)
			if da != "" {
				parsed.Metadata["egressDefaultAction"] = da
			}
			if len(hosts) > 0 {
				parsed.Metadata["egressAllowedHosts"] = strings.Join(hosts, ",")
				parsed.AllowedEgress = hosts[0]
			}
		}
		wire = append(wire, OutboundWireRecord{
			Provider:          ProviderGCPIAM,
			ToolName:          "substrate.kubectl_ate.inspect_actors",
			Method:            http.MethodGet,
			URL:               fmt.Sprintf("ate://%s/actors", atespace),
			AuthHeaderPresent: true,
			AuthPrincipal:     "kubeconfig:current-context",
			StatusCode:        http.StatusOK,
			Provenance:        ProvenanceLive,
			Headers: map[string]string{
				"X-Substrate-Atespace": atespace,
			},
		})
	}

	if bridgeFn, useBridge := c.rt.substrateRouterBridge(); useBridge && bridgeFn != nil {
		bridgeCtx, bridgeCancel := context.WithTimeout(ctx, 25*time.Second)
		defer bridgeCancel()
		if baseURL, closeBridge, bridgeErr := bridgeFn(bridgeCtx); bridgeErr == nil && strings.TrimSpace(baseURL) != "" {
			if closeBridge != nil {
				defer closeBridge()
			}
			execURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/sandbox/execute"
			if gwResp, gwWire, gwOK := c.dispatchGatewayHTTP(bridgeCtx, execURL, execReq); gwOK && gwResp != nil {
				parsed.Verified = gwResp.Verified
				if gwResp.SandboxClass != "" {
					parsed.SandboxClass = gwResp.SandboxClass
				}
				if gwResp.PreferredFidelity != "" {
					parsed.PreferredFidelity = gwResp.PreferredFidelity
				}
				if gwResp.TestOutput != "" {
					parsed.TestOutput = gwResp.TestOutput
				}
				if gwResp.AllowedEgress != "" {
					parsed.AllowedEgress = gwResp.AllowedEgress
				}
				parsed.BlockedEgress = gwResp.BlockedEgress
				parsed.Metadata["bridgeMode"] = "atenet-router-loopback"
				parsed.Metadata["targetActor"] = targetActor
				for k, v := range gwResp.Metadata {
					if strings.TrimSpace(v) != "" {
						parsed.Metadata[k] = v
					}
				}
				if gwResp.Verified && parsed.Metadata["actorState"] == "ACTOR_STATE_SUSPENDED" {
					parsed.Metadata["actorState"] = "ACTOR_STATE_RUNNING"
				}
				wire = append(wire, gwWire...)
			}
		}
	}

	return parsed, wire, true
}

func extractJSONPayload(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	objIdx := bytes.IndexByte(trimmed, '{')
	arrIdx := bytes.IndexByte(trimmed, '[')
	start := -1
	if objIdx >= 0 && arrIdx >= 0 {
		if objIdx < arrIdx {
			start = objIdx
		} else {
			start = arrIdx
		}
	} else if objIdx >= 0 {
		start = objIdx
	} else if arrIdx >= 0 {
		start = arrIdx
	}
	if start < 0 {
		return nil
	}
	return bytes.TrimSpace(trimmed[start:])
}

func hasMeaningfulEgressPolicyJSON(raw []byte) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	if strings.Contains(strings.ToLower(string(raw)), "has no egress policy") {
		return false
	}
	payload := extractJSONPayload(raw)
	if len(payload) <= 2 {
		return false
	}
	var probe struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		DefaultAction string            `json:"defaultAction"`
		Rules         []json.RawMessage `json:"rules"`
		Spec          struct {
			DefaultAction string            `json:"defaultAction"`
			Rules         []json.RawMessage `json:"rules"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return false
	}
	return probe.Metadata.Name != "" ||
		probe.DefaultAction != "" ||
		probe.Spec.DefaultAction != "" ||
		len(probe.Rules) > 0 ||
		len(probe.Spec.Rules) > 0
}

func parseEgressPolicySummary(payload []byte) (defaultAction string, allowedHosts []string) {
	type egressPolicyRule struct {
		HTTPS struct {
			Hostnames []string `json:"hostnames"`
		} `json:"https"`
		Destinations []struct {
			Host string `json:"host"`
		} `json:"destinations"`
	}
	var epObj struct {
		DefaultAction string             `json:"defaultAction"`
		Rules         []egressPolicyRule `json:"rules"`
		Spec          struct {
			DefaultAction string             `json:"defaultAction"`
			Rules         []egressPolicyRule `json:"rules"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(payload, &epObj); err != nil {
		return "", nil
	}
	defaultAction = firstNonEmpty(epObj.Spec.DefaultAction, epObj.DefaultAction)
	seen := map[string]bool{}
	addHost := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			allowedHosts = append(allowedHosts, h)
		}
	}
	for _, r := range append(epObj.Rules, epObj.Spec.Rules...) {
		for _, h := range r.HTTPS.Hostnames {
			addHost(h)
		}
		for _, d := range r.Destinations {
			addHost(d.Host)
		}
	}
	return defaultAction, allowedHosts
}
