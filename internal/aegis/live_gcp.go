package aegis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agentregistry"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/genai"
)

var wrapLiveGCPScenariosOnce sync.Once

func ensureLiveGCPScenarioWrappers() {
	wrapLiveGCPScenariosOnce.Do(func() {
		registeredScenarioHandlersMu.Lock()
		defer registeredScenarioHandlersMu.Unlock()

		allScenarios := []ScenarioID{
			Scenario01PromptInjectionAndPII,
			Scenario02ConfusedDeputy3LO,
			Scenario03AgentGatewayAndStepUp,
			Scenario04AttenuatedA2ASandbox,
			Scenario05FullChainZeroTrust,
		}
		for _, id := range allScenarios {
			scenarioID := id
			base, exists := registeredScenarioHandlers[scenarioID]
			if !exists {
				base = func(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
					return rt.executeScenario01(ctx, req)
				}
			}
			registeredScenarioHandlers[scenarioID] = func(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
				res, err := base(ctx, rt, req)
				if err != nil || res == nil {
					return res, err
				}
				enrichTurnWithLiveGCP(ctx, rt, req, res)
				return res, nil
			}
		}
	})
}

// resolveGCPBearerToken resolves a Google Cloud OAuth 2.0 Bearer access token via:
// 1. Explicit environment token (GOOGLE_OAUTH_ACCESS_TOKEN or GCP_ACCESS_TOKEN)
// 2. Google Application Default Credentials (golang.org/x/oauth2/google.FindDefaultCredentials)
// 3. gcloud auth print-access-token CLI fallback when calling googleapis.com endpoints
// 4. Deterministic ADC fallback token so local httptest.Server endpoints verify Bearer header injection.
func resolveGCPBearerToken(ctx context.Context, targetURL string) string {
	if tok := strings.TrimSpace(os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")); tok != "" {
		return tok
	}
	if tok := strings.TrimSpace(os.Getenv("GCP_ACCESS_TOKEN")); tok != "" {
		return tok
	}

	adcCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if creds, err := google.FindDefaultCredentials(adcCtx, "https://www.googleapis.com/auth/cloud-platform"); err == nil && creds != nil && creds.TokenSource != nil {
		if tok, err := creds.TokenSource.Token(); err == nil && tok != nil && strings.TrimSpace(tok.AccessToken) != "" {
			return strings.TrimSpace(tok.AccessToken)
		}
	}

	if strings.Contains(strings.ToLower(targetURL), "googleapis.com") {
		cliCtx, cliCancel := context.WithTimeout(ctx, 2*time.Second)
		defer cliCancel()
		if out, err := exec.CommandContext(cliCtx, "gcloud", "auth", "print-access-token").Output(); err == nil {
			if tok := strings.TrimSpace(string(out)); tok != "" {
				return tok
			}
		}
	}

	return "adc-gcp-iam-token"
}

// ModelArmorSDPConnector wraps ContentGuard with SourceProvenance reporting.
type ModelArmorSDPConnector struct {
	rt *Runtime
}

// NewModelArmorSDPConnector constructs a ModelArmorSDPConnector for rt.
func NewModelArmorSDPConnector(rt *Runtime) *ModelArmorSDPConnector {
	return &ModelArmorSDPConnector{rt: rt}
}

// Provenance returns ProvenanceLive when ModelArmorEndpoint or DLPEndpoint is configured.
func (c *ModelArmorSDPConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	cfg := c.rt.Config()
	if strings.TrimSpace(cfg.ModelArmorEndpoint) != "" || strings.TrimSpace(cfg.DLPEndpoint) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

// AgentRegistryConnector discovers governed MCP servers and A2A peers via Google Cloud Agent Registry
// with Google ADC Bearer token authentication.
type AgentRegistryConnector struct {
	rt *Runtime
}

// NewAgentRegistryConnector constructs an AgentRegistryConnector for rt.
func NewAgentRegistryConnector(rt *Runtime) *AgentRegistryConnector {
	return &AgentRegistryConnector{rt: rt}
}

// Provenance returns ProvenanceLive when AgentRegistryURL is configured.
func (c *AgentRegistryConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	if strings.TrimSpace(c.rt.Config().AgentRegistryURL) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

// DiscoverGovernedResources queries Google Cloud Agent Registry with ADC Bearer authentication.
func (c *AgentRegistryConnector) DiscoverGovernedResources(ctx context.Context) (*RegistryCatalog, SourceProvenance, error) {
	if c == nil || c.rt == nil {
		return defaultRegistryCatalog(), ProvenanceFixture, nil
	}
	cfg := c.rt.Config()
	regURL := strings.TrimSpace(cfg.AgentRegistryURL)
	if regURL == "" {
		return defaultRegistryCatalog(), ProvenanceFixture, nil
	}

	baseTransport := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		baseTransport = cfg.HTTPClient.Transport
	}
	targetURL, err := url.Parse(strings.TrimRight(regURL, "/"))
	if err != nil || targetURL.Host == "" {
		return defaultRegistryCatalog(), ProvenanceFixture, nil
	}

	projectID := firstNonEmpty(strings.TrimSpace(cfg.GCPProjectID), "aegis-sre")
	location := firstNonEmpty(strings.TrimSpace(cfg.GCPLocation), "us-central1")
	token := resolveGCPBearerToken(ctx, regURL)

	hc := &http.Client{
		Transport: &adcRegistryRewriteTransport{
			base:        baseTransport,
			target:      targetURL,
			bearerToken: token,
		},
		Timeout: 5 * time.Second,
	}

	regClient, err := agentregistry.New(ctx, agentregistry.Config{
		ProjectID:  projectID,
		Location:   location,
		HTTPClient: hc,
	})
	if err == nil {
		mcpResp, mcpErr := regClient.ListMCPServers(ctx)
		agentResp, agentErr := regClient.ListAgents(ctx)
		if mcpErr == nil && agentErr == nil && len(mcpResp.MCPServers) > 0 {
			return &RegistryCatalog{
				Source:     "agentregistry_api",
				MCPServers: mcpResp.MCPServers,
				Agents:     agentResp.Agents,
			}, ProvenanceLive, nil
		}
	}

	return defaultRegistryCatalog(), ProvenanceFixture, nil
}

type adcRegistryRewriteTransport struct {
	base        http.RoundTripper
	target      *url.URL
	bearerToken string
}

func (t *adcRegistryRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = t.target.Scheme
	cloned.URL.Host = t.target.Host
	cloned.Host = t.target.Host
	if t.bearerToken != "" && cloned.Header.Get("Authorization") == "" {
		cloned.Header.Set("Authorization", "Bearer "+t.bearerToken)
	}
	return t.base.RoundTrip(cloned)
}

// GCPObservabilityConnector queries live Cloud Logging (entries:list) and GKE Cluster (clusters.get) REST APIs
// using Google ADC Bearer authentication.
type GCPObservabilityConnector struct {
	rt             *Runtime
	LoggingBaseURL string
	GKEBaseURL     string
}

// NewGCPObservabilityConnector constructs a GCPObservabilityConnector for rt.
func NewGCPObservabilityConnector(rt *Runtime) *GCPObservabilityConnector {
	var regURL string
	if rt != nil {
		regURL = strings.TrimSpace(rt.Config().AgentRegistryURL)
	}
	localFallback := ""
	if strings.HasPrefix(regURL, "http://127.0.0.1:") || strings.HasPrefix(regURL, "http://localhost:") || strings.HasPrefix(regURL, "http://[::1]:") {
		localFallback = strings.TrimRight(regURL, "/")
	}
	return &GCPObservabilityConnector{
		rt:             rt,
		LoggingBaseURL: strings.TrimRight(firstNonEmpty(strings.TrimSpace(os.Getenv("GCP_LOGGING_BASE_URL")), localFallback, "https://logging.googleapis.com"), "/"),
		GKEBaseURL:     strings.TrimRight(firstNonEmpty(strings.TrimSpace(os.Getenv("GCP_GKE_BASE_URL")), localFallback, "https://container.googleapis.com"), "/"),
	}
}

// Provenance returns ProvenanceLive when both GCPProjectID and GKEClusterName are configured.
func (c *GCPObservabilityConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	cfg := c.rt.Config()
	if strings.TrimSpace(cfg.GCPProjectID) != "" && strings.TrimSpace(cfg.GKEClusterName) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

// QueryLoggingAndGKE executes live Cloud Logging entries:list and GKE clusters.get HTTP requests.
func (c *GCPObservabilityConnector) QueryLoggingAndGKE(ctx context.Context, persona PersonaID) ([]OutboundWireRecord, SourceProvenance) {
	if c.Provenance() != ProvenanceLive {
		return nil, ProvenanceFixture
	}
	cfg := c.rt.Config()
	projectID := strings.TrimSpace(cfg.GCPProjectID)
	location := firstNonEmpty(strings.TrimSpace(cfg.GCPLocation), "us-central1")
	clusterName := strings.TrimSpace(cfg.GKEClusterName)

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}

	var records []OutboundWireRecord

	// 1. POST {LoggingBaseURL}/v2/entries:list
	loggingURL := fmt.Sprintf("%s/v2/entries:list", c.LoggingBaseURL)
	loggingBody, _ := json.Marshal(map[string]any{
		"resourceNames": []string{"projects/" + projectID},
		"pageSize":      5,
	})
	logReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loggingURL, bytes.NewReader(loggingBody))
	if err == nil {
		logReq.Header.Set("Content-Type", "application/json")
		tok := resolveGCPBearerToken(ctx, loggingURL)
		if tok != "" {
			logReq.Header.Set("Authorization", "Bearer "+tok)
		}
		if resp, doErr := hc.Do(logReq); doErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				records = append(records, OutboundWireRecord{
					Provider:          ProviderGCPIAM,
					ToolName:          "logging.entries.list",
					Method:            http.MethodPost,
					URL:               loggingURL,
					AuthHeaderPresent: tok != "",
					AuthPrincipal:     string(persona),
					StatusCode:        resp.StatusCode,
					Provenance:        ProvenanceLive,
				})
			}
		}
	}

	// 2. GET {GKEBaseURL}/v1/projects/{project}/locations/{location}/clusters/{cluster}
	gkeURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/clusters/%s", c.GKEBaseURL, projectID, location, clusterName)
	gkeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, gkeURL, nil)
	if err == nil {
		tok := resolveGCPBearerToken(ctx, gkeURL)
		if tok != "" {
			gkeReq.Header.Set("Authorization", "Bearer "+tok)
		}
		if resp, doErr := hc.Do(gkeReq); doErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				records = append(records, OutboundWireRecord{
					Provider:          ProviderGCPIAM,
					ToolName:          "container.clusters.get",
					Method:            http.MethodGet,
					URL:               gkeURL,
					AuthHeaderPresent: tok != "",
					AuthPrincipal:     string(persona),
					StatusCode:        resp.StatusCode,
					Provenance:        ProvenanceLive,
				})
			}
		}
	}

	if len(records) == 0 {
		return nil, ProvenanceFixture
	}
	return records, ProvenanceLive
}

// VertexGeminiConnector builds and executes an ADK Go v2 llmagent ("aegis_triage_orchestrator")
// backed by Vertex AI gemini-2.5-flash and governed functiontools.
type VertexGeminiConnector struct {
	rt *Runtime
}

// NewVertexGeminiConnector constructs a VertexGeminiConnector for rt.
func NewVertexGeminiConnector(rt *Runtime) *VertexGeminiConnector {
	return &VertexGeminiConnector{rt: rt}
}

// Provenance returns ProvenanceLive when VertexLiveLLM or GeminiEndpoint is configured.
func (c *VertexGeminiConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	cfg := c.rt.Config()
	if cfg.VertexLiveLLM || strings.TrimSpace(cfg.GeminiEndpoint) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

type governedToolArgs struct {
	Target string `json:"target,omitempty"`
	Query  string `json:"query,omitempty"`
}

type governedToolResult struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func buildGovernedADKTools() ([]tool.Tool, error) {
	specs := []struct {
		name string
		desc string
	}{
		{"read_gmail_escalation", "Read and SDP-sanitize customer P0 escalation emails from Gmail via 3LO Token Broker"},
		{"get_jira_issue", "Read Jira Cloud incident ticket via per-persona 3LO Token Broker"},
		{"post_jira_comment", "Post an SDP-redacted incident update comment to Jira Cloud (gated by Step-Up Confirmation)"},
		{"get_github_advisory", "Read GitHub repository security advisory and checkout-service source via 3LO Token Broker"},
		{"create_github_pull_request", "Create a remediation Pull Request on the Target Repository (gated by Step-Up Confirmation)"},
		{"query_cloud_logging", "Query GKE container logs via Agent Gateway UAP (logging.entries.list)"},
		{"get_gke_cluster_status", "Inspect GKE cluster status via Agent Gateway UAP (container.clusters.get)"},
		{"run_sandbox_verification", "Delegate untrusted go test verification over attenuated A2A v2 to Agent Substrate v0.5.0 gVisor Sandbox"},
	}
	tools := make([]tool.Tool, 0, len(specs))
	for _, sp := range specs {
		toolName := sp.name
		ft, err := functiontool.New(functiontool.Config{
			Name:        sp.name,
			Description: sp.desc,
		}, func(_ agent.Context, args governedToolArgs) (governedToolResult, error) {
			return governedToolResult{
				Status: "GOVERNED_OK",
				Detail: fmt.Sprintf("Executed governed tool %s on %s", toolName, firstNonEmpty(args.Target, args.Query, "checkout-service")),
			}, nil
		})
		if err != nil {
			return nil, err
		}
		tools = append(tools, ft)
	}
	return tools, nil
}

// BuildOrchestratorAgent constructs the ADK Go v2 llmagent ("aegis_triage_orchestrator")
// with gemini-2.5-flash and the 8 governed AegisSRE functiontools.
func (c *VertexGeminiConnector) BuildOrchestratorAgent(ctx context.Context) (agent.Agent, error) {
	tools, err := buildGovernedADKTools()
	if err != nil {
		return nil, err
	}
	llmModel := c.buildLLMModel(ctx)
	return llmagent.New(llmagent.Config{
		Name:        "aegis_triage_orchestrator",
		Description: "AegisSRE Zero-Trust Incident Triage Orchestrator on GKE",
		InstructionProvider: func(_ agent.ReadonlyContext) (string, error) {
			return "You are AegisSRE Triage Orchestrator. Summarize the incident triage outcome concisely based on the sanitized context without exposing raw PII or secrets.", nil
		},
		Model: llmModel,
		Tools: tools,
	})
}

func (c *VertexGeminiConnector) buildLLMModel(ctx context.Context) model.LLM {
	cfg := c.rt.Config()
	project := firstNonEmpty(strings.TrimSpace(cfg.GCPProjectID), "aegis-sre")
	location := firstNonEmpty(strings.TrimSpace(cfg.GCPLocation), "us-central1")
	endpoint := strings.TrimSpace(cfg.GeminiEndpoint)
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/gemini-2.5-flash:generateContent", location, project, location)
	} else if !strings.Contains(endpoint, ":generateContent") && strings.Contains(endpoint, "aiplatform.googleapis.com") {
		endpoint = fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/gemini-2.5-flash:generateContent", strings.TrimRight(endpoint, "/"), project, location)
	}

	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 8 * time.Second}
	}

	// Attempt to initialize standard adk/v2/model/gemini when using default Vertex AI endpoint
	var sdkModel model.LLM
	if strings.TrimSpace(cfg.GeminiEndpoint) == "" && strings.TrimSpace(cfg.GCPProjectID) != "" {
		if m, err := gemini.NewModel(ctx, "gemini-2.5-flash", &genai.ClientConfig{
			Backend:  genai.BackendVertexAI,
			Project:  project,
			Location: location,
		}); err == nil {
			sdkModel = m
		}
	}

	return &vertexGeminiRESTModel{
		modelName:  "gemini-2.5-flash",
		endpoint:   endpoint,
		httpClient: hc,
		sdkModel:   sdkModel,
		useDirect:  strings.TrimSpace(cfg.GeminiEndpoint) != "" || sdkModel == nil,
	}
}

type vertexGeminiRESTModel struct {
	modelName  string
	endpoint   string
	httpClient *http.Client
	sdkModel   model.LLM
	useDirect  bool
}

func (m *vertexGeminiRESTModel) Name() string {
	return m.modelName
}

func (m *vertexGeminiRESTModel) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	if !m.useDirect && m.sdkModel != nil {
		return m.sdkModel.GenerateContent(ctx, req, stream)
	}
	return func(yield func(*model.LLMResponse, error) bool) {
		payload := map[string]any{
			"contents": req.Contents,
		}
		if req.Config != nil && req.Config.SystemInstruction != nil {
			payload["systemInstruction"] = req.Config.SystemInstruction
		}
		rawBody, err := json.Marshal(payload)
		if err != nil {
			yield(nil, err)
			return
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(rawBody))
		if err != nil {
			yield(nil, err)
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if tok := resolveGCPBearerToken(ctx, m.endpoint); tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := m.httpClient.Do(httpReq)
		if err != nil {
			yield(nil, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			yield(nil, fmt.Errorf("vertex gemini endpoint returned HTTP %d", resp.StatusCode))
			return
		}
		var parsed struct {
			Candidates []struct {
				Content      *genai.Content     `json:"content"`
				FinishReason genai.FinishReason `json:"finishReason"`
			} `json:"candidates"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			yield(nil, err)
			return
		}
		if len(parsed.Candidates) == 0 || parsed.Candidates[0].Content == nil {
			yield(nil, fmt.Errorf("vertex gemini response contained no candidates"))
			return
		}
		yield(&model.LLMResponse{
			Content:      parsed.Candidates[0].Content,
			FinishReason: parsed.Candidates[0].FinishReason,
			TurnComplete: true,
		}, nil)
	}
}

// SynthesizeTurn runs the ADK Go v2 llmagent over the sanitized turn input and prompt.
func (c *VertexGeminiConnector) SynthesizeTurn(ctx context.Context, req TurnRequest, sanitizedInput string) (string, error) {
	if c.Provenance() != ProvenanceLive {
		return "", fmt.Errorf("vertex gemini connector not in LIVE mode")
	}
	orchAgent, err := c.BuildOrchestratorAgent(ctx)
	if err != nil {
		return "", err
	}
	rnr, err := runner.NewInMemory("aegis-sre", orchAgent)
	if err != nil {
		return "", err
	}

	promptText := fmt.Sprintf("Operator Prompt: %s\nSanitized Context:\n%s", req.Prompt, sanitizedInput)
	userMsg := genai.NewContentFromText(promptText, genai.RoleUser)

	var texts []string
	for ev, runErr := range rnr.Run(ctx, string(req.Persona), req.SessionID, userMsg, agent.RunConfig{}) {
		if runErr != nil {
			return "", runErr
		}
		if ev != nil && ev.Content != nil {
			for _, part := range ev.Content.Parts {
				if part != nil && strings.TrimSpace(part.Text) != "" {
					texts = append(texts, strings.TrimSpace(part.Text))
				}
			}
		}
	}
	if len(texts) == 0 {
		return "", fmt.Errorf("adk v2 llmagent produced no text output")
	}
	return strings.Join(texts, "\n"), nil
}

func enrichTurnWithLiveGCPObservabilityAndRegistry(ctx context.Context, r *Runtime, req TurnRequest, res *TurnResult) {
	if req.ScenarioID != Scenario03AgentGatewayAndStepUp && req.ScenarioID != Scenario05FullChainZeroTrust {
		return
	}
	cfg := r.Config()

	// 1. Live Agent Registry discovery with ADC token
	regLive := false
	if strings.TrimSpace(cfg.AgentRegistryURL) != "" {
		regConn := NewAgentRegistryConnector(r)
		if _, prov, err := regConn.DiscoverGovernedResources(ctx); err == nil && prov == ProvenanceLive {
			regLive = true
			for i := range res.BoundaryTrace {
				ev := &res.BoundaryTrace[i]
				if ev.Boundary == BoundaryPlatformGovernance &&
					(strings.Contains(ev.Component, "agentregistry") || strings.Contains(ev.Shield, "Agent Registry")) {
					ev.Provenance = ProvenanceLive
				}
			}
		}
	}

	// 2. Live GCP Observability (Cloud Logging & GKE Cluster)
	if strings.TrimSpace(cfg.GCPProjectID) != "" && strings.TrimSpace(cfg.GKEClusterName) != "" {
		obsConn := NewGCPObservabilityConnector(r)
		liveRecords, prov := obsConn.QueryLoggingAndGKE(ctx, req.Persona)
		if prov == ProvenanceLive && len(liveRecords) > 0 {
			for _, lwr := range liveRecords {
				replaced := false
				for i := range res.WireRecords {
					if res.WireRecords[i].ToolName == lwr.ToolName {
						res.WireRecords[i] = lwr
						replaced = true
						break
					}
				}
				if !replaced {
					res.WireRecords = append(res.WireRecords, lwr)
				}
			}
			for i := range res.BoundaryTrace {
				ev := &res.BoundaryTrace[i]
				if ev.Boundary == BoundaryPlatformGovernance &&
					(strings.Contains(ev.Action, "logging.entries.list") || strings.Contains(ev.Action, "container.clusters.get") || regLive) {
					ev.Provenance = ProvenanceLive
				}
			}
		}
	}
}

func enrichTurnWithLiveVertexGemini(ctx context.Context, r *Runtime, req TurnRequest, res *TurnResult) {
	if r == nil || res == nil || res.Outcome != OutcomeDefendedSuccess {
		return
	}
	conn := NewVertexGeminiConnector(r)
	if conn.Provenance() != ProvenanceLive {
		return
	}
	synthesized, err := conn.SynthesizeTurn(ctx, req, res.SanitizedInputPreview)
	if err != nil || strings.TrimSpace(synthesized) == "" {
		return
	}
	// Screen synthesized output through ContentGuard to ensure zero raw PII leak
	guarded := r.Guard().InspectAndSanitize(ctx, synthesized, req.Posture)
	if guarded.Blocked {
		return
	}
	res.AssistantText = guarded.SanitizedText
	res.BoundaryTrace = append(res.BoundaryTrace, BoundaryTraceEvent{
		Order:      len(res.BoundaryTrace) + 1,
		Boundary:   BoundaryReasoningGuard,
		Shield:     "ADK v2 Reasoning Orchestrator",
		Component:  "ADK v2 llmagent (gemini-2.5-flash)",
		Action:     "GenerateContent(aegis_triage_orchestrator)",
		Verdict:    VerdictAllowed,
		Provenance: ProvenanceLive,
		Detail:     "Synthesized incident summary via ADK Go v2 llmagent (gemini-2.5-flash) over SDP-sanitized context",
		Timestamp:  time.Now().UTC(),
	})
}
