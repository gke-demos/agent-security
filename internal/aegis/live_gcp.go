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
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/agentregistry"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/genai"
)

func resolveGoogleADCToken(ctx context.Context) string {
	return resolveGCPBearerToken(ctx, "https://logging.googleapis.com")
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

	userProject := strings.TrimSpace(cfg.GCPProjectID)
	projectID := firstNonEmpty(userProject, "aegis-sre")
	location := firstNonEmpty(strings.TrimSpace(cfg.GCPLocation), "us-central1")
	if parsedProj, parsedLoc := parseProjectAndLocationFromURL(targetURL.Path); parsedProj != "" && parsedLoc != "" {
		projectID = parsedProj
		location = parsedLoc
	}
	token := resolveGCPBearerToken(ctx, regURL)

	hc := &http.Client{
		Transport: &adcRegistryRewriteTransport{
			base:        baseTransport,
			target:      targetURL,
			bearerToken: token,
			userProject: userProject,
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
		if mcpErr == nil {
			def := defaultRegistryCatalog()
			servers := mcpResp.MCPServers
			if len(servers) == 0 {
				servers = def.MCPServers
			}
			agents := def.Agents
			if agentErr == nil && len(agentResp.Agents) > 0 {
				agents = agentResp.Agents
			}
			return &RegistryCatalog{
				Source:     "agentregistry_api",
				MCPServers: servers,
				Agents:     agents,
			}, ProvenanceLive, nil
		}
	}

	return defaultRegistryCatalog(), ProvenanceFixture, nil
}

func parseProjectAndLocationFromURL(urlPath string) (string, string) {
	parts := strings.Split(strings.Trim(urlPath, "/"), "/")
	var proj, loc string
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "projects" && proj == "" {
			proj = parts[i+1]
		}
		if parts[i] == "locations" && loc == "" {
			loc = parts[i+1]
		}
	}
	return proj, loc
}

type adcRegistryRewriteTransport struct {
	base        http.RoundTripper
	target      *url.URL
	bearerToken string
	userProject string
}

func (t *adcRegistryRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = t.target.Scheme
	cloned.URL.Host = t.target.Host
	cloned.Host = t.target.Host
	if t.bearerToken != "" && cloned.Header.Get("Authorization") == "" {
		cloned.Header.Set("Authorization", "Bearer "+t.bearerToken)
	}
	if t.userProject != "" && cloned.Header.Get("x-goog-user-project") == "" {
		cloned.Header.Set("x-goog-user-project", t.userProject)
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

// QueryCloudLogging executes a live Cloud Logging entries:list HTTP request.
func (c *GCPObservabilityConnector) QueryCloudLogging(ctx context.Context, persona PersonaID) (*OutboundWireRecord, error) {
	if c == nil || c.rt == nil {
		return nil, fmt.Errorf("gcp observability connector not initialized")
	}
	cfg := c.rt.Config()
	projectID := strings.TrimSpace(cfg.GCPProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT is not configured")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}

	loggingURL := fmt.Sprintf("%s/v2/entries:list", c.LoggingBaseURL)
	loggingBody, _ := json.Marshal(map[string]any{
		"resourceNames": []string{"projects/" + projectID},
		"pageSize":      5,
	})
	logReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loggingURL, bytes.NewReader(loggingBody))
	if err != nil {
		return nil, err
	}
	logReq.Header.Set("Content-Type", "application/json")
	tok := resolveGCPBearerToken(ctx, loggingURL)
	if tok != "" {
		logReq.Header.Set("Authorization", "Bearer "+tok)
	}
	if projectID != "" {
		logReq.Header.Set("x-goog-user-project", projectID)
	}
	resp, doErr := hc.Do(logReq)
	if doErr != nil {
		return nil, doErr
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("logging entries:list returned HTTP %d", resp.StatusCode)
	}
	return &OutboundWireRecord{
		Provider:          ProviderGCPIAM,
		ToolName:          "logging.entries.list",
		Method:            http.MethodPost,
		URL:               loggingURL,
		AuthHeaderPresent: tok != "",
		AuthPrincipal:     string(persona),
		StatusCode:        resp.StatusCode,
		Provenance:        ProvenanceLive,
		Headers: map[string]string{
			"x-goog-user-project": projectID,
		},
	}, nil
}

// GetGKECluster executes a live GKE clusters.get HTTP request.
func (c *GCPObservabilityConnector) GetGKECluster(ctx context.Context, persona PersonaID) (*OutboundWireRecord, error) {
	if c == nil || c.rt == nil {
		return nil, fmt.Errorf("gcp observability connector not initialized")
	}
	cfg := c.rt.Config()
	projectID := strings.TrimSpace(cfg.GCPProjectID)
	location := firstNonEmpty(strings.TrimSpace(cfg.GCPLocation), "us-central1")
	clusterName := strings.TrimSpace(cfg.GKEClusterName)
	if projectID == "" || clusterName == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT or GKE_CLUSTER_NAME is not configured")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}

	gkeURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/clusters/%s", c.GKEBaseURL, projectID, location, clusterName)
	gkeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, gkeURL, nil)
	if err != nil {
		return nil, err
	}
	tok := resolveGCPBearerToken(ctx, gkeURL)
	if tok != "" {
		gkeReq.Header.Set("Authorization", "Bearer "+tok)
	}
	if projectID != "" {
		gkeReq.Header.Set("x-goog-user-project", projectID)
	}
	resp, doErr := hc.Do(gkeReq)
	if doErr != nil {
		return nil, doErr
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("container clusters.get returned HTTP %d", resp.StatusCode)
	}
	return &OutboundWireRecord{
		Provider:          ProviderGCPIAM,
		ToolName:          "container.clusters.get",
		Method:            http.MethodGet,
		URL:               gkeURL,
		AuthHeaderPresent: tok != "",
		AuthPrincipal:     string(persona),
		StatusCode:        resp.StatusCode,
		Provenance:        ProvenanceLive,
		Headers: map[string]string{
			"x-goog-user-project": projectID,
		},
	}, nil
}

// QueryLoggingAndGKE executes live Cloud Logging entries:list and GKE clusters.get HTTP requests.
func (c *GCPObservabilityConnector) QueryLoggingAndGKE(ctx context.Context, persona PersonaID) ([]OutboundWireRecord, SourceProvenance) {
	if c.Provenance() != ProvenanceLive {
		return nil, ProvenanceFixture
	}

	var records []OutboundWireRecord
	if logRec, err := c.QueryCloudLogging(ctx, persona); err == nil && logRec != nil {
		records = append(records, *logRec)
	}
	if gkeRec, err := c.GetGKECluster(ctx, persona); err == nil && gkeRec != nil {
		records = append(records, *gkeRec)
	}

	if len(records) == 0 {
		return nil, ProvenanceFixture
	}
	return records, ProvenanceLive
}

// AgentPlatformGeminiConnector builds and executes an ADK Go v2 llmagent ("aegis_triage_orchestrator")
// backed by Gemini Enterprise Agent Platform gemini-2.5-flash and governed functiontools.
type AgentPlatformGeminiConnector struct {
	rt *Runtime
}

// NewAgentPlatformGeminiConnector constructs an AgentPlatformGeminiConnector for rt.
func NewAgentPlatformGeminiConnector(rt *Runtime) *AgentPlatformGeminiConnector {
	return &AgentPlatformGeminiConnector{rt: rt}
}

// Provenance returns ProvenanceLive when AgentPlatformLiveLLM or GeminiEndpoint is configured.
func (c *AgentPlatformGeminiConnector) Provenance() SourceProvenance {
	if c == nil || c.rt == nil {
		return ProvenanceFixture
	}
	cfg := c.rt.Config()
	if cfg.AgentPlatformLiveLLM || strings.TrimSpace(cfg.GeminiEndpoint) != "" {
		return ProvenanceLive
	}
	return ProvenanceFixture
}

// BuildOrchestratorAgent constructs the ADK Go v2 llmagent ("aegis_triage_orchestrator")
// with gemini-2.5-flash and the 8 governed AegisSRE functiontools.
func (c *AgentPlatformGeminiConnector) BuildOrchestratorAgent(ctx context.Context) (agent.Agent, error) {
	var rt *Runtime
	if c != nil {
		rt = c.rt
	}
	tools, _, err := buildUnifiedGovernedADKTools(rt)
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

func (c *AgentPlatformGeminiConnector) buildLLMModel(ctx context.Context) model.LLM {
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

	// Attempt to initialize standard adk/v2/model/gemini when using default Gemini Enterprise Agent Platform endpoint
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

	return &agentPlatformGeminiRESTModel{
		modelName:   "gemini-2.5-flash",
		endpoint:    endpoint,
		userProject: strings.TrimSpace(cfg.GCPProjectID),
		httpClient:  hc,
		sdkModel:    sdkModel,
		useDirect:   strings.TrimSpace(cfg.GeminiEndpoint) != "" || sdkModel == nil,
	}
}

type agentPlatformGeminiRESTModel struct {
	modelName   string
	endpoint    string
	userProject string
	httpClient  *http.Client
	sdkModel    model.LLM
	useDirect   bool
}

func (m *agentPlatformGeminiRESTModel) Name() string {
	return m.modelName
}

func (m *agentPlatformGeminiRESTModel) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	if !m.useDirect && m.sdkModel != nil {
		return m.sdkModel.GenerateContent(ctx, req, stream)
	}
	return func(yield func(*model.LLMResponse, error) bool) {
		payload := map[string]any{
			"contents": req.Contents,
		}
		if req.Config != nil {
			if req.Config.SystemInstruction != nil {
				payload["systemInstruction"] = req.Config.SystemInstruction
			}
			if len(req.Config.Tools) > 0 {
				var fnDecls []map[string]any
				for _, t := range req.Config.Tools {
					if t == nil {
						continue
					}
					for _, fd := range t.FunctionDeclarations {
						if fd == nil || strings.TrimSpace(fd.Name) == "" {
							continue
						}
						decl := map[string]any{
							"name":        fd.Name,
							"description": fd.Description,
						}
						if fd.Parameters != nil {
							decl["parameters"] = fd.Parameters
						} else if fd.ParametersJsonSchema != nil {
							decl["parameters"] = fd.ParametersJsonSchema
						}
						fnDecls = append(fnDecls, decl)
					}
				}
				if len(fnDecls) > 0 {
					payload["tools"] = []map[string]any{
						{"functionDeclarations": fnDecls},
					}
				}
			}
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
		if m.userProject != "" {
			httpReq.Header.Set("x-goog-user-project", m.userProject)
		}
		resp, err := m.httpClient.Do(httpReq)
		if err != nil {
			yield(nil, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			yield(nil, fmt.Errorf("agent platform gemini endpoint returned HTTP %d", resp.StatusCode))
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
			yield(nil, fmt.Errorf("agent platform gemini response contained no candidates"))
			return
		}
		content := parsed.Candidates[0].Content
		for i, p := range content.Parts {
			if p != nil && p.FunctionCall != nil && strings.TrimSpace(p.FunctionCall.Name) != "" {
				callID := p.FunctionCall.ID
				fcPart := genai.NewPartFromFunctionCall(p.FunctionCall.Name, p.FunctionCall.Args)
				if callID != "" && fcPart.FunctionCall != nil {
					fcPart.FunctionCall.ID = callID
				}
				content.Parts[i] = fcPart
			}
		}
		yield(&model.LLMResponse{
			Content:      content,
			FinishReason: parsed.Candidates[0].FinishReason,
			TurnComplete: true,
		}, nil)
	}
}

// SynthesizeTurn runs the ADK Go v2 llmagent over the sanitized turn input and prompt.
func (c *AgentPlatformGeminiConnector) SynthesizeTurn(ctx context.Context, req TurnRequest, sanitizedInput string) (string, error) {
	if c.Provenance() != ProvenanceLive {
		return "", fmt.Errorf("agent platform gemini connector not in LIVE mode")
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

