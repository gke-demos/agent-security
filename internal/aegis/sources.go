package aegis

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var defaultGitHubCLITokenResolver = resolveGitHubCLIToken

func init() {
	RegisterHTTPRoutes(registerSourcesHTTPRoutes)
}

// TODO(security): GET /api/sources/status is a stateless read-only JSON endpoint that sanitizes
// GCPProjectID and GKEClusterName from display strings before returning SourceStatus payloads;
// SQL parameterization, multipart file-upload scanning, and cookie-based CSRF tokens are N/A
// (zero SQL DB, zero file uploads, zero auth cookies).
func registerSourcesHTTPRoutes(mux *http.ServeMux, rt *Runtime) {
	mux.HandleFunc("GET /api/sources/status", func(w http.ResponseWriter, r *http.Request) {
		statuses, err := rt.GetSourcesStatus(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"sources": statuses,
		})
	})
}

// ConfigFromEnv populates a RuntimeConfig from environment variables,
// auto-defaulting regional Model Armor, Cloud SDP, and Agent Registry endpoints
// when GOOGLE_CLOUD_PROJECT is set, and auto-detecting `gh auth token` when LIVE_GITHUB=true.
func ConfigFromEnv() RuntimeConfig {
	return ConfigFromEnvWithLookup(os.Getenv, defaultGitHubCLITokenResolver)
}

// RuntimeConfigFromEnv is an alias for ConfigFromEnv.
func RuntimeConfigFromEnv() RuntimeConfig {
	return ConfigFromEnv()
}

// ConfigFromEnvWithLookup populates a RuntimeConfig using the provided environment lookup
// and GitHub CLI token resolver functions.
func ConfigFromEnvWithLookup(getenv func(string) string, ghTokenFn func() string) RuntimeConfig {
	if getenv == nil {
		getenv = os.Getenv
	}
	if ghTokenFn == nil {
		ghTokenFn = defaultGitHubCLITokenResolver
	}

	cfg := RuntimeConfig{
		ModelArmorEndpoint:         strings.TrimSpace(getenv("MODEL_ARMOR_ENDPOINT")),
		DLPEndpoint:                strings.TrimSpace(getenv("DLP_ENDPOINT")),
		AgentRegistryURL:           strings.TrimSpace(getenv("AGENT_REGISTRY_URL")),
		GCPProjectID:               strings.TrimSpace(getenv("GOOGLE_CLOUD_PROJECT")),
		GCPLocation:                strings.TrimSpace(getenv("GOOGLE_CLOUD_LOCATION")),
		GKEClusterName:             strings.TrimSpace(getenv("GKE_CLUSTER_NAME")),
		AgentPlatformLiveLLM:       parseBoolEnv(getenv("AGENT_PLATFORM_LIVE_LLM")),
		GeminiEndpoint:             strings.TrimSpace(getenv("GEMINI_ENDPOINT")),
		GitHubAPIURL:               strings.TrimSpace(getenv("GITHUB_API_URL")),
		GitHubTargetRepo:           strings.TrimSpace(getenv("GITHUB_TARGET_REPO")),
		GmailAPIURL:                strings.TrimSpace(getenv("GMAIL_API_URL")),
		JiraBaseURL:                strings.TrimSpace(getenv("JIRA_BASE_URL")),
		JiraRestrictedKey:          strings.TrimSpace(getenv("JIRA_RESTRICTED_KEY")),
		JiraPublicKey:              strings.TrimSpace(getenv("JIRA_PUBLIC_KEY")),
		SubstrateGatewayURL:        strings.TrimSpace(getenv("SUBSTRATE_GATEWAY_URL")),
		SubstrateTargetActor:       firstNonEmpty(strings.TrimSpace(getenv("SUBSTRATE_TARGET_ACTOR")), defaultSubstrateTargetActor),
		LiveSubstrate:              parseBoolEnv(getenv("LIVE_SUBSTRATE")),
		AliceGitHubToken:           strings.TrimSpace(getenv("ALICE_GITHUB_TOKEN")),
		BobGitHubToken:             strings.TrimSpace(getenv("BOB_GITHUB_TOKEN")),
		AliceGmailToken:            strings.TrimSpace(getenv("ALICE_GMAIL_TOKEN")),
		BobGmailToken:              strings.TrimSpace(getenv("BOB_GMAIL_TOKEN")),
		AliceJiraToken:             strings.TrimSpace(getenv("ALICE_JIRA_TOKEN")),
		BobJiraToken:               strings.TrimSpace(getenv("BOB_JIRA_TOKEN")),
		GitHubOAuthClientID:        strings.TrimSpace(getenv("GITHUB_OAUTH_CLIENT_ID")),
		GitHubOAuthClientSecret:    strings.TrimSpace(getenv("GITHUB_OAUTH_CLIENT_SECRET")),
		GoogleOAuthClientID:        strings.TrimSpace(getenv("GOOGLE_OAUTH_CLIENT_ID")),
		GoogleOAuthClientSecret:    strings.TrimSpace(getenv("GOOGLE_OAUTH_CLIENT_SECRET")),
		JiraOAuthClientID:          strings.TrimSpace(getenv("JIRA_OAUTH_CLIENT_ID")),
		JiraOAuthClientSecret:      strings.TrimSpace(getenv("JIRA_OAUTH_CLIENT_SECRET")),
		OAuthTokenEndpointOverride: strings.TrimSpace(getenv("OAUTH_TOKEN_ENDPOINT_OVERRIDE")),
	}

	if cfg.GCPProjectID != "" {
		if cfg.GCPLocation == "" {
			cfg.GCPLocation = "us-central1"
		}
		if cfg.ModelArmorEndpoint == "" {
			cfg.ModelArmorEndpoint = fmt.Sprintf(
				"https://modelarmor.%s.rep.googleapis.com/v1/projects/%s/locations/%s/templates/aegis-prompt-screen:sanitizeUserPrompt",
				cfg.GCPLocation,
				cfg.GCPProjectID,
				cfg.GCPLocation,
			)
		}
		if cfg.DLPEndpoint == "" {
			cfg.DLPEndpoint = fmt.Sprintf(
				"https://dlp.googleapis.com/v2/projects/%s/locations/global/content:deidentify",
				cfg.GCPProjectID,
			)
		}
		if cfg.AgentRegistryURL == "" {
			cfg.AgentRegistryURL = fmt.Sprintf(
				"https://agentregistry.googleapis.com/v1alpha/projects/%s/locations/global",
				cfg.GCPProjectID,
			)
		}
	}

	if parseBoolEnv(getenv("LIVE_GITHUB")) && cfg.AliceGitHubToken == "" && ghTokenFn != nil {
		if tok := strings.TrimSpace(ghTokenFn()); tok != "" {
			cfg.AliceGitHubToken = tok
		}
	}

	return cfg
}

func parseBoolEnv(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func resolveGitHubCLIToken() string {
	if flag.Lookup("test.v") != nil {
		if !parseBoolEnv(os.Getenv("AEGIS_LIVE_EVALS")) || strings.TrimSpace(os.Getenv("ALICE_GITHUB_TOKEN")) != "" {
			return ""
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func normalizeTurnResultProvenance(res *TurnResult) {
	if res == nil {
		return
	}
	for i := range res.BoundaryTrace {
		if res.BoundaryTrace[i].Provenance == "" {
			res.BoundaryTrace[i].Provenance = ProvenanceFixture
		}
	}
	for i := range res.WireRecords {
		if res.WireRecords[i].Provenance == "" {
			res.WireRecords[i].Provenance = ProvenanceFixture
		}
	}
}

// GetSourcesStatus returns the SourceProvenance ("LIVE" vs "FIXTURE") and endpoint metadata
// for all 8 External Sources in canonical order.
func (r *Runtime) GetSourcesStatus(_ context.Context) ([]SourceStatus, error) {
	cfg := r.Config()

	agentPlatformLive := NewAgentPlatformGeminiConnector(r).Provenance() == ProvenanceLive
	modelArmorLive := NewModelArmorSDPConnector(r).Provenance() == ProvenanceLive
	gcpObsLive := NewGCPObservabilityConnector(r).Provenance() == ProvenanceLive
	registryLive := NewAgentRegistryConnector(r).Provenance() == ProvenanceLive
	githubLive := isGitHubLive(r)
	gmailLive := isGmailLive(r)
	jiraLive := isJiraLive(r)
	substrateLive := NewSubstrateSandboxConnector(r).Provenance() == ProvenanceLive

	targetRepo := sanitizeStageSafeText(firstNonEmpty(cfg.GitHubTargetRepo, "gke-demos/aegis-checkout-target"), cfg)

	statuses := []SourceStatus{
		buildSourceStatus(
			SourceAgentPlatformGemini,
			"Gemini on Agent Platform (ADK v2)",
			BoundaryReasoningGuard,
			agentPlatformLive,
			formatStageSafeGeminiEndpoint(cfg),
			"in-memory://adk-v2-fixture-orchestrator",
			"Live ADK Go v2 llmagent reasoning on Gemini Enterprise Agent Platform (gemini-2.5-flash)",
			"Deterministic ADK v2 scenario state machine fallback",
		),
		buildSourceStatus(
			SourceModelArmorSDP,
			"Model Armor + Cloud SDP",
			BoundaryReasoningGuard,
			modelArmorLive,
			formatStageSafeModelArmorEndpoint(cfg),
			"in-memory://model-armor-sdp-policy-engine",
			"Live Model Armor prompt screening and Cloud SDP DeidentifyContent",
			"Deterministic local prompt injection & SDP de-identification engine",
		),
		buildSourceStatus(
			SourceGCPObservability,
			"Cloud Logging & GKE MCP",
			BoundaryPlatformGovernance,
			gcpObsLive,
			"https://logging.googleapis.com/mcp + https://container.googleapis.com/mcp",
			"in-memory://gcp-observability-mcp-fixture",
			"Live Cloud Logging & GKE cluster telemetry (Active GKE Context)",
			"Deterministic GKE & Cloud Logging MCP fixture",
		),
		buildSourceStatus(
			SourceAgentRegistry,
			"Google Cloud Agent Registry",
			BoundaryPlatformGovernance,
			registryLive,
			formatStageSafeAgentRegistryEndpoint(cfg),
			"in-memory://governed-registry-manifest",
			"Live adk/v2/agentregistry catalog discovery",
			"Governed local MCP server & A2A agent manifest fallback",
		),
		buildSourceStatus(
			SourceGitHub,
			"GitHub ("+targetRepo+")",
			BoundaryIdentity3LO,
			githubLive,
			firstNonEmpty(cfg.GitHubAPIURL, "https://api.github.com")+" ("+targetRepo+")",
			"in-memory://github-3lo-fixture",
			"Live GitHub 3LO issues, advisories, and Step-Up PR creation",
			"Deterministic GitHub 3LO advisory & PR fixture",
		),
		buildSourceStatus(
			SourceGoogleGmail,
			"Google Workspace Gmail",
			BoundaryIdentity3LO,
			gmailLive,
			firstNonEmpty(cfg.GmailAPIURL, "https://gmail.googleapis.com/gmail/v1"),
			"in-memory://gmail-escalation-fixture",
			"Live Gmail 3LO escalation message reader",
			"Deterministic P0 checkout escalation email fixture",
		),
		buildSourceStatus(
			SourceAtlassianJira,
			"Atlassian Jira Cloud",
			BoundaryIdentity3LO,
			jiraLive,
			firstNonEmpty(cfg.JiraBaseURL, "https://api.atlassian.com/ex/jira"),
			"in-memory://jira-sec101-pub202-fixture",
			"Live Jira Cloud 3LO issue correlation and comment updates",
			"Deterministic SEC-101 / PUB-202 per-persona ACL fixture",
		),
		buildSourceStatus(
			SourceSubstrateSandbox,
			"Agent Substrate v0.5.0 gVisor",
			BoundarySandboxEgress,
			substrateLive,
			firstNonEmpty(cfg.SubstrateGatewayURL, "kubectl://aegis-system/aegis-remediator-pool (gVisor)"),
			"in-memory://substrate-gvisor-atenet-fixture",
			"Live Agent Substrate v0.5.0 gVisor WorkerPool & atenet Egress MITM",
			"Deterministic gVisor Actor & atenet Egress MITM fixture",
		),
	}

	for i := range statuses {
		statuses[i] = sanitizeStageSafeSourceStatus(statuses[i], cfg)
	}
	return statuses, nil
}

var stageSafeProjectsSegmentRe = regexp.MustCompile(`/projects/[^/\s:)]+`)

func formatStageSafeGeminiEndpoint(cfg RuntimeConfig) string {
	raw := firstNonEmpty(cfg.GeminiEndpoint, "https://aiplatform.googleapis.com/v1 (gemini-2.5-flash)")
	if idx := strings.Index(raw, "/projects/"); idx >= 0 {
		base := firstNonEmpty(strings.TrimRight(raw[:idx], "/"), "https://aiplatform.googleapis.com/v1")
		return sanitizeStageSafeText(base+" (gemini-2.5-flash)", cfg)
	}
	return sanitizeStageSafeText(raw, cfg)
}

func formatStageSafeModelArmorEndpoint(cfg RuntimeConfig) string {
	if cfg.ModelArmorEndpoint != "" && strings.Contains(cfg.ModelArmorEndpoint, "/projects/") {
		idx := strings.Index(cfg.ModelArmorEndpoint, "/projects/")
		base := strings.TrimRight(cfg.ModelArmorEndpoint[:idx], "/")
		if base == "" {
			loc := firstNonEmpty(cfg.GCPLocation, "us-central1")
			base = fmt.Sprintf("https://modelarmor.%s.rep.googleapis.com/v1", loc)
		}
		tmpl := extractModelArmorTemplateName(cfg.ModelArmorEndpoint)
		return sanitizeStageSafeText(fmt.Sprintf("%s · Template %s", base, tmpl), cfg)
	}
	raw := firstNonEmpty(cfg.ModelArmorEndpoint, cfg.DLPEndpoint, "https://modelarmor.googleapis.com/v1")
	if idx := strings.Index(raw, "/projects/"); idx >= 0 {
		base := firstNonEmpty(strings.TrimRight(raw[:idx], "/"), "https://dlp.googleapis.com/v2")
		return sanitizeStageSafeText(base+" · Cloud SDP DeidentifyContent", cfg)
	}
	return sanitizeStageSafeText(raw, cfg)
}

func extractModelArmorTemplateName(endpoint string) string {
	const marker = "/templates/"
	idx := strings.Index(endpoint, marker)
	if idx < 0 {
		return "aegis-prompt-screen"
	}
	rest := endpoint[idx+len(marker):]
	if cut := strings.IndexAny(rest, ":/?"); cut >= 0 {
		rest = rest[:cut]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "aegis-prompt-screen"
	}
	return rest
}

func formatStageSafeAgentRegistryEndpoint(cfg RuntimeConfig) string {
	raw := firstNonEmpty(cfg.AgentRegistryURL, "https://agentregistry.googleapis.com/v1alpha")
	if idx := strings.Index(raw, "/projects/"); idx >= 0 {
		base := firstNonEmpty(strings.TrimRight(raw[:idx], "/"), "https://agentregistry.googleapis.com/v1alpha")
		return sanitizeStageSafeText(base+" · Global Catalog", cfg)
	}
	return sanitizeStageSafeText(raw, cfg)
}

func sanitizeStageSafeSourceStatus(st SourceStatus, cfg RuntimeConfig) SourceStatus {
	st.Name = sanitizeStageSafeText(st.Name, cfg)
	st.Endpoint = sanitizeStageSafeText(st.Endpoint, cfg)
	st.Detail = sanitizeStageSafeText(st.Detail, cfg)
	return st
}

func sanitizeStageSafeText(text string, cfg RuntimeConfig) string {
	if text == "" {
		return text
	}
	out := stageSafeProjectsSegmentRe.ReplaceAllString(text, "/projects/active-gcp-project")
	if proj := strings.TrimSpace(cfg.GCPProjectID); proj != "" {
		out = replaceCaseInsensitiveLiteral(out, proj, "active-gcp-project")
	}
	if cluster := strings.TrimSpace(cfg.GKEClusterName); cluster != "" {
		out = replaceCaseInsensitiveLiteral(out, cluster, "active-gke-context")
	}
	return out
}

func replaceCaseInsensitiveLiteral(haystack, needle, replacement string) string {
	if needle == "" {
		return haystack
	}
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(needle))
	return re.ReplaceAllString(haystack, replacement)
}

func buildSourceStatus(
	id ExternalSourceID,
	name string,
	boundary BoundaryID,
	live bool,
	liveEndpoint string,
	fixtureEndpoint string,
	liveDetail string,
	fixtureDetail string,
) SourceStatus {
	if live {
		return SourceStatus{
			ID:         id,
			Name:       name,
			Boundary:   boundary,
			Provenance: ProvenanceLive,
			Endpoint:   liveEndpoint,
			Detail:     liveDetail,
		}
	}
	return SourceStatus{
		ID:         id,
		Name:       name,
		Boundary:   boundary,
		Provenance: ProvenanceFixture,
		Endpoint:   fixtureEndpoint,
		Detail:     fixtureDetail,
	}
}
