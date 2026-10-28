package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"google.golang.org/adk/v2/agentregistry"
	"google.golang.org/adk/v2/tool/toolconfirmation"
	"google.golang.org/genai"
)

func init() {
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

	mux.HandleFunc("POST /api/sessions/{sessionId}/confirmations/stream", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req ConfirmationResolution
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.SessionID = sessionID
		snap := rt.GetOrCreateSession(sessionID)
		if snap.PendingConfirmation == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("session %q has no pending StepUpConfirmation", sessionID)})
			return
		}
		if req.ConfirmationID != "" && snap.PendingConfirmation.ConfirmationID != req.ConfirmationID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("confirmation ID mismatch: got %q, want %q", req.ConfirmationID, snap.PendingConfirmation.ConfirmationID)})
			return
		}
		sink := initSSESink(w)
		if _, err := rt.ResolveConfirmationStream(r.Context(), req, sink); err != nil {
			writeSSEError(w, err)
		}
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
	cat, _, err := NewAgentRegistryConnector(r).DiscoverGovernedResources(ctx)
	return cat, err
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

// ResolveConfirmation completes a pending ADK Go v2 adk_request_confirmation Step-Up interrupt
// for the given session via the unified ADK runner.Runner, either executing the approved mutation
// (Confirmed: true) or aborting it (Confirmed: false).
func (r *Runtime) ResolveConfirmation(ctx context.Context, req ConfirmationResolution) (*TurnResult, error) {
	return r.ResolveConfirmationStream(ctx, req, nil)
}

// ResolveConfirmationStream completes a pending ADK Go v2 adk_request_confirmation Step-Up interrupt
// for the given session via the unified ADK runner.Runner, emitting real-time TurnStreamEvent frames
// to sink when non-nil.
func (r *Runtime) ResolveConfirmationStream(ctx context.Context, req ConfirmationResolution, sink TurnEventSink) (*TurnResult, error) {
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

	res, err := r.resolveConfirmationViaADKRunner(ctx, req, snap, pending, sink)
	if err != nil {
		return nil, err
	}
	return res, nil
}
