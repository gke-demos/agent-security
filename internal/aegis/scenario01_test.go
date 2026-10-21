package aegis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func TestScenario01_PromptScreenAndPIIRedactor_RedVsBlue(t *testing.T) {
	ctx := context.Background()
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})

	t.Run("BlueMode blocks indirect prompt injection in Gmail escalation with ThreatInterceptCard", func(t *testing.T) {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-blue-s1",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario01PromptInjectionAndPII,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Triage the latest customer P0 escalation email from Gmail and post a summary to Jira.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeBlocked {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeBlocked)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardThreatIntercept {
			t.Fatalf("Cards = %+v, want first card %q", res.Cards, aegis.CardThreatIntercept)
		}
		if strings.Contains(res.AssistantText, "123-45-6789") || strings.Contains(res.AssistantText, "AIzaSyD-CustomerLeakedKey999") {
			t.Errorf("BlueMode AssistantText leaked raw customer PII/secret: %q", res.AssistantText)
		}
		foundBlock := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Verdict == aegis.VerdictBlocked {
				foundBlock = true
			}
		}
		if !foundBlock {
			t.Errorf("BoundaryTrace = %+v, expected BoundaryReasoningGuard VerdictBlocked", res.BoundaryTrace)
		}
	})

	t.Run("BlueMode SDP-only match performs in-flight PII redaction and continues execution (IsSdpOnlyBlock)", func(t *testing.T) {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "sess-blue-sdp-only",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario01PromptInjectionAndPII,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Triage the clean customer PII escalation email (SDP-only, no injection) and draft the Jira update.",
			CleanPIIOnly: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardIncidentSummary {
			t.Fatalf("Cards = %+v, want %q", res.Cards, aegis.CardIncidentSummary)
		}
		if strings.Contains(res.SanitizedInputPreview, "123-45-6789") || strings.Contains(res.SanitizedInputPreview, "AIzaSyD-CustomerLeakedKey999") {
			t.Errorf("SanitizedInputPreview leaked raw SSN or API key: %q", res.SanitizedInputPreview)
		}
		if !strings.Contains(res.SanitizedInputPreview, "[REDACTED_SSN]") || !strings.Contains(res.SanitizedInputPreview, "[REDACTED_API_KEY]") {
			t.Errorf("SanitizedInputPreview missing redaction tokens: %q", res.SanitizedInputPreview)
		}
		foundRedacted := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryReasoningGuard && ev.Verdict == aegis.VerdictRedacted {
				foundRedacted = true
			}
		}
		if !foundRedacted {
			t.Errorf("BoundaryTrace = %+v, expected BoundaryReasoningGuard VerdictRedacted", res.BoundaryTrace)
		}
	})

	t.Run("RedMode allows indirect prompt injection and leaks raw PII over HTTP API", func(t *testing.T) {
		srv := httptest.NewServer(aegis.NewHandler(rt))
		defer srv.Close()

		reqBody, _ := json.Marshal(aegis.TurnRequest{
			SessionID:  "sess-red-s1",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario01PromptInjectionAndPII,
			Posture:    aegis.AllRedPosture(),
			Prompt:     "Triage the latest customer P0 escalation email from Gmail and post a summary to Jira.",
		})
		resp, err := http.Post(srv.URL+"/api/sessions/sess-red-s1/turns", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /api/sessions/sess-red-s1/turns error = %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}
		var got aegis.TurnResult
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if got.Outcome != aegis.OutcomeExploitedRed {
			t.Fatalf("Outcome = %q, want %q", got.Outcome, aegis.OutcomeExploitedRed)
		}
		if !strings.Contains(got.SanitizedInputPreview, "123-45-6789") {
			t.Errorf("RedMode expected raw SSN leak in unredacted input preview, got %q", got.SanitizedInputPreview)
		}
	})

	t.Run("Cold 3LO Gmail lookup returns OutcomeConsentRequired with ConsentChallengeCard for ProviderGoogleGmail and CompleteOAuthConsent unblocks turn", func(t *testing.T) {
		var iface aegis.AegisRuntime = rt

		coldRes, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:             "sess-cold-gmail-s1",
			Persona:               aegis.PersonaAlice,
			ScenarioID:            aegis.Scenario01PromptInjectionAndPII,
			Posture:               aegis.AllBluePosture(),
			Prompt:                "Triage the clean customer escalation email from Gmail.",
			CleanPIIOnly:          true,
			RequireCold3LOConsent: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(RequireCold3LOConsent) error = %v", err)
		}
		if coldRes.Outcome != aegis.OutcomeConsentRequired {
			t.Fatalf("Outcome = %q, want %q", coldRes.Outcome, aegis.OutcomeConsentRequired)
		}
		if coldRes.ConsentChallenge == nil || coldRes.ConsentChallenge.Provider != aegis.ProviderGoogleGmail {
			t.Fatalf("ConsentChallenge = %+v, want ProviderGoogleGmail", coldRes.ConsentChallenge)
		}
		if len(coldRes.Cards) == 0 || coldRes.Cards[0].Type != aegis.CardConsentChallenge {
			t.Fatalf("Cards = %+v, want first card %q", coldRes.Cards, aegis.CardConsentChallenge)
		}

		// Revoke Gmail grant, verify it still challenges, then complete consent via AegisRuntime.CompleteOAuthConsent
		rt.TokenBroker().Revoke(ctx, "sess-cold-gmail-s1", aegis.PersonaAlice, aegis.ProviderGoogleGmail, nil)
		revokedRes, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:    "sess-cold-gmail-s1",
			Persona:      aegis.PersonaAlice,
			ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
			Posture:      aegis.AllBluePosture(),
			Prompt:       "Triage the clean customer escalation email from Gmail.",
			CleanPIIOnly: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(after revoke) error = %v", err)
		}
		if revokedRes.Outcome != aegis.OutcomeConsentRequired {
			t.Fatalf("Outcome after revoke = %q, want %q", revokedRes.Outcome, aegis.OutcomeConsentRequired)
		}

		consentRes, err := iface.CompleteOAuthConsent(ctx, aegis.OAuthCallback{
			SessionID: "sess-cold-gmail-s1",
			Persona:   aegis.PersonaAlice,
			Provider:  aegis.ProviderGoogleGmail,
			Scopes:    []string{"https://www.googleapis.com/auth/gmail.readonly"},
			Nonce:     revokedRes.ConsentChallenge.Nonce,
		})
		if err != nil {
			t.Fatalf("CompleteOAuthConsent() error = %v", err)
		}
		if !consentRes.Granted || consentRes.Provider != aegis.ProviderGoogleGmail {
			t.Fatalf("ConsentResult = %+v, want Granted=true for google_gmail", consentRes)
		}

		snap, err := iface.GetSessionState(ctx, "sess-cold-gmail-s1")
		if err != nil || snap.SessionID != "sess-cold-gmail-s1" {
			t.Fatalf("GetSessionState() = (%+v, %v), want session sess-cold-gmail-s1", snap, err)
		}

		warmRes, err := iface.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:    "sess-cold-gmail-s1",
			Persona:      aegis.PersonaAlice,
			ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
			Posture:      aegis.AllBluePosture(),
			Prompt:       "Triage the clean customer escalation email from Gmail.",
			CleanPIIOnly: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(after CompleteOAuthConsent) error = %v", err)
		}
		if warmRes.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome after CompleteOAuthConsent = %q, want %q", warmRes.Outcome, aegis.OutcomeDefendedSuccess)
		}
	})

	t.Run("ContentGuard queries live Cloud DLP endpoint (DLPEndpoint) via httptest.Server", func(t *testing.T) {
		dlpHits := 0
		dlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dlpHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"result": {
					"findings": [
						{"infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"}},
						{"infoType": {"name": "CUSTOM_FINANCE_TOKEN"}}
					]
				},
				"item": {
					"value": "Customer [REDACTED_DLP_TOKEN] reported 502 error."
				}
			}`))
		}))
		defer dlpSrv.Close()

		liveRT := aegis.NewRuntime(aegis.RuntimeConfig{
			DLPEndpoint: dlpSrv.URL,
			HTTPClient:  dlpSrv.Client(),
		})
		res := liveRT.Guard().InspectAndSanitize(ctx, "Customer FIN-999999 reported 502 error.", aegis.AllBluePosture())
		if dlpHits == 0 {
			t.Fatalf("expected ContentGuard to query DLPEndpoint, got 0 hits")
		}
		if !res.IsSDPOnlyBlock || !res.DeidentifiedInFlight {
			t.Errorf("InspectAndSanitize() = %+v, want IsSDPOnlyBlock=true and DeidentifiedInFlight=true", res)
		}
		if !strings.Contains(res.SanitizedText, "[REDACTED_DLP_TOKEN]") {
			t.Errorf("SanitizedText = %q, want [REDACTED_DLP_TOKEN] from live DLP response", res.SanitizedText)
		}
		foundCustomType := false
		for _, mt := range res.SDPMatchTypes {
			if mt == "CUSTOM_FINANCE_TOKEN" {
				foundCustomType = true
			}
		}
		if !foundCustomType {
			t.Errorf("SDPMatchTypes = %v, want CUSTOM_FINANCE_TOKEN from live DLP response", res.SDPMatchTypes)
		}
	})
}
