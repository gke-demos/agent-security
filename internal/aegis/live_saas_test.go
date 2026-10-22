package aegis_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func TestLiveGmailConnector_Scenario01And05(t *testing.T) {
	ctx := context.Background()

	var (
		mu          sync.Mutex
		requestPath []string
		authHeaders []string
		emailBody   string
	)

	gmailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestPath = append(requestPath, r.URL.Path)
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		bodyText := emailBody
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/users/me/messages":
			_, _ = w.Write([]byte(`{"messages":[{"id":"msg-live-777","threadId":"thr-777"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/users/me/messages/msg-live-777":
			encoded := base64.RawURLEncoding.EncodeToString([]byte(bodyText))
			resp := map[string]any{
				"id":      "msg-live-777",
				"snippet": bodyText,
				"payload": map[string]any{
					"headers": []map[string]string{
						{"name": "From", "value": "vip-live@acme.example.com"},
						{"name": "Subject", "value": "[P0] Live Gmail Checkout 502 Escalation"},
					},
					"body": map[string]string{
						"data": encoded,
					},
				},
			}
			raw, _ := json.Marshal(resp)
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gmailSrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		GmailAPIURL:     gmailSrv.URL,
		AliceGmailToken: "gmail_tok_live_alice_3lo",
		HTTPClient:      gmailSrv.Client(),
	})

	t.Run("SCENARIO-01 fetches live Gmail message via auth.Transport, screens via ContentGuard, and records LIVE provenance", func(t *testing.T) {
		mu.Lock()
		requestPath = nil
		authHeaders = nil
		emailBody = "Customer SSN: 123-45-6789, API Key: AIzaSyD-CustomerLeakedKey999. Please triage live checkout 502 error in us-central1."
		mu.Unlock()

		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:    "live-gmail-s1-clean",
			Persona:      aegis.PersonaAlice,
			ScenarioID:   aegis.Scenario01PromptInjectionAndPII,
			Posture:      aegis.AllBluePosture(),
			Prompt:       "Triage the latest customer escalation email from live Gmail.",
			CleanPIIOnly: true,
		})
		if err != nil {
			t.Fatalf("ExecuteTurn() error = %v", err)
		}
		if res.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
		}

		mu.Lock()
		paths := append([]string(nil), requestPath...)
		hdrs := append([]string(nil), authHeaders...)
		mu.Unlock()

		if len(paths) < 2 || paths[0] != "/users/me/messages" || paths[1] != "/users/me/messages/msg-live-777" {
			t.Fatalf("Gmail request paths = %v, want [/users/me/messages /users/me/messages/msg-live-777]", paths)
		}
		for i, h := range hdrs {
			if h != "Bearer gmail_tok_live_alice_3lo" {
				t.Errorf("Gmail request[%d] Authorization = %q, want %q", i, h, "Bearer gmail_tok_live_alice_3lo")
			}
		}

		if strings.Contains(res.SanitizedInputPreview, "123-45-6789") || !strings.Contains(res.SanitizedInputPreview, "[REDACTED_SSN]") {
			t.Errorf("SanitizedInputPreview = %q, expected in-flight SDP redaction on live Gmail body", res.SanitizedInputPreview)
		}

		foundLiveGmailTrace := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryIdentity3LO && ev.Provenance == aegis.ProvenanceLive {
				foundLiveGmailTrace = true
			}
		}
		if !foundLiveGmailTrace {
			t.Errorf("BoundaryTrace = %+v, expected BoundaryIdentity3LO with ProvenanceLive", res.BoundaryTrace)
		}

		foundLiveGmailWire := false
		for _, wr := range res.WireRecords {
			if wr.Provider == aegis.ProviderGoogleGmail && wr.Provenance == aegis.ProvenanceLive && wr.AuthHeaderPresent {
				foundLiveGmailWire = true
			}
		}
		if !foundLiveGmailWire {
			t.Errorf("WireRecords = %+v, expected ProviderGoogleGmail with ProvenanceLive", res.WireRecords)
		}
	})

	t.Run("SCENARIO-05 records LIVE provenance for Gmail 3LO fetch", func(t *testing.T) {
		mu.Lock()
		requestPath = nil
		authHeaders = nil
		emailBody = "Customer SSN: 123-45-6789, Phone: (415) 555-0199. Live full-chain escalation."
		mu.Unlock()

		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-gmail-s5",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario05FullChainZeroTrust,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Run full-chain triage with live Gmail.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(SCENARIO-05) error = %v", err)
		}

		foundLiveGmailWire := false
		for _, wr := range res.WireRecords {
			if wr.Provider == aegis.ProviderGoogleGmail && wr.Provenance == aegis.ProvenanceLive {
				foundLiveGmailWire = true
			}
		}
		if !foundLiveGmailWire {
			t.Errorf("SCENARIO-05 WireRecords = %+v, expected ProviderGoogleGmail with ProvenanceLive", res.WireRecords)
		}

		foundLiveGmailTrace := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryIdentity3LO && ev.Provenance == aegis.ProvenanceLive {
				foundLiveGmailTrace = true
			}
		}
		if !foundLiveGmailTrace {
			t.Errorf("SCENARIO-05 BoundaryTrace = %+v, expected BoundaryIdentity3LO with ProvenanceLive", res.BoundaryTrace)
		}
	})
}

func TestLiveGitHubConnector_Scenario02AndStepUpPR(t *testing.T) {
	ctx := context.Background()

	var (
		mu          sync.Mutex
		ghRequests  []string
		prPostCount int
	)

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		mu.Lock()
		ghRequests = append(ghRequests, r.Method+" "+r.URL.Path)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		// Enforce Persona ACLs on live GitHub: Alice token allowed, Bob token denied with 404 Not Found on private issues or 403 Forbidden
		if strings.Contains(authHeader, "gho_bob_restricted") {
			if strings.HasPrefix(r.URL.Path, "/repos/gke-demos/aegis-checkout-target/issues/") {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by contractor token"}`))
			return
		}
		if !strings.Contains(authHeader, "gho_alice_privileged") && !strings.Contains(authHeader, "shared-service-account-root-token") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/issues/1":
			_, _ = w.Write([]byte(`{
				"number": 1,
				"title": "SEC-101: OAuth Token Cache Leak in checkout-service",
				"state": "open",
				"html_url": "https://github.com/gke-demos/aegis-checkout-target/issues/1"
			}`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/git/ref/heads/main":
			_, _ = w.Write([]byte(`{"ref":"refs/heads/main","object":{"sha":"abc123def456"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/git/refs":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/fix/aegis-checkout-502"}`))
		case r.Method == http.MethodPut && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/contents/checkout.go":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"content":{"path":"checkout.go"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/contents/checkout.go":
			_, _ = w.Write([]byte(`{
				"name": "checkout.go",
				"path": "checkout.go",
				"sha": "sha999checkout",
				"encoding": "base64",
				"content": "cGFja2FnZSBjaGVja291dAo="
			}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/pulls":
			mu.Lock()
			prPostCount++
			count := prPostCount
			mu.Unlock()
			if count == 1 {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{
					"number": 88,
					"html_url": "https://github.com/gke-demos/aegis-checkout-target/pull/88",
					"state": "open"
				}`))
				return
			}
			// Simulate PR already exists on second call to verify open PR query fallback
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"Validation Failed","errors":[{"message":"A pull request already exists for gke-demos:untrusted/pr-fix-token-cache."}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/repos/gke-demos/aegis-checkout-target/pulls":
			_, _ = w.Write([]byte(`[
				{
					"number": 88,
					"html_url": "https://github.com/gke-demos/aegis-checkout-target/pull/88",
					"state": "open"
				}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghSrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		GitHubAPIURL:     ghSrv.URL,
		GitHubTargetRepo: "gke-demos/aegis-checkout-target",
		AliceGitHubToken: "gho_alice_privileged",
		BobGitHubToken:   "gho_bob_restricted",
		HTTPClient:       ghSrv.Client(),
	})

	t.Run("SCENARIO-02 Alice fetches live GitHub issue #1 and checkout.go with LIVE provenance", func(t *testing.T) {
		mu.Lock()
		ghRequests = nil
		mu.Unlock()

		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-gh-s2-alice",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Correlate SEC-101 with target repository issue #1 and checkout.go.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(Alice) error = %v", err)
		}
		if res.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeDefendedSuccess)
		}

		var sawIssue1, sawContents bool
		for _, wr := range res.WireRecords {
			if wr.Provider == aegis.ProviderGitHub && wr.Provenance == aegis.ProvenanceLive {
				if strings.HasSuffix(wr.URL, "/repos/gke-demos/aegis-checkout-target/issues/1") && wr.StatusCode == http.StatusOK {
					sawIssue1 = true
				}
				if strings.HasSuffix(wr.URL, "/repos/gke-demos/aegis-checkout-target/contents/checkout.go") && wr.StatusCode == http.StatusOK {
					sawContents = true
				}
			}
		}
		if !sawIssue1 || !sawContents {
			t.Errorf("WireRecords = %+v, want LIVE GET /issues/1 and /contents/checkout.go", res.WireRecords)
		}

		foundLiveB3 := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryIdentity3LO && ev.Provenance == aegis.ProvenanceLive && ev.Verdict == aegis.VerdictAllowed {
				foundLiveB3 = true
			}
		}
		if !foundLiveB3 {
			t.Errorf("BoundaryTrace = %+v, want BoundaryIdentity3LO VerdictAllowed with ProvenanceLive", res.BoundaryTrace)
		}
	})

	t.Run("SCENARIO-02 Bob receives 403 from live GitHub and returns CardAclDenial with LIVE provenance", func(t *testing.T) {
		res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-gh-s2-bob",
			Persona:    aegis.PersonaBob,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Attempt to read restricted GitHub issue as contractor Bob.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(Bob) error = %v", err)
		}
		if res.Outcome != aegis.OutcomeBlocked {
			t.Fatalf("Outcome = %q, want %q", res.Outcome, aegis.OutcomeBlocked)
		}
		if len(res.Cards) == 0 || res.Cards[0].Type != aegis.CardAclDenial {
			t.Fatalf("Cards = %+v, want CardAclDenial", res.Cards)
		}

		foundLiveDeniedB3 := false
		for _, ev := range res.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryIdentity3LO && ev.Verdict == aegis.VerdictBlocked && ev.Provenance == aegis.ProvenanceLive {
				foundLiveDeniedB3 = true
			}
		}
		if !foundLiveDeniedB3 {
			t.Errorf("BoundaryTrace = %+v, want BoundaryIdentity3LO VerdictBlocked with ProvenanceLive", res.BoundaryTrace)
		}
	})

	t.Run("ResolveConfirmation opens live GitHub PR via auth.Transport and populates Pull Request URL with LIVE provenance", func(t *testing.T) {
		s3Res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-gh-s3-pr",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario03AgentGatewayAndStepUp,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Create remediation PR on gke-demos/aegis-checkout-target.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(SCENARIO-03) error = %v", err)
		}
		if s3Res.StepUpConfirmation == nil {
			t.Fatalf("expected pending StepUpConfirmation")
		}

		approved, err := rt.ResolveConfirmation(ctx, aegis.ConfirmationResolution{
			SessionID:      "live-gh-s3-pr",
			ConfirmationID: s3Res.StepUpConfirmation.ConfirmationID,
			Confirmed:      true,
		})
		if err != nil {
			t.Fatalf("ResolveConfirmation(true) error = %v", err)
		}
		if approved.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Outcome = %q, want %q", approved.Outcome, aegis.OutcomeDefendedSuccess)
		}
		if len(approved.Cards) == 0 || approved.Cards[0].Type != aegis.CardIncidentSummary {
			t.Fatalf("Cards = %+v, want CardIncidentSummary", approved.Cards)
		}
		gotPRURL := approved.Cards[0].Fields["Pull Request URL"]
		wantPRURL := "https://github.com/gke-demos/aegis-checkout-target/pull/88"
		if gotPRURL != wantPRURL {
			t.Errorf("IncidentSummaryCard.Fields[\"Pull Request URL\"] = %q, want %q", gotPRURL, wantPRURL)
		}

		foundLivePRWire := false
		for _, wr := range approved.WireRecords {
			if wr.Provider == aegis.ProviderGitHub && wr.Method == http.MethodPost &&
				strings.HasSuffix(wr.URL, "/repos/gke-demos/aegis-checkout-target/pulls") &&
				wr.Provenance == aegis.ProvenanceLive {
				foundLivePRWire = true
			}
		}
		if !foundLivePRWire {
			t.Errorf("WireRecords = %+v, want LIVE POST /repos/gke-demos/aegis-checkout-target/pulls", approved.WireRecords)
		}

		foundLiveB1 := false
		for _, ev := range approved.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryGenerativeUI && ev.Verdict == aegis.VerdictAllowed && ev.Provenance == aegis.ProvenanceLive {
				foundLiveB1 = true
			}
		}
		if !foundLiveB1 {
			t.Errorf("BoundaryTrace = %+v, want BoundaryGenerativeUI VerdictAllowed with ProvenanceLive", approved.BoundaryTrace)
		}

		// Second approval tests existing open PR fallback (422 -> GET /pulls?head=...&state=open)
		s5Res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-gh-s5-pr-existing",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario05FullChainZeroTrust,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Run full-chain and approve PR when PR already exists.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(SCENARIO-05) error = %v", err)
		}
		approvedExisting, err := rt.ResolveConfirmation(ctx, aegis.ConfirmationResolution{
			SessionID:      "live-gh-s5-pr-existing",
			ConfirmationID: s5Res.StepUpConfirmation.ConfirmationID,
			Confirmed:      true,
		})
		if err != nil {
			t.Fatalf("ResolveConfirmation(existing PR) error = %v", err)
		}
		if approvedExisting.Cards[0].Fields["Pull Request URL"] != wantPRURL {
			t.Errorf("existing PR fallback URL = %q, want %q", approvedExisting.Cards[0].Fields["Pull Request URL"], wantPRURL)
		}
	})
}

func TestLiveJiraConnector_Scenario02AndStepUpComment(t *testing.T) {
	ctx := context.Background()

	var (
		mu              sync.Mutex
		jiraCommentBody string
	)

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(authHeader, "jira_bob_restricted") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist or you do not have permission to see it."]}`))
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/api/3/issue/SEC-101":
			_, _ = w.Write([]byte(`{
				"id": "10001",
				"key": "SEC-101",
				"fields": {
					"summary": "Restricted SecOps OAuth Token Investigation"
				}
			}`))
		case r.Method == http.MethodPost && r.URL.Path == "/rest/api/3/issue/SEC-101/comment":
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			jiraCommentBody = string(raw)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"20001"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer jiraSrv.Close()

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		JiraBaseURL:       jiraSrv.URL,
		JiraRestrictedKey: "SEC-101",
		AliceJiraToken:    "jira_alice_privileged",
		BobJiraToken:      "jira_bob_restricted",
		HTTPClient:        jiraSrv.Client(),
	})

	t.Run("SCENARIO-02 calls live Jira GET /rest/api/3/issue/SEC-101 for Alice and blocks Bob with 403 and LIVE provenance", func(t *testing.T) {
		aliceRes, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-jira-s2-alice",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Fetch SEC-101 from live Jira Cloud.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(Alice) error = %v", err)
		}
		if aliceRes.Outcome != aegis.OutcomeDefendedSuccess {
			t.Fatalf("Alice Outcome = %q, want %q", aliceRes.Outcome, aegis.OutcomeDefendedSuccess)
		}

		foundLiveJiraWire := false
		for _, wr := range aliceRes.WireRecords {
			if wr.Provider == aegis.ProviderAtlassianJira &&
				strings.HasSuffix(wr.URL, "/rest/api/3/issue/SEC-101") &&
				wr.Provenance == aegis.ProvenanceLive &&
				wr.StatusCode == http.StatusOK {
				foundLiveJiraWire = true
			}
		}
		if !foundLiveJiraWire {
			t.Errorf("Alice WireRecords = %+v, want LIVE GET /rest/api/3/issue/SEC-101", aliceRes.WireRecords)
		}

		bobRes, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-jira-s2-bob",
			Persona:    aegis.PersonaBob,
			ScenarioID: aegis.Scenario02ConfusedDeputy3LO,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Fetch SEC-101 from live Jira Cloud as contractor Bob.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(Bob) error = %v", err)
		}
		if bobRes.Outcome != aegis.OutcomeBlocked {
			t.Fatalf("Bob Outcome = %q, want %q", bobRes.Outcome, aegis.OutcomeBlocked)
		}
		if len(bobRes.Cards) == 0 || bobRes.Cards[0].Type != aegis.CardAclDenial {
			t.Fatalf("Bob Cards = %+v, want CardAclDenial", bobRes.Cards)
		}
		if len(bobRes.BoundaryTrace) == 0 || bobRes.BoundaryTrace[0].Provenance != aegis.ProvenanceLive {
			t.Errorf("Bob BoundaryTrace = %+v, want ProvenanceLive", bobRes.BoundaryTrace)
		}
	})

	t.Run("ResolveConfirmation posts sanitized comment to live Jira POST /rest/api/3/issue/SEC-101/comment with LIVE provenance", func(t *testing.T) {
		s3Res, err := rt.ExecuteTurn(ctx, aegis.TurnRequest{
			SessionID:  "live-jira-s3-approve",
			Persona:    aegis.PersonaAlice,
			ScenarioID: aegis.Scenario03AgentGatewayAndStepUp,
			Posture:    aegis.AllBluePosture(),
			Prompt:     "Propose checkout PR and Jira SEC-101 comment.",
		})
		if err != nil {
			t.Fatalf("ExecuteTurn(SCENARIO-03) error = %v", err)
		}

		approved, err := rt.ResolveConfirmation(ctx, aegis.ConfirmationResolution{
			SessionID:      "live-jira-s3-approve",
			ConfirmationID: s3Res.StepUpConfirmation.ConfirmationID,
			Confirmed:      true,
		})
		if err != nil {
			t.Fatalf("ResolveConfirmation(true) error = %v", err)
		}

		mu.Lock()
		gotComment := jiraCommentBody
		mu.Unlock()
		if gotComment == "" {
			t.Fatalf("expected POST /rest/api/3/issue/SEC-101/comment to be called with non-empty body")
		}

		foundLiveJiraCommentWire := false
		for _, wr := range approved.WireRecords {
			if wr.Provider == aegis.ProviderAtlassianJira &&
				wr.Method == http.MethodPost &&
				strings.HasSuffix(wr.URL, "/rest/api/3/issue/SEC-101/comment") &&
				wr.Provenance == aegis.ProvenanceLive {
				foundLiveJiraCommentWire = true
			}
		}
		if !foundLiveJiraCommentWire {
			t.Errorf("WireRecords = %+v, want LIVE POST /rest/api/3/issue/SEC-101/comment", approved.WireRecords)
		}

		foundLiveB1 := false
		for _, ev := range approved.BoundaryTrace {
			if ev.Boundary == aegis.BoundaryGenerativeUI && ev.Provenance == aegis.ProvenanceLive {
				foundLiveB1 = true
			}
		}
		if !foundLiveB1 {
			t.Errorf("BoundaryTrace = %+v, want BoundaryGenerativeUI with ProvenanceLive", approved.BoundaryTrace)
		}
	})
}
