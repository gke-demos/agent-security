package aegis

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func containsEmoji(s string) (rune, bool) {
	for _, r := range s {
		switch {
		case r >= 0x1F300 && r <= 0x1FAFF:
			return r, true
		case r >= 0x2600 && r <= 0x27BF:
			return r, true
		case r >= 0xFE00 && r <= 0xFE0F:
			return r, true
		}
	}
	return 0, false
}

func TestPortal_RootHTMLAndStaticAssets(t *testing.T) {
	rt := NewRuntime(RuntimeConfig{})
	srv := httptest.NewServer(NewHandler(rt))
	defer srv.Close()

	// 1. GET / returns 200 OK HTML with all required arena controls and zero emojis
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html", ct)
	}
	htmlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTML body: %v", err)
	}
	html := string(htmlBytes)

	if r, found := containsEmoji(html); found {
		t.Errorf("GET / HTML contains forbidden emoji rune U+%04X", r)
	}

	requiredHTMLSnippets := []string{
		"AegisSRE",
		"Red-vs-Blue Arena",
		"Prompt Screen",
		"PII Redactor",
		"Token Broker",
		"Step-Up Confirmation",
		"Sandbox Egress MITM",
		"All Blue (Defended)",
		"All Red (Vulnerable)",
		"Alice (SecOps Lead)",
		"Bob (External Contractor)",
		"SCENARIO-01",
		"SCENARIO-02",
		"SCENARIO-03",
		"SCENARIO-04",
		"SCENARIO-05",
		"Seed / Reset Fixtures",
		"Boundary Trace Waterfall",
		`id="btn-theme-toggle"`,
		"<svg",
	}
	for _, snippet := range requiredHTMLSnippets {
		if !strings.Contains(html, snippet) {
			t.Errorf("GET / HTML missing required snippet %q", snippet)
		}
	}

	// 2. GET /static/styles.css returns 200 OK text/css with pure color token overrides for [data-theme="light"]
	cssResp, err := http.Get(srv.URL + "/static/styles.css")
	if err != nil {
		t.Fatalf("GET /static/styles.css: %v", err)
	}
	defer cssResp.Body.Close()

	if cssResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /static/styles.css status = %d, want 200", cssResp.StatusCode)
	}
	if ct := cssResp.Header.Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("GET /static/styles.css Content-Type = %q, want text/css", ct)
	}
	cssBytes, err := io.ReadAll(cssResp.Body)
	if err != nil {
		t.Fatalf("read CSS: %v", err)
	}
	css := string(cssBytes)

	if r, found := containsEmoji(css); found {
		t.Errorf("styles.css contains forbidden emoji rune U+%04X", r)
	}
	if !strings.Contains(css, ":root") || !strings.Contains(css, `[data-theme="light"]`) {
		t.Errorf("styles.css must define :root and [data-theme=\"light\"] color tokens")
	}

	// Verify [data-theme="light"] block has zero layout-shifting rules (only --* variables and color-scheme)
	lightBlockRe := regexp.MustCompile(`(?s)\[data-theme="light"\]\s*\{([^}]+)\}`)
	matches := lightBlockRe.FindStringSubmatch(css)
	if len(matches) < 2 {
		t.Fatalf("could not extract [data-theme=\"light\"] block from styles.css")
	}
	for _, rawLine := range strings.Split(matches[1], "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			continue
		}
		if !strings.HasPrefix(line, "--") && !strings.HasPrefix(line, "color-scheme:") {
			t.Errorf("[data-theme=\"light\"] contains non-token rule %q (must be pure color token override with zero layout shift)", line)
		}
	}

	// 3. GET /static/app.js returns 200 OK JavaScript with all 6 A2UI card renderers and interactive handlers
	jsResp, err := http.Get(srv.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js: %v", err)
	}
	defer jsResp.Body.Close()

	if jsResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /static/app.js status = %d, want 200", jsResp.StatusCode)
	}
	if ct := jsResp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("GET /static/app.js Content-Type = %q, want javascript", ct)
	}
	jsBytes, err := io.ReadAll(jsResp.Body)
	if err != nil {
		t.Fatalf("read JS: %v", err)
	}
	js := string(jsBytes)

	if r, found := containsEmoji(js); found {
		t.Errorf("app.js contains forbidden emoji rune U+%04X", r)
	}

	requiredJSSnippets := []string{
		"IncidentSummaryCard",
		"ConsentChallengeCard",
		"StepUpConfirmationCard",
		"ThreatInterceptCard",
		"AclDenialCard",
		"SandboxExecutionCard",
		"/oauth/grant",
		"/oauth/revoke",
		"/confirmations",
		"/api/fixtures/seed",
		"/api/scenarios",
		"data-theme",
	}
	for _, snippet := range requiredJSSnippets {
		if !strings.Contains(js, snippet) {
			t.Errorf("app.js missing required snippet %q", snippet)
		}
	}
}

func TestPortal_SeedFixturesEndpoint(t *testing.T) {
	rt := NewRuntime(RuntimeConfig{})
	srv := httptest.NewServer(NewHandler(rt))
	defer srv.Close()

	// Dirty the session state first: revoke Alice's Jira 3LO grant and trigger a pending Step-Up confirmation
	revokeBody, _ := json.Marshal(map[string]any{
		"persona":  "alice",
		"provider": "atlassian_jira",
	})
	revResp, err := http.Post(srv.URL+"/api/sessions/stage-session/oauth/revoke", "application/json", bytes.NewReader(revokeBody))
	if err != nil {
		t.Fatalf("revoke 3LO: %v", err)
	}
	revResp.Body.Close()

	turnBody, _ := json.Marshal(TurnRequest{
		Persona:    PersonaAlice,
		ScenarioID: Scenario03AgentGatewayAndStepUp,
		Posture:    AllBluePosture(),
		Prompt:     "Run SCENARIO-03",
	})
	turnResp, err := http.Post(srv.URL+"/api/sessions/stage-session/turns", "application/json", bytes.NewReader(turnBody))
	if err != nil {
		t.Fatalf("execute turn: %v", err)
	}
	turnResp.Body.Close()

	// Now call POST /api/fixtures/seed to reset and re-seed fixtures
	seedReqBody, _ := json.Marshal(map[string]string{
		"sessionId": "stage-session",
	})
	seedResp, err := http.Post(srv.URL+"/api/fixtures/seed", "application/json", bytes.NewReader(seedReqBody))
	if err != nil {
		t.Fatalf("POST /api/fixtures/seed: %v", err)
	}
	defer seedResp.Body.Close()

	if seedResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/fixtures/seed status = %d, want 200", seedResp.StatusCode)
	}

	var payload struct {
		Status   string          `json:"status"`
		Session  SessionSnapshot `json:"session"`
		Fixtures struct {
			GmailMessages []string `json:"gmailMessages"`
			JiraIssues    []string `json:"jiraIssues"`
			GitHubRepos   []string `json:"githubRepos"`
			MCPServers    []string `json:"mcpServers"`
		} `json:"fixtures"`
	}
	if err := json.NewDecoder(seedResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode seed response: %v", err)
	}

	if payload.Status != "seeded" {
		t.Errorf("seed status = %q, want %q", payload.Status, "seeded")
	}
	if payload.Session.PendingConfirmation != nil {
		t.Errorf("expected PendingConfirmation to be cleared after seed, got %+v", payload.Session.PendingConfirmation)
	}
	if len(payload.Session.GrantedProviders[PersonaAlice]) != 4 {
		t.Errorf("expected Alice to have 4 granted providers after seed, got %v", payload.Session.GrantedProviders[PersonaAlice])
	}
	if len(payload.Session.GrantedProviders[PersonaBob]) != 4 {
		t.Errorf("expected Bob to have 4 granted providers after seed, got %v", payload.Session.GrantedProviders[PersonaBob])
	}
	if len(payload.Fixtures.JiraIssues) < 2 {
		t.Errorf("expected Jira fixtures to include PUB-202 and SEC-101, got %v", payload.Fixtures.JiraIssues)
	}
}

func TestPortal_ScenariosEndpoint(t *testing.T) {
	rt := NewRuntime(RuntimeConfig{})
	srv := httptest.NewServer(NewHandler(rt))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/scenarios")
	if err != nil {
		t.Fatalf("GET /api/scenarios: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/scenarios status = %d, want 200", resp.StatusCode)
	}

	var out struct {
		Scenarios []struct {
			ID                ScenarioID   `json:"id"`
			Title             string       `json:"title"`
			Subtitle          string       `json:"subtitle"`
			DefaultPersona    PersonaID    `json:"defaultPersona"`
			DefaultPrompt     string       `json:"defaultPrompt"`
			PrimaryBoundaries []BoundaryID `json:"primaryBoundaries"`
			RedExploitSummary string       `json:"redExploitSummary"`
			BlueDefenseSummary string      `json:"blueDefenseSummary"`
		} `json:"scenarios"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode scenarios response: %v", err)
	}

	wantIDs := []ScenarioID{
		Scenario01PromptInjectionAndPII,
		Scenario02ConfusedDeputy3LO,
		Scenario03AgentGatewayAndStepUp,
		Scenario04AttenuatedA2ASandbox,
		Scenario05FullChainZeroTrust,
	}
	if len(out.Scenarios) != len(wantIDs) {
		t.Fatalf("got %d scenarios, want %d", len(out.Scenarios), len(wantIDs))
	}
	for i, wantID := range wantIDs {
		if out.Scenarios[i].ID != wantID {
			t.Errorf("scenario[%d].ID = %q, want %q", i, out.Scenarios[i].ID, wantID)
		}
		if out.Scenarios[i].Title == "" || out.Scenarios[i].DefaultPrompt == "" {
			t.Errorf("scenario %q missing title or defaultPrompt", wantID)
		}
	}
}
