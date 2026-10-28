package aegis_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gke-demos/agent-security/internal/aegis"
)

func newLoopbackServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		srv.Close()
		t.Fatalf("test server URL %q must bind strictly to 127.0.0.1", srv.URL)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestPortal_PathBasedRouting_RootAndAbout(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	var rootHTML, aboutHTML string

	for _, route := range []string{"/", "/about"} {
		resp, err := http.Get(srv.URL + route)
		if err != nil {
			t.Fatalf("GET %s error: %v", route, err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read %s body: %v", route, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200 OK", route, resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if ct != "text/html; charset=utf-8" {
			t.Errorf("GET %s Content-Type = %q, want %q", route, ct, "text/html; charset=utf-8")
		}
		if route == "/" {
			rootHTML = string(raw)
		} else {
			aboutHTML = string(raw)
		}
	}

	if rootHTML != aboutHTML {
		t.Errorf("expected GET / and GET /about to serve identical SPA HTML shell")
	}

	// Verify segmented route switcher & about-view mount exist in SPA shell
	for _, wantSnippet := range []string{
		`id="nav-route-arena"`,
		`id="nav-route-about"`,
		`id="about-view"`,
		`Arena`,
		`Architecture`,
	} {
		if !strings.Contains(aboutHTML, wantSnippet) {
			t.Errorf("SPA HTML shell missing required routing snippet %q", wantSnippet)
		}
	}

	// Unknown paths must return 404 Not Found
	for _, badPath := range []string{"/about/extra", "/settings", "/unknown-route"} {
		resp, err := http.Get(srv.URL + badPath)
		if err != nil {
			t.Fatalf("GET %s error: %v", badPath, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404 Not Found", badPath, resp.StatusCode)
		}
	}

	// Verify app.js uses path-based History API routing and never query parameters (?view=about)
	jsResp, err := http.Get(srv.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js error: %v", err)
	}
	jsBytes, err := io.ReadAll(jsResp.Body)
	jsResp.Body.Close()
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	js := string(jsBytes)

	for _, wantJS := range []string{
		"window.location.pathname",
		"window.history.pushState",
		"popstate",
		`"/about"`,
		"nav-route-arena",
		"nav-route-about",
		"about-view",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing path-based routing snippet %q", wantJS)
		}
	}
	for _, forbiddenQuery := range []string{"?view=", "?page=", "?route=", "searchParams.get(\"view\")"} {
		if strings.Contains(js, forbiddenQuery) || strings.Contains(aboutHTML, forbiddenQuery) {
			t.Errorf("forbidden query-parameter routing snippet %q detected", forbiddenQuery)
		}
	}
}

func TestArchitectureTopologyCatalog_BoundariesCallbacksToolsAndLiveSources(t *testing.T) {
	// Configure a hybrid runtime where GitHub and Substrate Gateway are LIVE while others remain FIXTURE,
	// verifying that GET /api/about/catalog dynamically reflects live rt.GetSourcesStatus(ctx).
	mockGitHub := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mockSubstrate := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rt := aegis.NewRuntime(aegis.RuntimeConfig{
		GitHubAPIURL:        mockGitHub.URL,
		GitHubTargetRepo:    "gke-demos/aegis-checkout-target",
		AliceGitHubToken:    "gho_test_alice_live_catalog",
		SubstrateGatewayURL: mockSubstrate.URL,
	})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/api/about/catalog")
	if err != nil {
		t.Fatalf("GET /api/about/catalog error: %v", err)
	}
	rawBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read catalog body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/about/catalog status = %d, want 200 OK (body=%s)", resp.StatusCode, string(rawBytes))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	rawStr := string(rawBytes)
	if strings.Contains(strings.ToLower(rawStr), "vertex ai") {
		t.Errorf("catalog JSON must use Gemini Enterprise Agent Platform branding, never retired 'Vertex AI'")
	}
	if strings.Contains(strings.ToLower(rawStr), "fluid compute") {
		t.Errorf("catalog JSON must never contain internal term 'fluid compute'")
	}

	var catalog aegis.ArchitectureTopologyCatalog
	if err := json.Unmarshal(rawBytes, &catalog); err != nil {
		t.Fatalf("unmarshal ArchitectureTopologyCatalog: %v", err)
	}

	// 1. Verify all 6 canonical BoundaryIDs with SVG geometry, Phase 4 B3 PKCE 15m vault & B6 atenet-router Actor/remediator-1
	wantBoundaries := []aegis.BoundaryID{
		aegis.BoundaryGenerativeUI,
		aegis.BoundaryReasoningGuard,
		aegis.BoundaryIdentity3LO,
		aegis.BoundaryPlatformGovernance,
		aegis.BoundaryCrossAgentA2A,
		aegis.BoundarySandboxEgress,
	}
	if len(catalog.Boundaries) != len(wantBoundaries) {
		t.Fatalf("len(catalog.Boundaries) = %d, want %d", len(catalog.Boundaries), len(wantBoundaries))
	}
	for i, wantID := range wantBoundaries {
		b := catalog.Boundaries[i]
		if b.ID != wantID {
			t.Errorf("Boundaries[%d].ID = %q, want %q", i, b.ID, wantID)
		}
		if b.Width <= 0 || b.Height <= 0 {
			t.Errorf("Boundary %q has invalid SVG dimensions (%d x %d)", b.ID, b.Width, b.Height)
		}
		if b.ShieldKey == "" || b.ComponentName == "" || b.RedExploitMode == "" || b.BlueDefenseMechanism == "" {
			t.Errorf("Boundary %q missing required descriptive fields: %+v", b.ID, b)
		}
		if len(b.GovernedTools) == 0 || len(b.ADRNumbers) == 0 {
			t.Errorf("Boundary %q must link governed tools and ADRs: %+v", b.ID, b)
		}
		if b.ID == aegis.BoundaryIdentity3LO {
			joined := b.ComponentName + " " + b.BlueDefenseMechanism
			if !strings.Contains(joined, "PKCE") || !strings.Contains(joined, "S256") || !strings.Contains(joined, "15m") {
				t.Errorf("B3 catalog node must reflect S256 PKCE + 15m in-memory TokenBroker vault, got: %s", joined)
			}
		}
		if b.ID == aegis.BoundarySandboxEgress {
			joined := b.ComponentName + " " + b.BlueDefenseMechanism
			if !strings.Contains(joined, "atenet-router") || !strings.Contains(joined, "remediator-1") || !strings.Contains(joined, "SNAPSHOT_FIDELITY_MEMORY") {
				t.Errorf("B6 catalog node must reflect svc/atenet-router + Actor/remediator-1 Golden Snapshot, got: %s", joined)
			}
		}
	}

	if len(catalog.Edges) < 6 {
		t.Errorf("expected at least 6 SVG topology edges, got %d", len(catalog.Edges))
	}

	// 2. Verify all 6 AegisSecurityPlugin callbacks in exact lifecycle order with valid TurnStreamEvent SSE previews
	wantCallbacks := aegis.CanonicalSecurityPluginCallbacks()
	if !reflect.DeepEqual(wantCallbacks, []string{"BeforeRun", "BeforeModel", "BeforeTool", "AfterTool", "AfterModel", "OnEvent"}) {
		t.Fatalf("CanonicalSecurityPluginCallbacks() = %v, want exact 6 ADK lifecycle hooks", wantCallbacks)
	}
	if len(catalog.PluginCallbacks) != len(wantCallbacks) {
		t.Fatalf("len(catalog.PluginCallbacks) = %d, want %d", len(catalog.PluginCallbacks), len(wantCallbacks))
	}
	for i, wantHook := range wantCallbacks {
		cb := catalog.PluginCallbacks[i]
		if cb.Name != wantHook {
			t.Errorf("PluginCallbacks[%d].Name = %q, want %q", i, cb.Name, wantHook)
		}
		if cb.StageIndex != i+1 {
			t.Errorf("PluginCallbacks[%d].StageIndex = %d, want %d", i, cb.StageIndex, i+1)
		}
		if cb.RoleSummary == "" || cb.ShortCircuitBehavior == "" || len(cb.GovernedBoundaries) == 0 || len(cb.GovernedTools) == 0 {
			t.Errorf("PluginCallback %q missing required fields: %+v", cb.Name, cb)
		}
		var sampleEv aegis.TurnStreamEvent
		if err := json.Unmarshal([]byte(cb.SampleSSEFrame), &sampleEv); err != nil {
			t.Errorf("PluginCallback %q SampleSSEFrame is not valid TurnStreamEvent JSON: %v (%s)", cb.Name, err, cb.SampleSSEFrame)
		}
		if sampleEv.Type == "" {
			t.Errorf("PluginCallback %q SampleSSEFrame missing TurnStreamEvent.Type", cb.Name)
		}
	}

	// 3. Verify 1:1 parity between actual registered ADK functiontools and catalog.Tools
	registeredTools := rt.RegisteredGovernedTools()
	gotCatalogTools := make([]string, 0, len(catalog.Tools))
	for _, toolEntry := range catalog.Tools {
		gotCatalogTools = append(gotCatalogTools, toolEntry.Name)
		if toolEntry.PrimaryBoundary == "" || toolEntry.StepUpPolicy == "" || toolEntry.Description == "" {
			t.Errorf("ToolCatalogEntry %q missing metadata: %+v", toolEntry.Name, toolEntry)
		}
	}
	if !reflect.DeepEqual(gotCatalogTools, registeredTools) {
		t.Errorf("catalog.Tools names = %v, want 1:1 parity with rt.RegisteredGovernedTools() = %v", gotCatalogTools, registeredTools)
	}

	// 4. Verify live 8 External Sources match rt.GetSourcesStatus(ctx)
	if len(catalog.Sources) != 8 {
		t.Fatalf("len(catalog.Sources) = %d, want 8", len(catalog.Sources))
	}
	bySource := map[aegis.ExternalSourceID]aegis.SourceProvenance{}
	for _, s := range catalog.Sources {
		bySource[s.ID] = s.Provenance
	}
	if bySource[aegis.SourceGitHub] != aegis.ProvenanceLive {
		t.Errorf("catalog.Sources[github] = %q, want LIVE", bySource[aegis.SourceGitHub])
	}
	if bySource[aegis.SourceSubstrateSandbox] != aegis.ProvenanceLive {
		t.Errorf("catalog.Sources[substrate_sandbox] = %q, want LIVE", bySource[aegis.SourceSubstrateSandbox])
	}
	if bySource[aegis.SourceAtlassianJira] != aegis.ProvenanceFixture {
		t.Errorf("catalog.Sources[atlassian_jira] = %q, want FIXTURE", bySource[aegis.SourceAtlassianJira])
	}
}

func TestArchitectureTopologyCatalog_ScenariosADRsAndDriftDetection(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/api/about/catalog")
	if err != nil {
		t.Fatalf("GET /api/about/catalog error: %v", err)
	}
	rawBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read catalog body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var catalog aegis.ArchitectureTopologyCatalog
	if err := json.Unmarshal(rawBytes, &catalog); err != nil {
		t.Fatalf("unmarshal catalog: %v", err)
	}

	// 1. Verify all 5 Security Scenarios (SCENARIO-01..05) have Blue and Red pulse trajectories
	wantScenarios := []aegis.ScenarioID{
		aegis.Scenario01PromptInjectionAndPII,
		aegis.Scenario02ConfusedDeputy3LO,
		aegis.Scenario03AgentGatewayAndStepUp,
		aegis.Scenario04AttenuatedA2ASandbox,
		aegis.Scenario05FullChainZeroTrust,
	}
	if len(catalog.Scenarios) != len(wantScenarios) {
		t.Fatalf("len(catalog.Scenarios) = %d, want %d", len(catalog.Scenarios), len(wantScenarios))
	}

	validNodeIDs := map[string]bool{}
	for _, n := range catalog.ContextNodes {
		validNodeIDs[n.ID] = true
	}
	for _, b := range catalog.Boundaries {
		validNodeIDs[string(b.ID)] = true
	}
	validEdgeIDs := map[string]bool{}
	for _, e := range catalog.Edges {
		validEdgeIDs[e.ID] = true
		if !validNodeIDs[e.From] || !validNodeIDs[e.To] {
			t.Errorf("Topology edge %q references unknown node (%q -> %q)", e.ID, e.From, e.To)
		}
	}

	allowedPulseVerdicts := map[aegis.PacketPulseVerdict]bool{
		aegis.PulseVerdictPass:        true,
		aegis.PulseVerdictRedacted:    true,
		aegis.PulseVerdictBlocked:     true,
		aegis.PulseVerdictStepUp:      true,
		aegis.PulseVerdictExfiltrated: true,
	}
	seenPulseVerdicts := map[aegis.PacketPulseVerdict]bool{}

	for i, wantID := range wantScenarios {
		sc := catalog.Scenarios[i]
		if sc.ID != wantID {
			t.Errorf("Scenarios[%d].ID = %q, want %q", i, sc.ID, wantID)
		}
		if sc.Title == "" || len(sc.PrimaryBoundaries) == 0 {
			t.Errorf("Scenario %q missing title or primaryBoundaries", sc.ID)
		}
		for _, traj := range []struct {
			mode string
			spec aegis.ScenarioPostureTrajectory
		}{
			{"BLUE", sc.Blue},
			{"RED", sc.Red},
		} {
			if traj.spec.Summary == "" || len(traj.spec.ActiveBoundaries) == 0 || len(traj.spec.Pulses) == 0 {
				t.Errorf("Scenario %q (%s) missing summary, activeBoundaries, or pulses: %+v", sc.ID, traj.mode, traj.spec)
			}
			if !allowedPulseVerdicts[traj.spec.TerminalVerdict] {
				t.Errorf("Scenario %q (%s) invalid TerminalVerdict %q", sc.ID, traj.mode, traj.spec.TerminalVerdict)
			}
			seenPulseVerdicts[traj.spec.TerminalVerdict] = true
			for _, hop := range traj.spec.Pulses {
				if !validNodeIDs[hop.From] || !validNodeIDs[hop.To] {
					t.Errorf("Scenario %q (%s) pulse hop (%q -> %q) references unknown node", sc.ID, traj.mode, hop.From, hop.To)
				}
				if !validEdgeIDs[hop.EdgeID] {
					t.Errorf("Scenario %q (%s) pulse hop references unknown edgeId %q", sc.ID, traj.mode, hop.EdgeID)
				}
				if !allowedPulseVerdicts[hop.Verdict] {
					t.Errorf("Scenario %q (%s) pulse hop has invalid verdict %q", sc.ID, traj.mode, hop.Verdict)
				}
				seenPulseVerdicts[hop.Verdict] = true
			}
		}
	}

	// Ensure all 5 canonical packet-pulse verdicts are exercised across the simulation specs
	for wantVerdict := range allowedPulseVerdicts {
		if !seenPulseVerdicts[wantVerdict] {
			t.Errorf("expected packet-pulse verdict %q to be exercised in catalog.Scenarios, seen=%v", wantVerdict, seenPulseVerdicts)
		}
	}

	// 2. Glob ../../docs/adr/[0-9][0-9][0-9][0-9]-*.md on disk and assert exact 1:1 parity across all 13 ADR files
	adrDir := filepath.Clean("../../docs/adr")
	adrFiles, err := filepath.Glob(filepath.Join(adrDir, "[0-9][0-9][0-9][0-9]-*.md"))
	if err != nil {
		t.Fatalf("glob ADR files: %v", err)
	}
	if len(adrFiles) < 13 {
		t.Fatalf("expected at least 13 ADR files on disk in %s, found %d", adrDir, len(adrFiles))
	}
	if len(catalog.ADRs) != len(adrFiles) {
		t.Fatalf("len(catalog.ADRs) = %d, want exact parity with %d ADR files on disk", len(catalog.ADRs), len(adrFiles))
	}
	for i, adrPath := range adrFiles {
		base := strings.TrimSuffix(filepath.Base(adrPath), ".md")
		parts := strings.SplitN(base, "-", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected ADR filename %q", base)
		}
		wantNum, wantSlug := parts[0], parts[1]
		got := catalog.ADRs[i]
		if got.Number != wantNum || got.Slug != wantSlug {
			t.Errorf("ADRs[%d] = (%s, %s), want (%s, %s)", i, got.Number, got.Slug, wantNum, wantSlug)
		}
		if got.Title == "" || got.Summary == "" || len(got.PrimaryBoundaries) == 0 {
			t.Errorf("ADR %s-%s missing title, summary, or primaryBoundaries: %+v", got.Number, got.Slug, got)
		}
	}

	// 3. Run automated drift engine against real repo docs/adr and prove it fails on synthetic drift
	if err := aegis.VerifyArchitectureCatalogDrift(&catalog, rt, adrDir); err != nil {
		t.Fatalf("VerifyArchitectureCatalogDrift failed on live repository state: %v", err)
	}

	t.Run("DetectsUnregisteredADROnDisk", func(t *testing.T) {
		tmpADRDir := t.TempDir()
		for _, f := range adrFiles {
			data, readErr := os.ReadFile(f)
			if readErr != nil {
				t.Fatalf("read %s: %v", f, readErr)
			}
			if writeErr := os.WriteFile(filepath.Join(tmpADRDir, filepath.Base(f)), data, 0o600); writeErr != nil {
				t.Fatalf("write temp ADR: %v", writeErr)
			}
		}
		extra := filepath.Join(tmpADRDir, "0099-unregistered-drift-check.md")
		if err := os.WriteFile(extra, []byte("# 99. Unregistered Drift Check\n"), 0o600); err != nil {
			t.Fatalf("write extra ADR: %v", err)
		}
		if err := aegis.VerifyArchitectureCatalogDrift(&catalog, rt, tmpADRDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when an unregistered ADR file exists on disk")
		}
	})

	t.Run("DetectsMissingGovernedToolOrBoundary", func(t *testing.T) {
		mutated := catalog
		mutated.Tools = append([]aegis.ToolCatalogEntry(nil), catalog.Tools[:len(catalog.Tools)-1]...)
		if err := aegis.VerifyArchitectureCatalogDrift(&mutated, rt, adrDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when a registered ADK tool is missing from catalog.Tools")
		}

		mutatedBoundaries := catalog
		mutatedBoundaries.Boundaries = append([]aegis.BoundaryCatalogNode(nil), catalog.Boundaries[:5]...)
		if err := aegis.VerifyArchitectureCatalogDrift(&mutatedBoundaries, rt, adrDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when a canonical BoundaryID is missing")
		}
	})
}

func assertNoEmojiRunes(t *testing.T, label, content string) {
	t.Helper()
	for _, r := range content {
		if (r >= 0x1F300 && r <= 0x1FAFF) || (r >= 0x2600 && r <= 0x27BF) || (r >= 0xFE00 && r <= 0xFE0F) {
			t.Errorf("%s contains forbidden emoji rune U+%04X (%q); use inline SVG icons only", label, r, string(r))
			return
		}
	}
}

func TestPortal_AboutInteractiveVisualizerModulesAndSecurityHygiene(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	aboutResp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	aboutBytes, err := io.ReadAll(aboutResp.Body)
	aboutResp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(aboutBytes)

	cssResp, err := http.Get(srv.URL + "/static/styles.css")
	if err != nil {
		t.Fatalf("GET /static/styles.css error: %v", err)
	}
	cssBytes, err := io.ReadAll(cssResp.Body)
	cssResp.Body.Close()
	if err != nil {
		t.Fatalf("read styles.css: %v", err)
	}
	css := string(cssBytes)

	jsResp, err := http.Get(srv.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js error: %v", err)
	}
	jsBytes, err := io.ReadAll(jsResp.Body)
	jsResp.Body.Close()
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	js := string(jsBytes)

	// 1. Verify all 3 interactive visual canvas modules exist in /about HTML shell
	wantHTMLMounts := []string{
		// Module 1: Interactive 6-Boundary SVG Topology & Red-vs-Blue Packet-Pulse Simulator
		`id="about-topology-module"`,
		`id="topology-scenario-pills"`,
		`id="btn-sim-posture-blue"`,
		`id="btn-sim-posture-red"`,
		`id="btn-sim-replay"`,
		`id="about-topology-svg-stage"`,
		`id="topology-pulse-log"`,
		`id="boundary-inspector-card"`,
		// Module 2: AegisSecurityPlugin Callback State Machine & SSE Wire Preview
		`id="about-lifecycle-module"`,
		`id="lifecycle-stage-track"`,
		`id="lifecycle-detail-panel"`,
		`id="lifecycle-sse-preview"`,
		// Module 3: Live 8-Source Provenance, Tool Governance & ADR Matrix
		`id="about-governance-module"`,
		`id="about-sources-grid"`,
		`id="about-tools-grid"`,
		`id="adr-filter-pills"`,
		`id="about-adr-grid"`,
	}
	for _, snippet := range wantHTMLMounts {
		if !strings.Contains(html, snippet) {
			t.Errorf("/about HTML missing required visualizer mount %q", snippet)
		}
	}

	// 2. Verify app.js drives all 3 modules from GET /api/about/catalog via safe SVG/DOM APIs
	wantJSSnippets := []string{
		"/api/about/catalog",
		"http://www.w3.org/2000/svg",
		"createElementNS",
		"requestAnimationFrame",
		"about-topology-svg-stage",
		"boundary-inspector-card",
		"lifecycle-stage-track",
		"lifecycle-sse-preview",
		"about-sources-grid",
		"about-tools-grid",
		"about-adr-grid",
		"EXFILTRATED",
		"STEP-UP",
	}
	for _, snippet := range wantJSSnippets {
		if !strings.Contains(js, snippet) {
			t.Errorf("app.js missing required /about interactive visualizer logic %q", snippet)
		}
	}

	// 3. Verify styles.css includes responsive styling for /about topology, pulse animation, lifecycle, and matrices
	wantCSSSnippets := []string{
		".about-container",
		".topo-boundary-node",
		".lifecycle-stage-track",
		".about-sources-grid",
		".about-tools-grid",
		".about-adr-grid",
	}
	for _, snippet := range wantCSSSnippets {
		if !strings.Contains(css, snippet) {
			t.Errorf("styles.css missing required /about class %q", snippet)
		}
	}

	// 4. Security & brand hygiene checks across HTML, CSS, and JS
	assertNoEmojiRunes(t, "index.html", html)
	assertNoEmojiRunes(t, "styles.css", css)
	assertNoEmojiRunes(t, "app.js", js)

	for name, content := range map[string]string{
		"index.html": html,
		"styles.css": css,
		"app.js":     js,
	} {
		lower := strings.ToLower(content)
		if strings.Contains(lower, "vertex ai") {
			t.Errorf("%s contains retired branding 'Vertex AI'; use Gemini Enterprise Agent Platform", name)
		}
		if strings.Contains(lower, "fluid compute") {
			t.Errorf("%s contains forbidden internal term 'fluid compute'", name)
		}
	}
}
