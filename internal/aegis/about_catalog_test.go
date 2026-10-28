package aegis_test

import (
	"encoding/json"
	"io"
	"math"
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
	if strings.Contains(js, `indexOf("/about/") === 0`) || strings.Contains(js, `startsWith("/about/")`) {
		t.Errorf("resolveRouteFromPathname in app.js must only resolve exact '/about' or '/about/', never wildcard '/about/*'")
	}
	if !strings.Contains(js, `pathname === "/about" || pathname === "/about/"`) {
		t.Errorf("app.js missing exact '/about' / '/about/' route match in resolveRouteFromPathname")
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
	retiredBrand := "vertex" + " ai"
	internalTerm := "fluid" + " compute"
	if strings.Contains(strings.ToLower(rawStr), retiredBrand) {
		t.Errorf("catalog JSON must use Gemini Enterprise Agent Platform branding, never %q", retiredBrand)
	}
	if strings.Contains(strings.ToLower(rawStr), internalTerm) {
		t.Errorf("catalog JSON must never contain internal term %q", internalTerm)
	}
	avoidedTerm := "token" + " passthrough"
	if strings.Contains(strings.ToLower(rawStr), avoidedTerm) {
		t.Errorf("catalog JSON must honor GLOSSARY.md and avoid %q; use 'Unattenuated 3LO Credential Forwarding'", avoidedTerm)
	}
	if !strings.Contains(rawStr, "Unattenuated 3LO Credential Forwarding") {
		t.Errorf("catalog JSON missing 'Unattenuated 3LO Credential Forwarding' pulse label")
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

func evalCubicPoint(x0, y0, cx1, cy1, cx2, cy2, x3, y3, t float64) (float64, float64) {
	u := 1 - t
	tt := t * t
	uu := u * u
	uuu := uu * u
	ttt := tt * t
	return uuu*x0 + 3*uu*t*cx1 + 3*u*tt*cx2 + ttt*x3,
		uuu*y0 + 3*uu*t*cy1 + 3*u*tt*cy2 + ttt*y3
}

func TestArchitectureTopologyCatalog_ThreeZoneGeometryMicroSummariesAndNonCrossingEdges(t *testing.T) {
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

	rawJSON := string(rawBytes)
	for _, wantJSONKey := range []string{
		`"nodeTag"`,
		`"zone"`,
		`"blueSummary"`,
		`"redSummary"`,
		`"curveOffsetY"`,
	} {
		if !strings.Contains(rawJSON, wantJSONKey) {
			t.Errorf("GET /api/about/catalog JSON missing required key %s", wantJSONKey)
		}
	}

	var catalog aegis.ArchitectureTopologyCatalog
	if err := json.Unmarshal(rawBytes, &catalog); err != nil {
		t.Fatalf("unmarshal ArchitectureTopologyCatalog: %v", err)
	}

	if catalog.ViewBoxWidth != 1200 {
		t.Errorf("ViewBoxWidth = %d, want 1200", catalog.ViewBoxWidth)
	}
	if catalog.ViewBoxHeight != 390 && catalog.ViewBoxHeight != 400 {
		t.Errorf("ViewBoxHeight = %d, want 390 or 400", catalog.ViewBoxHeight)
	}

	type nodeBox struct {
		id   string
		zone string
		x    int
		y    int
		w    int
		h    int
	}
	boxes := make([]nodeBox, 0, len(catalog.ContextNodes)+len(catalog.Boundaries))
	byID := map[string]nodeBox{}

	if len(catalog.ContextNodes) == 0 {
		t.Fatalf("expected OPERATOR_BROWSER context node")
	}
	for _, cn := range catalog.ContextNodes {
		if strings.TrimSpace(cn.NodeTag) == "" {
			t.Errorf("ContextNode %q missing NodeTag", cn.ID)
		}
		nb := nodeBox{id: cn.ID, zone: "INGRESS", x: cn.X, y: cn.Y, w: cn.Width, h: cn.Height}
		if cn.Zone != "" {
			nb.zone = cn.Zone
		}
		boxes = append(boxes, nb)
		byID[cn.ID] = nb
	}

	wantBoundaryZone := map[aegis.BoundaryID]string{
		aegis.BoundaryGenerativeUI:       "INGRESS",
		aegis.BoundaryReasoningGuard:     "REASONING_CORE",
		aegis.BoundaryIdentity3LO:        "EXECUTION_PLANES",
		aegis.BoundaryPlatformGovernance: "EXECUTION_PLANES",
		aegis.BoundaryCrossAgentA2A:      "EXECUTION_PLANES",
		aegis.BoundarySandboxEgress:      "EXECUTION_PLANES",
	}

	for _, b := range catalog.Boundaries {
		if got, want := b.Zone, wantBoundaryZone[b.ID]; got != want {
			t.Errorf("Boundary %s Zone = %q, want %q", b.ID, got, want)
		}
		if strings.TrimSpace(b.NodeTag) == "" || len(b.NodeTag) > 28 {
			t.Errorf("Boundary %s NodeTag = %q, want non-empty concise tag (<= 28 chars)", b.ID, b.NodeTag)
		}
		if strings.TrimSpace(b.BlueSummary) == "" || strings.TrimSpace(b.RedSummary) == "" {
			t.Errorf("Boundary %s missing BlueSummary or RedSummary: blue=%q red=%q", b.ID, b.BlueSummary, b.RedSummary)
		}
		if strings.TrimSpace(b.ShortLabel) == "" || strings.TrimSpace(b.Subtitle) == "" ||
			strings.TrimSpace(b.BlueDefenseMechanism) == "" || strings.TrimSpace(b.RedExploitMode) == "" {
			t.Errorf("Boundary %s lost existing descriptive field: %+v", b.ID, b)
		}
		nb := nodeBox{id: string(b.ID), zone: b.Zone, x: b.X, y: b.Y, w: b.Width, h: b.Height}
		boxes = append(boxes, nb)
		byID[string(b.ID)] = nb
	}

	// Verify bounds & zero overlapping node boxes
	for i, a := range boxes {
		if a.x < 0 || a.y < 0 || a.x+a.w > catalog.ViewBoxWidth || a.y+a.h > catalog.ViewBoxHeight {
			t.Errorf("node %s box (%d,%d,%d,%d) exceeds viewBox (%dx%d)", a.id, a.x, a.y, a.w, a.h, catalog.ViewBoxWidth, catalog.ViewBoxHeight)
		}
		for j := i + 1; j < len(boxes); j++ {
			b := boxes[j]
			overlapX := a.x < b.x+b.w && b.x < a.x+a.w
			overlapY := a.y < b.y+b.h && b.y < a.y+a.h
			if overlapX && overlapY {
				t.Errorf("nodes %s and %s overlap: %+v vs %+v", a.id, b.id, a, b)
			}
		}
	}

	// Verify >= 52px horizontal separation between INGRESS, REASONING_CORE, and EXECUTION_PLANES
	zoneBounds := func(zone string) (minX, maxX int) {
		minX = catalog.ViewBoxWidth
		maxX = 0
		for _, nb := range boxes {
			if nb.zone != zone {
				continue
			}
			if nb.x < minX {
				minX = nb.x
			}
			if nb.x+nb.w > maxX {
				maxX = nb.x + nb.w
			}
		}
		return minX, maxX
	}
	_, ingressMaxX := zoneBounds("INGRESS")
	coreMinX, coreMaxX := zoneBounds("REASONING_CORE")
	execMinX, _ := zoneBounds("EXECUTION_PLANES")

	if gap1 := coreMinX - ingressMaxX; gap1 < 52 {
		t.Errorf("INGRESS -> REASONING_CORE horizontal gap = %dpx, want >= 52px", gap1)
	}
	if gap2 := execMinX - coreMaxX; gap2 < 52 {
		t.Errorf("REASONING_CORE -> EXECUTION_PLANES horizontal gap = %dpx, want >= 52px", gap2)
	}

	// Verify Execution Planes 3-lane vertical layout (B3 upper, B4 middle, B5 -> B6 lower)
	b3 := byID[string(aegis.BoundaryIdentity3LO)]
	b4 := byID[string(aegis.BoundaryPlatformGovernance)]
	b5 := byID[string(aegis.BoundaryCrossAgentA2A)]
	b6 := byID[string(aegis.BoundarySandboxEgress)]
	if b3.y+b3.h >= b4.y {
		t.Errorf("expected B3 upper lane (%d..%d) strictly above B4 middle lane (%d..%d)", b3.y, b3.y+b3.h, b4.y, b4.y+b4.h)
	}
	if b4.y+b4.h >= b5.y || b4.y+b4.h >= b6.y {
		t.Errorf("expected B4 middle lane (%d..%d) strictly above B5/B6 lower lane (%d)", b4.y, b4.y+b4.h, b5.y)
	}
	if b5.x+b5.w >= b6.x {
		t.Errorf("expected B5 (%d..%d) strictly left of B6 (%d..%d) in lower lane", b5.x, b5.x+b5.w, b6.x, b6.x+b6.w)
	}

	// Verify all 10 canonical edge IDs and non-crossing curves (especially EDGE_B6_B2 clearing B5)
	wantEdgeIDs := []string{
		"EDGE_BROWSER_B1",
		"EDGE_B1_B2",
		"EDGE_B2_B3",
		"EDGE_B3_B2",
		"EDGE_B2_B4",
		"EDGE_B2_B5",
		"EDGE_B5_B6",
		"EDGE_B6_B2",
		"EDGE_B2_B1",
		"EDGE_B1_BROWSER",
	}
	gotEdgeIDs := make([]string, 0, len(catalog.Edges))
	for _, e := range catalog.Edges {
		gotEdgeIDs = append(gotEdgeIDs, e.ID)
	}
	if !reflect.DeepEqual(gotEdgeIDs, wantEdgeIDs) {
		t.Fatalf("catalog.Edges IDs = %v, want %v", gotEdgeIDs, wantEdgeIDs)
	}

	foundReturnArc := false
	for _, e := range catalog.Edges {
		x0, y0 := float64(e.FromX), float64(e.FromY)
		x3, y3 := float64(e.ToX), float64(e.ToY)
		dx := math.Max(24, math.Abs(x3-x0)*0.48)

		type ctrlPair struct {
			name               string
			cx1, cy1, cx2, cy2 float64
		}
		var variants []ctrlPair
		if e.CurveOffsetY != 0 {
			railY := math.Max(y0, y3) + float64(e.CurveOffsetY)
			sign := 1.0
			if x3 < x0 {
				sign = -1.0
			}
			variants = []ctrlPair{
				{name: "vertical-drop", cx1: x0, cy1: railY, cx2: x3, cy2: railY},
				{name: "horizontal-spread", cx1: x0 + sign*dx, cy1: railY, cx2: x3 - sign*dx, cy2: railY},
			}
		} else {
			sign := 1.0
			if x3 < x0 {
				sign = -1.0
			}
			variants = []ctrlPair{
				{name: "standard", cx1: x0 + sign*dx, cy1: y0, cx2: x3 - sign*dx, cy2: y3},
			}
		}

		if e.ID == "EDGE_B6_B2" {
			foundReturnArc = true
			if e.CurveOffsetY <= 0 {
				t.Errorf("EDGE_B6_B2 CurveOffsetY = %d, want > 0 for bottom-margin return routing", e.CurveOffsetY)
			}
		}

		for _, v := range variants {
			for step := 0; step <= 200; step++ {
				tVal := float64(step) / 200.0
				px, py := evalCubicPoint(x0, y0, v.cx1, v.cy1, v.cx2, v.cy2, x3, y3, tVal)
				if px < 0 || px > float64(catalog.ViewBoxWidth) || py < 0 || py > float64(catalog.ViewBoxHeight) {
					t.Errorf("edge %s (%s) escapes viewBox at t=%.2f: (%.1f, %.1f)", e.ID, v.name, tVal, px, py)
					break
				}
				if step > 4 && step < 196 {
					for _, nb := range boxes {
						if nb.id == e.From || nb.id == e.To {
							continue
						}
						if px >= float64(nb.x) && px <= float64(nb.x+nb.w) && py >= float64(nb.y) && py <= float64(nb.y+nb.h) {
							t.Errorf("edge %s (%s) intersects intermediate node %s at t=%.2f (%.1f, %.1f)", e.ID, v.name, nb.id, tVal, px, py)
							break
						}
					}
				}
				if e.ID == "EDGE_B6_B2" && px >= float64(b5.x) && px <= float64(b5.x+b5.w) {
					if py <= float64(b5.y+b5.h)+8.0 {
						t.Errorf("EDGE_B6_B2 (%s) failed to clear bottom of B5 (%d) with >=8px margin at x=%.1f: py=%.1f", v.name, b5.y+b5.h, px, py)
						break
					}
				}
			}
		}
	}
	if !foundReturnArc {
		t.Errorf("missing EDGE_B6_B2 in catalog.Edges")
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

	t.Run("DetectsADRTitleAndStatusDriftOnDisk", func(t *testing.T) {
		// 1. Mutating an ADR's H1 title on disk must trigger drift error
		titleDriftDir := t.TempDir()
		for _, f := range adrFiles {
			data, readErr := os.ReadFile(f)
			if readErr != nil {
				t.Fatalf("read %s: %v", f, readErr)
			}
			content := string(data)
			if strings.HasPrefix(filepath.Base(f), "0012-") {
				content = strings.Replace(content, "# 12. OAuth 2.0 + S256 PKCE Login Flows and Ephemeral In-Memory TokenBroker Vault", "# 12. Mutated Out-of-Sync ADR Heading", 1)
			}
			if writeErr := os.WriteFile(filepath.Join(titleDriftDir, filepath.Base(f)), []byte(content), 0o600); writeErr != nil {
				t.Fatalf("write temp ADR: %v", writeErr)
			}
		}
		if err := aegis.VerifyArchitectureCatalogDrift(&catalog, rt, titleDriftDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when an ADR H1 title on disk drifts from catalog.ADRs")
		}

		// 2. Changing an Accepted ADR's ## Status to Superseded on disk must trigger drift error
		statusDriftDir := t.TempDir()
		for _, f := range adrFiles {
			data, readErr := os.ReadFile(f)
			if readErr != nil {
				t.Fatalf("read %s: %v", f, readErr)
			}
			content := string(data)
			if strings.HasPrefix(filepath.Base(f), "0012-") {
				content = strings.Replace(content, "## Status\n\nAccepted", "## Status\n\nSuperseded", 1)
			}
			if writeErr := os.WriteFile(filepath.Join(statusDriftDir, filepath.Base(f)), []byte(content), 0o600); writeErr != nil {
				t.Fatalf("write temp ADR: %v", writeErr)
			}
		}
		if err := aegis.VerifyArchitectureCatalogDrift(&catalog, rt, statusDriftDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when an ADR ## Status on disk changes from Accepted to Superseded")
		}
	})

	t.Run("DetectsOverlappingNodesOrInsufficientZoneGap", func(t *testing.T) {
		overlapCat := catalog
		overlapCat.Boundaries = append([]aegis.BoundaryCatalogNode(nil), catalog.Boundaries...)
		overlapCat.Boundaries[1].X = overlapCat.Boundaries[0].X + 10
		if err := aegis.VerifyArchitectureCatalogDrift(&overlapCat, rt, adrDir); err == nil {
			t.Fatalf("expected VerifyArchitectureCatalogDrift to fail when boundary boxes overlap or violate 52px zone gap")
		}
	})
}

func TestADR0011_DocumentsPhase5WorkspaceThreeZoneSVGAndStageSafeSources(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	catalog, err := rt.BuildArchitectureTopologyCatalog(t.Context())
	if err != nil {
		t.Fatalf("BuildArchitectureTopologyCatalog: %v", err)
	}

	adrDir := filepath.Clean("../../docs/adr")
	adr0011Path := filepath.Join(adrDir, "0011-path-based-routing-and-interactive-about-architecture-catalog.md")
	rawBytes, err := os.ReadFile(adr0011Path)
	if err != nil {
		t.Fatalf("read ADR-0011: %v", err)
	}
	md := string(rawBytes)

	if !strings.HasPrefix(md, "# 11. Path-Based Routing (`/` & `/about`) and Interactive Architecture Topology Catalog\n") {
		t.Errorf("ADR-0011 must preserve exact canonical H1 heading")
	}
	if !strings.Contains(md, "## Status\n\nAccepted") {
		t.Errorf("ADR-0011 must preserve Accepted status section")
	}

	for _, wantTerm := range []string{
		"Security Topology",
		"ADK Plugin Flow",
		"System Reference",
		"Ingress",
		"Reasoning Core",
		"Execution Planes",
		"Run in Arena",
		"GOOGLE_CLOUD_PROJECT",
		"GKE_CLUSTER_NAME",
		"/api/sources/status",
	} {
		if !strings.Contains(md, wantTerm) {
			t.Errorf("ADR-0011 missing Phase 5 architectural decision detail %q", wantTerm)
		}
	}

	assertNoEmojiRunes(t, "ADR-0011", md)
	lower := strings.ToLower(md)
	if strings.Contains(lower, "vertex"+" ai") || strings.Contains(lower, "fluid"+" compute") {
		t.Errorf("ADR-0011 contains forbidden branding or internal terminology")
	}

	var found0011 bool
	for _, entry := range catalog.ADRs {
		if entry.Number == "0011" {
			found0011 = true
			if !strings.Contains(entry.Summary, "3-tab") || !strings.Contains(entry.Summary, "3-zone") {
				t.Errorf("catalog ADR 0011 summary should reflect 3-tab workspace and 3-zone topology, got %q", entry.Summary)
			}
		}
	}
	if !found0011 {
		t.Errorf("ADR 0011 missing from catalog.ADRs")
	}

	if err := aegis.VerifyArchitectureCatalogDrift(catalog, rt, adrDir); err != nil {
		t.Fatalf("VerifyArchitectureCatalogDrift failed: %v", err)
	}
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
		"adk_request_confirmation / tool.Run",
		"OnEvent -> SSE",
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
		".lifecycle-stage-pill",
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

	retiredBrand := "vertex" + " ai"
	internalTerm := "fluid" + " compute"
	for name, content := range map[string]string{
		"index.html": html,
		"styles.css": css,
		"app.js":     js,
	} {
		lower := strings.ToLower(content)
		if strings.Contains(lower, retiredBrand) {
			t.Errorf("%s contains retired branding %q; use Gemini Enterprise Agent Platform", name, retiredBrand)
		}
		if strings.Contains(lower, internalTerm) {
			t.Errorf("%s contains forbidden internal term %q", name, internalTerm)
		}
	}
}
