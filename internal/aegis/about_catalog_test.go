package aegis_test

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
		zone aegis.TopologyZone
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
		nb := nodeBox{id: cn.ID, zone: aegis.ZoneIngress, x: cn.X, y: cn.Y, w: cn.Width, h: cn.Height}
		if cn.Zone != "" {
			nb.zone = cn.Zone
		}
		boxes = append(boxes, nb)
		byID[cn.ID] = nb
	}

	wantBoundaryZone := map[aegis.BoundaryID]aegis.TopologyZone{
		aegis.BoundaryGenerativeUI:       aegis.ZoneIngress,
		aegis.BoundaryReasoningGuard:     aegis.ZoneReasoningCore,
		aegis.BoundaryIdentity3LO:        aegis.ZoneExecutionPlanes,
		aegis.BoundaryPlatformGovernance: aegis.ZoneExecutionPlanes,
		aegis.BoundaryCrossAgentA2A:      aegis.ZoneExecutionPlanes,
		aegis.BoundarySandboxEgress:      aegis.ZoneExecutionPlanes,
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
	zoneBounds := func(zone aegis.TopologyZone) (minX, maxX int) {
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
	_, ingressMaxX := zoneBounds(aegis.ZoneIngress)
	coreMinX, coreMaxX := zoneBounds(aegis.ZoneReasoningCore)
	execMinX, _ := zoneBounds(aegis.ZoneExecutionPlanes)

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

func extractHTMLOpeningTagByID(html, elemID string) (string, bool) {
	needle := `id="` + elemID + `"`
	idx := strings.Index(html, needle)
	if idx < 0 {
		return "", false
	}
	start := strings.LastIndex(html[:idx], "<")
	endRel := strings.Index(html[idx:], ">")
	if start < 0 || endRel < 0 {
		return "", false
	}
	return html[start : idx+endRel+1], true
}

func TestPortal_AboutSingleLensThreeTabWorkspace(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(bodyBytes)

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

	// 1. Slim single-row header replaces tall 5-stat-pill hero banner
	if strings.Contains(html, "about-stat-pill") {
		t.Errorf("expected slim single-row /about header without 5-stat-pill hero clutter")
	}
	for _, wantTabMarkup := range []string{
		`id="about-workspace-tabs"`,
		`id="about-tab-topology"`,
		`data-about-tab="topology"`,
		`Security Topology`,
		`id="about-tab-lifecycle"`,
		`data-about-tab="lifecycle"`,
		`ADK Plugin Flow`,
		`id="about-tab-reference"`,
		`data-about-tab="reference"`,
		`System Reference`,
	} {
		if !strings.Contains(html, wantTabMarkup) {
			t.Errorf("/about HTML missing workspace tab markup %q", wantTabMarkup)
		}
	}

	// 2. Progressive disclosure on initial load: Security Topology visible; ADK Plugin Flow & System Reference hidden
	topoTag, ok := extractHTMLOpeningTagByID(html, "about-topology-module")
	if !ok {
		t.Fatalf("missing #about-topology-module opening tag")
	}
	if strings.Contains(topoTag, " hidden") {
		t.Errorf("expected #about-topology-module to be visible on load, got tag %q", topoTag)
	}

	for _, hiddenID := range []string{"about-lifecycle-module", "about-governance-module"} {
		openTag, found := extractHTMLOpeningTagByID(html, hiddenID)
		if !found {
			t.Fatalf("missing #%s opening tag", hiddenID)
		}
		if !strings.Contains(openTag, " hidden") {
			t.Errorf("expected #%s to carry hidden attribute on initial load, got tag %q", hiddenID, openTag)
		}
	}

	// 3. Client-side progressive-disclosure tab switching without query parameters
	for _, wantJS := range []string{
		"function switchAboutWorkspace(",
		`switchAboutWorkspace("reference")`,
		`switchAboutWorkspace("topology")`,
		"function jumpToAboutTool(",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing progressive-disclosure workspace switcher logic %q", wantJS)
		}
	}
	if strings.Contains(js, "?tab=") {
		t.Errorf("app.js must not use query-parameter tab routing (?tab=)")
	}
}

func TestPortal_AboutUnifiedToolbarAndRunInArenaHandoff(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(bodyBytes)

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

	// 1. Unified single-row toolbar above SVG stage with scenario pills, posture switch, Replay, and Run in Arena
	for _, wantHTML := range []string{
		`class="topology-toolbar"`,
		`id="topology-scenario-pills"`,
		`id="btn-sim-posture-blue"`,
		`id="btn-sim-posture-red"`,
		`id="btn-sim-replay"`,
		`id="btn-run-in-arena"`,
		`Run in Arena`,
	} {
		if !strings.Contains(html, wantHTML) {
			t.Errorf("/about HTML missing unified toolbar element %q", wantHTML)
		}
	}

	toolbarIdx := strings.Index(html, `class="topology-toolbar"`)
	stageIdx := strings.Index(html, `id="about-topology-svg-stage"`)
	if toolbarIdx < 0 || stageIdx < 0 || toolbarIdx > stageIdx {
		t.Errorf("expected .topology-toolbar (%d) to appear directly above #about-topology-svg-stage (%d)", toolbarIdx, stageIdx)
	}

	// 2. Compact 1-line scenario pill labels S1..S5 + Run in Arena handoff logic in app.js
	for _, wantJS := range []string{
		"S1 · Prompt & PII",
		"S2 · 3LO Vault",
		"S3 · UAP & Step-Up",
		"S4 · A2A Sandbox",
		"S5 · Full Chain",
		"async function runAboutScenarioInArena(",
		"btn-run-in-arena",
		"syncShieldUI()",
		"syncPersonaAndVaultUI()",
		"persistPosture()",
		`navigateToRoute("/", true)`,
		"selectScenarioAndFillPrompt(",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing toolbar or Run-in-Arena handoff snippet %q", wantJS)
		}
	}

	fnIdx := strings.Index(js, "async function runAboutScenarioInArena(")
	if fnIdx >= 0 {
		endIdx := strings.Index(js[fnIdx:], "\n  function ")
		if endIdx < 0 {
			endIdx = len(js) - fnIdx
		}
		fnBody := js[fnIdx : fnIdx+endIdx]
		if strings.Contains(fnBody, "executeTurn(") {
			t.Errorf("runAboutScenarioInArena must NOT auto-submit turns via executeTurn()")
		}
	}
}

func TestPortal_AboutDeclutteredThreeZoneSVGAndActivePathDimming(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

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

	// 1. Zero permanent idle edge label pills in base edges layer & zero 3rd/4th SVG node lines
	for _, forbiddenJS := range []string{
		"topo-edge-label-bg",
		"topo-edge-label-text",
		"CLIENT SURFACE",
		`" ADRs"`,
		"cy1 = 434",
	} {
		if strings.Contains(js, forbiddenJS) {
			t.Errorf("app.js still contains cluttered/stale SVG rendering artifact %q", forbiddenJS)
		}
	}
	if strings.Contains(css, ".topo-edge-label-bg") || strings.Contains(css, ".topo-edge-label-text") {
		t.Errorf("styles.css must not style permanent idle edge label pills")
	}

	// 2. Three-zone headers, curveOffsetY routing, 2-line nodeTag + status dot, active-path dimming, and top-layer hop callout
	for _, wantJS := range []string{
		"INGRESS",
		"REASONING CORE",
		"EXECUTION PLANES",
		"edge.curveOffsetY",
		"b.nodeTag",
		"cn.nodeTag",
		"node-status-dot",
		"inactive-scenario",
		"inactive-edge",
		"topo-hop-callout",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing decluttered 3-zone SVG hook %q", wantJS)
		}
	}

	for _, wantCSS := range []string{
		".topo-zone-label",
		".node-status-dot",
		".topo-boundary-node.inactive-scenario",
		".topo-edge-base.inactive-edge",
		".topo-hop-callout",
	} {
		if !strings.Contains(css, wantCSS) {
			t.Errorf("styles.css missing decluttered 3-zone SVG class %q", wantCSS)
		}
	}
}

func TestPortal_AboutHorizontalScrubberAndMicroInspector(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(bodyBytes)

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

	// 1. Standalone trajectory banner and tall 2-column bottom grid are replaced by horizontal scrubber + micro-inspector
	for _, removedHTML := range []string{
		`id="topology-trajectory-banner"`,
		`class="topology-bottom-grid"`,
	} {
		if strings.Contains(html, removedHTML) {
			t.Errorf("/about HTML still contains tall pre-Phase-5 layout block %q", removedHTML)
		}
	}
	for _, wantHTML := range []string{
		`class="topology-scrubber-bar"`,
		`id="topology-pulse-log"`,
		`id="pulse-step-counter"`,
		`id="pulse-hop-readout"`,
		`id="boundary-inspector-card"`,
	} {
		if !strings.Contains(html, wantHTML) {
			t.Errorf("/about HTML missing horizontal scrubber or micro-inspector mount %q", wantHTML)
		}
	}

	// 2. Micro-inspector uses concise blueSummary / redSummary + clickable governed tool & ADR jump pills
	for _, wantJS := range []string{
		"boundary.blueSummary",
		"boundary.redSummary",
		"about-tool-jump-btn",
		"jumpToAboutTool(",
		"about-adr-jump-btn",
		"jumpToAboutADR(",
		"scrubber-step-arrow",
		"selectAboutPulseHop(",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing horizontal scrubber or micro-inspector hook %q", wantJS)
		}
	}
	if strings.Contains(js, `getElementById("topology-trajectory-banner")`) {
		t.Errorf("app.js still references removed #topology-trajectory-banner")
	}

	for _, wantCSS := range []string{
		".topology-scrubber-bar",
		".pulse-hop-readout",
		".scrubber-step-arrow",
		".about-tool-jump-btn",
	} {
		if !strings.Contains(css, wantCSS) {
			t.Errorf("styles.css missing horizontal scrubber or micro-inspector class %q", wantCSS)
		}
	}
}

func TestPortal_AboutLifecyclePipelineAndCollapsibleSSEDrawer(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(bodyBytes)

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

	// 1. Permanently open 2-column SSE split is replaced by collapsed-by-default SSE wire drawer
	if strings.Contains(html, `class="lifecycle-bottom-grid"`) {
		t.Errorf("/about HTML still contains permanently open .lifecycle-bottom-grid split")
	}
	for _, wantHTML := range []string{
		`id="btn-toggle-lifecycle-sse"`,
		`aria-expanded="false"`,
		`aria-controls="lifecycle-sse-drawer"`,
		`Inspect Sample SSE Frame`,
		`id="lifecycle-sse-drawer"`,
		`id="lifecycle-sse-event-badge"`,
		`id="lifecycle-sse-preview"`,
	} {
		if !strings.Contains(html, wantHTML) {
			t.Errorf("/about HTML missing collapsible lifecycle SSE drawer markup %q", wantHTML)
		}
	}

	drawerTag, found := extractHTMLOpeningTagByID(html, "lifecycle-sse-drawer")
	if !found {
		t.Fatalf("missing #lifecycle-sse-drawer opening tag")
	}
	if !strings.Contains(drawerTag, " hidden") {
		t.Errorf("expected #lifecycle-sse-drawer to carry hidden attribute by default, got %q", drawerTag)
	}

	drawerIdx := strings.Index(html, `id="lifecycle-sse-drawer"`)
	previewIdx := strings.Index(html, `id="lifecycle-sse-preview"`)
	badgeIdx := strings.Index(html, `id="lifecycle-sse-event-badge"`)
	if drawerIdx < 0 || previewIdx < drawerIdx || badgeIdx < drawerIdx {
		t.Errorf("expected #lifecycle-sse-event-badge (%d) and #lifecycle-sse-preview (%d) inside #lifecycle-sse-drawer (%d)", badgeIdx, previewIdx, drawerIdx)
	}

	// 2. Lifecycle JS renders directional connectors, 2-column hook comparison, clickable tool/boundary pills, and drawer toggle
	fnStart := strings.Index(js, "function renderAboutLifecycleModule(")
	if fnStart < 0 {
		t.Fatalf("missing renderAboutLifecycleModule in app.js")
	}
	fnEndRel := strings.Index(js[fnStart+1:], "\n  function ")
	lifecycleFn := js[fnStart:]
	if fnEndRel >= 0 {
		lifecycleFn = js[fnStart : fnStart+1+fnEndRel]
	}

	for _, wantFnSnippet := range []string{
		"lifecycle-stage-connector",
		"adk_request_confirmation / tool.Run",
		"OnEvent -> SSE",
		"inspector-compare-grid",
		"What This Hook Enforces",
		"Short-Circuit / Mutation Rule",
		"selectAboutBoundary(",
		"about-tool-jump-btn",
		"jumpToAboutTool(",
	} {
		if !strings.Contains(lifecycleFn, wantFnSnippet) {
			t.Errorf("renderAboutLifecycleModule missing expected Phase 5 snippet %q", wantFnSnippet)
		}
	}
	for _, wantDrawerJS := range []string{
		"btn-toggle-lifecycle-sse",
		"lifecycle-sse-drawer",
		"aria-expanded",
	} {
		if !strings.Contains(js, wantDrawerJS) {
			t.Errorf("app.js missing SSE drawer toggle logic %q", wantDrawerJS)
		}
	}

	// 3. CSS enforces non-wrapping horizontal pipeline on .lifecycle-stage-name & .lifecycle-stage-track
	nameRuleIdx := strings.Index(css, ".lifecycle-stage-name")
	if nameRuleIdx < 0 {
		t.Fatalf("styles.css missing .lifecycle-stage-name rule")
	}
	nameRuleEnd := strings.Index(css[nameRuleIdx:], "}")
	if nameRuleEnd < 0 || !strings.Contains(css[nameRuleIdx:nameRuleIdx+nameRuleEnd], "white-space: nowrap") {
		t.Errorf("expected .lifecycle-stage-name rule to enforce white-space: nowrap")
	}
	for _, wantCSS := range []string{
		".lifecycle-stage-connector",
		".lifecycle-sse-toggle-btn",
		".lifecycle-sse-drawer",
	} {
		if !strings.Contains(css, wantCSS) {
			t.Errorf("styles.css missing lifecycle pipeline or SSE drawer class %q", wantCSS)
		}
	}
}

func TestPortal_AboutSystemReferenceSubtabsCompactRowsAndDeepLinks(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

	resp, err := http.Get(srv.URL + "/about")
	if err != nil {
		t.Fatalf("GET /about error: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read /about HTML: %v", err)
	}
	html := string(bodyBytes)

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

	// 1. 3-way segmented System Reference sub-switcher & panel progressive disclosure in index.html
	for _, wantHTML := range []string{
		`id="about-reference-subtabs"`,
		`id="ref-subtab-tools"`,
		`data-ref-subtab="tools"`,
		`Governed Tools (8)`,
		`id="ref-subtab-sources"`,
		`data-ref-subtab="sources"`,
		`External Sources (8)`,
		`id="ref-subtab-adrs"`,
		`data-ref-subtab="adrs"`,
		`ADR Index (13)`,
		`id="ref-panel-tools"`,
		`id="ref-panel-sources"`,
		`id="ref-panel-adrs"`,
		`id="about-sources-summary"`,
		`id="btn-refresh-about-catalog"`,
	} {
		if !strings.Contains(html, wantHTML) {
			t.Errorf("/about HTML missing System Reference sub-tab or panel markup %q", wantHTML)
		}
	}

	toolsPanelTag, ok := extractHTMLOpeningTagByID(html, "ref-panel-tools")
	if !ok {
		t.Fatalf("missing #ref-panel-tools opening tag")
	}
	if strings.Contains(toolsPanelTag, " hidden") {
		t.Errorf("expected #ref-panel-tools to be visible by default, got %q", toolsPanelTag)
	}
	for _, hiddenPanelID := range []string{"ref-panel-sources", "ref-panel-adrs"} {
		panelTag, found := extractHTMLOpeningTagByID(html, hiddenPanelID)
		if !found {
			t.Fatalf("missing #%s opening tag", hiddenPanelID)
		}
		if !strings.Contains(panelTag, " hidden") {
			t.Errorf("expected #%s to carry hidden attribute by default, got %q", hiddenPanelID, panelTag)
		}
	}

	// 2. Compact expandable .about-ref-row & .about-ref-detail + bidirectional cross-tab deep-links in app.js
	for _, wantJS := range []string{
		"function switchAboutReferenceSubtab(",
		`switchAboutReferenceSubtab("adrs")`,
		`switchAboutReferenceSubtab("tools")`,
		"about-ref-row",
		"about-ref-summary",
		"about-ref-detail",
		"expandedTools",
		"expandedSources",
		"expandedAdrs",
		"ev.stopPropagation()",
		"selectAboutBoundary(",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing System Reference compact row or cross-tab deep-link snippet %q", wantJS)
		}
	}

	// 3. CSS styles compact rows, detail trays, and sub-switcher
	for _, wantCSS := range []string{
		".about-reference-subtabs",
		".about-ref-subtab",
		".about-ref-row",
		".about-ref-summary",
		".about-ref-detail",
	} {
		if !strings.Contains(css, wantCSS) {
			t.Errorf("styles.css missing System Reference compact row or sub-tab class %q", wantCSS)
		}
	}
}

func TestPortal_AboutInterZoneCalloutClearanceAndLightModeZeroShift(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	srv := newLoopbackServer(t, aegis.NewHTTPHandler(rt))

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

	// 1. Dynamic obstacle-aware SVG hop callout clearance across inter-zone & horizontal ingress/return edges,
	//    Micro-Inspector component tag + deep disclosure, Cmd+K stage-safe source endpoints, and glossary Operator naming.
	for _, wantJS := range []string{
		"function computeRectOverlapArea(",
		"function resolveHopCalloutBox(",
		`"EDGE_B2_B3"`,
		`"EDGE_B3_B2"`,
		`"EDGE_B2_B4"`,
		`"EDGE_B2_B5"`,
		`"EDGE_B2_B1"`,
		`"EDGE_B1_BROWSER"`,
		"hop.edgeId",
		"finalHop.edgeId",
		"inspector-component-tag",
		"inspector-deep-drawer",
		"source-status-endpoint",
		"source-status-detail",
		"status-operator",
		"function createAboutRefRow(",
	} {
		if !strings.Contains(js, wantJS) {
			t.Errorf("app.js missing Phase 5 hardening logic %q", wantJS)
		}
	}
	if strings.Contains(js, "status-client") || strings.Contains(css, ".status-client") {
		t.Errorf("Operator Browser status dot must use Glossary 'status-operator' rather than avoided synonym 'client'")
	}
	if strings.Contains(css, ".topology-trajectory-banner") {
		t.Errorf("styles.css still contains unused .topology-trajectory-banner rules")
	}

	// 2. Projector Light Mode ([data-theme="light"]) uses pure color-token overrides with zero layout-shifting rules
	if count := strings.Count(css, `[data-theme=`); count != 1 {
		t.Errorf("expected exactly 1 [data-theme=...] token block in styles.css, got %d", count)
	}
	lightIdx := strings.Index(css, `[data-theme="light"]`)
	if lightIdx < 0 {
		t.Fatalf("missing [data-theme=\"light\"] block in styles.css")
	}
	openBrace := strings.Index(css[lightIdx:], "{")
	closeBrace := strings.Index(css[lightIdx:], "}")
	if openBrace < 0 || closeBrace < 0 || closeBrace <= openBrace {
		t.Fatalf("malformed [data-theme=\"light\"] block in styles.css")
	}
	lightBody := css[lightIdx+openBrace+1 : lightIdx+closeBrace]
	for _, rawLine := range strings.Split(lightBody, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "/*") {
			continue
		}
		if !strings.HasPrefix(line, "--") && !strings.HasPrefix(line, "color-scheme:") {
			t.Errorf("[data-theme=\"light\"] contains non-token declaration %q that could shift layout", line)
		}
	}
}

func TestPhase6_AboutCatalogADR0014AndBoundarySync(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	catalog, err := rt.BuildArchitectureTopologyCatalog(t.Context())
	if err != nil {
		t.Fatalf("BuildArchitectureTopologyCatalog: %v", err)
	}

	if len(catalog.ADRs) < 14 {
		t.Fatalf("len(catalog.ADRs) = %d, want >= 14 (0001..0014)", len(catalog.ADRs))
	}
	adr0014 := catalog.ADRs[13]
	if adr0014.Number != "0014" || adr0014.Slug != "gke-native-agent-platform-governance-and-dual-path-rollout" {
		t.Errorf("catalog.ADRs[13] = (%s, %s), want (0014, gke-native-agent-platform-governance-and-dual-path-rollout)", adr0014.Number, adr0014.Slug)
	}

	byBoundary := map[aegis.BoundaryID]aegis.BoundaryCatalogNode{}
	for _, b := range catalog.Boundaries {
		byBoundary[b.ID] = b
		if len(b.BlueSummary) > 140 {
			t.Errorf("Boundary %s BlueSummary length = %d, want <= 140 (%q)", b.ID, len(b.BlueSummary), b.BlueSummary)
		}
		if len(b.RedSummary) > 140 {
			t.Errorf("Boundary %s RedSummary length = %d, want <= 140 (%q)", b.ID, len(b.RedSummary), b.RedSummary)
		}
	}

	containsADR := func(nums []string, want string) bool {
		for _, n := range nums {
			if n == want {
				return true
			}
		}
		return false
	}

	for _, wantB := range []aegis.BoundaryID{
		aegis.BoundaryReasoningGuard,
		aegis.BoundaryIdentity3LO,
		aegis.BoundaryPlatformGovernance,
		aegis.BoundaryCrossAgentA2A,
	} {
		node := byBoundary[wantB]
		if !containsADR(node.ADRNumbers, "0014") {
			t.Errorf("Boundary %s ADRNumbers = %v, want 0014 included", wantB, node.ADRNumbers)
		}
	}

	b3 := byBoundary[aegis.BoundaryIdentity3LO]
	b3Joined := b3.ComponentName + " " + b3.BlueDefenseMechanism
	for _, term := range []string{"Agent Identity", "SPIFFE", "S256", "PKCE", "15m", "TokenBroker"} {
		if !strings.Contains(b3Joined, term) {
			t.Errorf("BoundaryIdentity3LO must reference %q, got %q", term, b3Joined)
		}
	}

	b4 := byBoundary[aegis.BoundaryPlatformGovernance]
	b4Joined := b4.ComponentName + " " + b4.BlueDefenseMechanism
	for _, term := range []string{"GCPAgentGateway", "GCPAuthzPolicy", "UAP Policy V2", "Agent Registry", "roles/iap.egressor"} {
		if !strings.Contains(b4Joined, term) {
			t.Errorf("BoundaryPlatformGovernance must reference %q, got %q", term, b4Joined)
		}
	}
}

func TestPhase6_ParameterizedManifestsAndAmbientEgressOverlay(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	manifestChecks := map[string][]string{
		"manifests/02-aegis-deployment.yaml": {
			"kind: Deployment",
			"name: aegis-sre",
			"namespace: aegis-system",
			`registry.gke.io/functional-type: "AGENT"`,
			`a2a-protocol.org/agent-card: '{"protocolVersion":"0.3.0","card":{"uriPath":"/.well-known/agent-card.json","port":8080,"protocol":"HTTP"}}'`,
			`iam.gke.io/spiffe-identity-type: "agent-identity"`,
			`iam.gke.io/identity: "spiffe://agents.global.org-${ORG_ID}.system.id.goog/*"`,
			`iam.gke.io/inject-podcertificates: "true"`,
			"image: us-central1-docker.pkg.dev/${PROJECT_ID}/aegis/aegis-server:latest",
			"GOOGLE_CLOUD_PROJECT",
			"${PROJECT_ID}",
			"GOOGLE_CLOUD_LOCATION",
			"${REGION}",
			"GKE_CLUSTER_NAME",
			"${CLUSTER_NAME}",
			"GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN",
			"AGENT_PLATFORM_LIVE_LLM",
			"LIVE_SUBSTRATE",
			"SUBSTRATE_GATEWAY_URL",
			"http://atenet-router.ate-system.svc.cluster.local/sandbox/execute",
			"SUBSTRATE_TARGET_ACTOR",
			"aegis-system/remediator-1",
			"SPIFFE_CREDENTIAL_BUNDLE_PATH",
			"/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem",
			"kind: Service",
			"name: a2a-http",
			"port: 80",
			"port: 8080",
		},
		"manifests/03-gke-diy-agent-gateway.yaml": {
			"apiVersion: gateway.networking.k8s.io/v1",
			"kind: Gateway",
			"name: aegis-ingress-gateway",
			"gatewayClassName: gke-l7-regional-external-managed",
			"kind: HTTPRoute",
			"name: aegis-a2a-route",
			"/.well-known/agent-card.json",
			"/a2a",
			"/mcp",
			"/about",
			"/healthz",
			"apiVersion: networking.gke.io/v1",
			"kind: GCPAgentGateway",
			"name: aegis-client-to-agent-gateway",
			"//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/global",
			"//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/${REGION}",
			"kind: GCPAuthzExtension",
			"name: aegis-modelarmor-content-ext",
			"modelarmor.${REGION}.rep.googleapis.com:443",
			"X-Goog-User-Project",
			"model_armor_settings",
			"projects/${PROJECT_ID}/locations/${REGION}/templates/aegis-prompt-screen",
			"name: aegis-iap-request-ext",
			"iap.googleapis.com:443",
			"kind: GCPAuthzPolicy",
			"name: aegis-a2a-ingress-policy",
			"enforcementLevel: L7",
			"action: ALLOW",
			"CONTENT_AUTHZ",
			"MATCH_BASE_PROTOCOL_METHODS",
			"enable_gcp_agent_gateway_policy",
		},
		"manifests/agw-egress-config.yaml": {
			"googleManaged:",
			"governedAccessPath: AGENT_TO_ANYWHERE",
			"protocols:",
			"- MCP",
			"registries:",
			"//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/global",
			"//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/${REGION}",
			"https://logging.googleapis.com/mcp",
			"https://container.googleapis.com/mcp",
			"https://api.github.com/mcp",
			"https://api.atlassian.com/mcp",
		},
		"manifests/iap-policy.json": {
			"aegis-egress-uap",
			"iap.googleapis.com/resources.egressViaIAP",
			"principal://agents.global.org-${ORG_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre",
			"destination.is_registered == true && destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true && destination.agent_registry.mcp_server.tool.annotations.destructive_hint != true",
			"roles/iap.egressor",
			"iap.googleapis.com/mcp.tool.isReadOnly",
			"iap.googleapis.com/mcp.toolName",
			"logging.entries.list",
			"container.clusters.get",
		},
		"manifests/model-armor-config.yaml": {
			"apiVersion: modelarmor.googleapis.com/v1",
			"aegis-prompt-screen",
			"filterConfig:",
			"piAndJailbreakFilterSettings:",
			"maliciousUriFilterSettings:",
			"raiSettings:",
			"sdpSettings:",
		},
		"manifests/ambient-egress/01-ambient-egress-policy.yaml": {
			"apiVersion: networking.gke.io/v1",
			"kind: GCPBackend",
			"name: aegis-swp-egress-backend",
			"serviceUris:",
			"kind: GCPEgressPolicy",
			"name: default",
			"excludeCIDRRanges:",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
	}

	for relPath, wantSubstrings := range manifestChecks {
		fullPath := filepath.Join(repoRoot, relPath)
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}
		content := string(rawBytes)
		assertNoEmojiRunes(t, relPath, content)
		for _, sub := range wantSubstrings {
			if !strings.Contains(content, sub) {
				t.Errorf("%s missing expected snippet %q", relPath, sub)
			}
		}
		if strings.HasSuffix(relPath, ".json") {
			var parsed map[string]any
			if err := json.Unmarshal(rawBytes, &parsed); err != nil {
				t.Errorf("%s is not valid JSON: %v", relPath, err)
			}
		}
	}
}

func TestPhase6_AutoResolvingHackScripts(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	scriptChecks := map[string][]string{
		"hack/deploy-gke.sh": {
			"kubectl config current-context",
			"PROJECT_ID",
			"PROJECT_NUMBER",
			"ORG_ID",
			"CLUSTER_NAME",
			"CLUSTER_LOCATION",
			"REGION",
			"sed",
			"manifests/00-namespace-and-rbac.yaml",
			"manifests/01-agent-substrate-v050.yaml",
			"manifests/02-aegis-deployment.yaml",
			"manifests/03-gke-diy-agent-gateway.yaml",
			"deployment/aegis-sre",
		},
		"hack/register-gemini-enterprise.sh": {
			"kubectl",
			"aegis-ingress-gateway",
			"{.status.addresses[0].value}",
			"https://aegis.example.com",
			"/.well-known/agent-card.json",
			"discoveryengine.googleapis.com",
			"serverSideOauth2",
		},
	}

	for relPath, wantSubstrings := range scriptChecks {
		fullPath := filepath.Join(repoRoot, relPath)
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("read %s: %v", relPath, err)
		}
		content := string(rawBytes)
		assertNoEmojiRunes(t, relPath, content)
		for _, sub := range wantSubstrings {
			if !strings.Contains(content, sub) {
				t.Errorf("%s missing expected snippet %q", relPath, sub)
			}
		}
		if out, err := exec.Command("bash", "-n", fullPath).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s failed: %v (%s)", relPath, err, string(out))
		}
	}
}

func TestPhase7_Manifests02And03And04AndDeployScript(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	manifestChecks := map[string][]string{
		"manifests/02-aegis-deployment.yaml": {
			"app: aegis-sre",
			"name: ext-proc-tls",
			"containerPort: 8443",
			"protocol: TCP",
			"name: EXT_PROC_TLS_ADDR",
			`value: ":8443"`,
		},
		"manifests/03-gke-diy-agent-gateway.yaml": {
			"kind: Service",
			"name: aegis-model-armor-ext-proc",
			`cloud.google.com/neg: '{"ingress":true}'`,
			"app: aegis-sre",
			"name: grpc-ext-proc",
			"port: 443",
			"targetPort: 8443",
			"appProtocol: HTTP2",
			"kind: GCPAuthzExtension",
			"authority: aegis-model-armor-ext-proc.aegis-system.svc.cluster.local",
			"wireFormat: ExtProcGRPC",
			"timeout: 2000ms",
			"backendRef:",
			"kind: GCPTrafficExtension",
			"name: aegis-model-armor-body-ext",
			"supportedEvents:",
			"- RequestHeaders",
			"- RequestBody",
			"requestBodySendMode: FullDuplexStreamed",
			"modelarmor.${REGION}.rep.googleapis.com",
		},
		"manifests/04-checkout-target-workload.yaml": {
			"apiVersion: apps/v1",
			"kind: Deployment",
			"name: checkout-service",
			"namespace: aegis-system",
			"app: checkout-service",
			"version: v2.4.0",
			"image: alpine:3.20",
			"502 Bad Gateway",
			"RetryPolicy.NextBackoff",
			"checkout_handler.go",
			"142",
			"sleep 15",
		},
		"hack/deploy-gke.sh": {
			"manifests/04-checkout-target-workload.yaml",
			"deployment/checkout-service",
		},
	}

	for relPath, wantSubstrings := range manifestChecks {
		fullPath := filepath.Join(repoRoot, relPath)
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}
		content := string(rawBytes)
		assertNoEmojiRunes(t, relPath, content)
		lower := strings.ToLower(content)
		for _, forbidden := range []string{"mofi" + "labs", "ate" + "-cluster", "gke-ate" + "-cluster", "vertex" + " ai", "fluid" + " compute"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains forbidden personal/retired string %q", relPath, forbidden)
			}
		}
		for _, sub := range wantSubstrings {
			if !strings.Contains(content, sub) {
				t.Errorf("%s missing expected Phase 7 snippet %q", relPath, sub)
			}
		}
	}
}

func TestPhase7_AboutCatalogExtProcAndCheckoutTelemetrySync(t *testing.T) {
	rt := aegis.NewRuntime(aegis.RuntimeConfig{})
	catalog, err := rt.BuildArchitectureTopologyCatalog(t.Context())
	if err != nil {
		t.Fatalf("BuildArchitectureTopologyCatalog: %v", err)
	}

	if len(catalog.ADRs) != 15 {
		t.Fatalf("len(catalog.ADRs) = %d, want 15 (0001..0015)", len(catalog.ADRs))
	}
	adr0015 := catalog.ADRs[14]
	if adr0015.Number != "0015" || adr0015.Slug != "in-cluster-ext-proc-callout-live-checkout-telemetry-and-stage-runbook" {
		t.Errorf("catalog.ADRs[14] = (%s, %s), want (0015, in-cluster-ext-proc-callout-live-checkout-telemetry-and-stage-runbook)", adr0015.Number, adr0015.Slug)
	}

	byBoundary := map[aegis.BoundaryID]aegis.BoundaryCatalogNode{}
	for _, b := range catalog.Boundaries {
		byBoundary[b.ID] = b
	}

	b1Joined := byBoundary[aegis.BoundaryGenerativeUI].ComponentName + " " + byBoundary[aegis.BoundaryGenerativeUI].BlueDefenseMechanism
	for _, term := range []string{":8443", "ExtProcGRPC", "Authz Extension Callout", "X-Aegis-Authz-Extension"} {
		if !strings.Contains(b1Joined, term) {
			t.Errorf("B1 (BoundaryGenerativeUI) must reference %q, got %q", term, b1Joined)
		}
	}

	b2Joined := byBoundary[aegis.BoundaryReasoningGuard].ComponentName + " " + byBoundary[aegis.BoundaryReasoningGuard].BlueDefenseMechanism
	for _, term := range []string{":8443", "ExtProcGRPC", "Authz Extension Callout", "Service/aegis-model-armor-ext-proc", "GCPAuthzExtension", "GCPTrafficExtension"} {
		if !strings.Contains(b2Joined, term) {
			t.Errorf("B2 (BoundaryReasoningGuard) must reference %q, got %q", term, b2Joined)
		}
	}

	b4Joined := byBoundary[aegis.BoundaryPlatformGovernance].ComponentName + " " + byBoundary[aegis.BoundaryPlatformGovernance].BlueDefenseMechanism
	for _, term := range []string{":8443", "ExtProcGRPC", "Service/aegis-model-armor-ext-proc", "GCPAuthzExtension", "GCPTrafficExtension", "Deployment/checkout-service", "502"} {
		if !strings.Contains(b4Joined, term) {
			t.Errorf("B4 (BoundaryPlatformGovernance) must reference %q, got %q", term, b4Joined)
		}
	}

	if err := aegis.VerifyArchitectureCatalogDrift(catalog, rt, filepath.Clean("../../docs/adr")); err != nil {
		t.Fatalf("VerifyArchitectureCatalogDrift: %v", err)
	}
}

func TestPhase7_READMEAndStageRunbookSyncAndHygiene(t *testing.T) {
	repoRoot := filepath.Clean("../..")

	docChecks := map[string][]string{
		"README.md": {
			"ADR-0014",
			"ADR-0015",
			"0015",
			"ADR Index (15)",
			":8443",
			"ExtProcGRPC",
			"Service/aegis-model-armor-ext-proc",
			"GCPAuthzExtension",
			"GCPTrafficExtension",
			"AGENT_TO_ANYWHERE",
			"iap.googleapis.com/resources.egressViaIAP",
			"/var/run/secrets/workload-spiffe-credentials/",
			"manifests/03-gke-diy-agent-gateway.yaml",
			"manifests/04-checkout-target-workload.yaml",
			"docs/stage-runbook.md",
		},
		"docs/stage-runbook.md": {
			"Deployment/aegis-sre",
			"Deployment/checkout-service",
			"WorkerPool/aegis-remediator-pool",
			"Actor/remediator-1",
			"Gateway/aegis-ingress-gateway",
			"Projector Light Mode",
			"/about",
			"Security Topology",
			"Run in Arena",
			"ADK Plugin Flow",
			"System Reference",
			"15",
			"SCENARIO-01",
			"IsSdpOnlyBlock",
			"SCENARIO-02",
			"Alice",
			"Bob",
			"15m",
			"S256",
			"Token Broker",
			"SCENARIO-03",
			"container.clusters.delete",
			"adk_request_confirmation",
			"SCENARIO-04",
			"svc/atenet-router",
			"SNAPSHOT_FIDELITY_MEMORY",
			"SCENARIO-05",
			":8443",
			"ExtProcGRPC",
			"X-Aegis-Edge-Enforce: true",
			"blocked_by_gcp_authz_extension",
			"curl",
		},
	}

	forbiddenCliches := []string{
		"not just ",
		"not merely ",
		"delve",
		"tapestry",
		"stands as a testament",
		"let's dive in",
		"without further ado",
	}

	for relPath, wantSubstrings := range docChecks {
		fullPath := filepath.Join(repoRoot, relPath)
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}
		content := string(rawBytes)
		assertNoEmojiRunes(t, relPath, content)
		lower := strings.ToLower(content)
		for _, forbidden := range []string{"mofi" + "labs", "ate" + "-cluster", "gke-ate" + "-cluster", "vertex" + " ai", "fluid" + " compute"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains forbidden personal/retired string %q", relPath, forbidden)
			}
		}
		for _, cliche := range forbiddenCliches {
			if strings.Contains(lower, cliche) {
				t.Errorf("%s contains forbidden AI cliche %q", relPath, cliche)
			}
		}
		for _, sub := range wantSubstrings {
			if !strings.Contains(content, sub) {
				t.Errorf("%s missing expected Phase 7 snippet %q", relPath, sub)
			}
		}
	}
}






