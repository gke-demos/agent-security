package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PacketPulseVerdict classifies an animated SVG signal pulse hop in the /about topology simulator.
type PacketPulseVerdict string

const (
	PulseVerdictPass        PacketPulseVerdict = "PASS"
	PulseVerdictRedacted    PacketPulseVerdict = "REDACTED"
	PulseVerdictBlocked     PacketPulseVerdict = "BLOCKED"
	PulseVerdictStepUp      PacketPulseVerdict = "STEP-UP"
	PulseVerdictExfiltrated PacketPulseVerdict = "EXFILTRATED"
)

// TopologyContextNode describes a non-boundary entry/exit actor node on the SVG topology canvas (e.g. Operator Browser).
type TopologyContextNode struct {
	ID       string `json:"id"`
	Zone     string `json:"zone"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	NodeTag  string `json:"nodeTag"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
}

// BoundaryCatalogNode describes one of AegisSRE's 6 defense-in-depth security boundaries for /about.
type BoundaryCatalogNode struct {
	ID                   BoundaryID `json:"id"`
	Code                 string     `json:"code"`
	Zone                 string     `json:"zone"`
	Title                string     `json:"title"`
	ShortLabel           string     `json:"shortLabel"`
	Subtitle             string     `json:"subtitle"`
	NodeTag              string     `json:"nodeTag"`
	X                    int        `json:"x"`
	Y                    int        `json:"y"`
	Width                int        `json:"width"`
	Height               int        `json:"height"`
	ShieldKey            string     `json:"shieldKey"`
	ShieldName           string     `json:"shieldName"`
	ComponentName        string     `json:"componentName"`
	BlueSummary          string     `json:"blueSummary"`
	RedSummary           string     `json:"redSummary"`
	RedExploitMode       string     `json:"redExploitMode"`
	BlueDefenseMechanism string     `json:"blueDefenseMechanism"`
	GovernedTools        []string   `json:"governedTools"`
	ADRNumbers           []string   `json:"adrNumbers"`
}

// TopologyEdgeSpec defines a directed SVG connection between two topology nodes.
type TopologyEdgeSpec struct {
	ID           string `json:"id"`
	From         string `json:"from"`
	To           string `json:"to"`
	Label        string `json:"label"`
	FromX        int    `json:"fromX"`
	FromY        int    `json:"fromY"`
	ToX          int    `json:"toX"`
	ToY          int    `json:"toY"`
	CurveOffsetY int    `json:"curveOffsetY,omitempty"`
}

// PluginCallbackCatalogNode describes one of the 6 AegisSecurityPlugin lifecycle hooks.
type PluginCallbackCatalogNode struct {
	StageIndex              int                   `json:"stageIndex"`
	Name                    string                `json:"name"`
	ExecutionLabel          string                `json:"executionLabel"`
	RoleSummary             string                `json:"roleSummary"`
	ShortCircuitBehavior    string                `json:"shortCircuitBehavior"`
	GovernedBoundaries      []BoundaryID          `json:"governedBoundaries"`
	GovernedTools           []string              `json:"governedTools"`
	EmittedStreamEventTypes []TurnStreamEventType `json:"emittedStreamEventTypes"`
	SampleSSEFrame          string                `json:"sampleSSEFrame"`
}

// ToolCatalogEntry describes one of the 8 governed ADK Go v2 functiontool tools.
type ToolCatalogEntry struct {
	Name            string           `json:"name"`
	WireOperation   string           `json:"wireOperation"`
	PrimaryBoundary BoundaryID       `json:"primaryBoundary"`
	Provider        ProviderID       `json:"provider"`
	ExternalSource  ExternalSourceID `json:"externalSource"`
	StepUpPolicy    string           `json:"stepUpPolicy"`
	Description     string           `json:"description"`
}

// ScenarioPulseHop represents a single animated packet hop across a topology edge.
type ScenarioPulseHop struct {
	Step    int                `json:"step"`
	EdgeID  string             `json:"edgeId"`
	From    string             `json:"from"`
	To      string             `json:"to"`
	Verdict PacketPulseVerdict `json:"verdict"`
	Label   string             `json:"label"`
	Detail  string             `json:"detail"`
}

// ScenarioPostureTrajectory defines the animated SVG signal trajectory under either Blue or Red posture.
type ScenarioPostureTrajectory struct {
	Posture          string             `json:"posture"`
	Outcome          TurnOutcome        `json:"outcome"`
	TerminalVerdict  PacketPulseVerdict `json:"terminalVerdict"`
	Summary          string             `json:"summary"`
	ActiveBoundaries []BoundaryID       `json:"activeBoundaries"`
	Pulses           []ScenarioPulseHop `json:"pulses"`
}

// ScenarioSimulationSpec defines both Red and Blue packet-pulse simulation trajectories for a Security Scenario.
type ScenarioSimulationSpec struct {
	ID                ScenarioID                `json:"id"`
	Title             string                    `json:"title"`
	Subtitle          string                    `json:"subtitle"`
	DefaultPersona    PersonaID                 `json:"defaultPersona"`
	PrimaryBoundaries []BoundaryID              `json:"primaryBoundaries"`
	Blue              ScenarioPostureTrajectory `json:"blue"`
	Red               ScenarioPostureTrajectory `json:"red"`
}

// ADRCatalogEntry represents an accepted Architecture Decision Record in docs/adr/.
type ADRCatalogEntry struct {
	Number            string       `json:"number"`
	Slug              string       `json:"slug"`
	FileName          string       `json:"fileName"`
	Status            string       `json:"status"`
	Title             string       `json:"title"`
	Summary           string       `json:"summary"`
	PrimaryBoundaries []BoundaryID `json:"primaryBoundaries"`
}

// ArchitectureTopologyCatalog is the strongly typed backend specification for GET /api/about/catalog (ADR-0011).
type ArchitectureTopologyCatalog struct {
	ViewBoxWidth    int                         `json:"viewBoxWidth"`
	ViewBoxHeight   int                         `json:"viewBoxHeight"`
	ContextNodes    []TopologyContextNode       `json:"contextNodes"`
	Boundaries      []BoundaryCatalogNode       `json:"boundaries"`
	Edges           []TopologyEdgeSpec          `json:"edges"`
	PluginCallbacks []PluginCallbackCatalogNode `json:"pluginCallbacks"`
	Tools           []ToolCatalogEntry          `json:"tools"`
	Scenarios       []ScenarioSimulationSpec    `json:"scenarios"`
	ADRs            []ADRCatalogEntry           `json:"adrs"`
	Sources         []SourceStatus              `json:"sources"`
}

// BuildArchitectureTopologyCatalog constructs the live ArchitectureTopologyCatalog for /about.
// TODO(security): GET /api/about/catalog is a stateless read-only JSON endpoint backed by in-memory
// canonical metadata and live non-secret SourceStatus probes; SQL parameterization, multipart file-upload
// scanning, and cookie-based CSRF tokens are N/A (zero SQL DB, zero file uploads, zero auth cookies).
func (r *Runtime) BuildArchitectureTopologyCatalog(ctx context.Context) (*ArchitectureTopologyCatalog, error) {
	sources, err := r.GetSourcesStatus(ctx)
	if err != nil {
		return nil, err
	}

	return &ArchitectureTopologyCatalog{
		ViewBoxWidth:  1200,
		ViewBoxHeight: 390,
		ContextNodes: []TopologyContextNode{
			{
				ID:       "OPERATOR_BROWSER",
				Zone:     "INGRESS",
				Title:    "Operator Browser",
				Subtitle: "A2UI v0.9 + Web Crypto PKCE",
				NodeTag:  "A2UI v0.9 · PKCE",
				X:        20,
				Y:        144,
				Width:    168,
				Height:   72,
			},
		},
		Boundaries:      canonicalBoundaryCatalogNodes(),
		Edges:           canonicalTopologyEdges(),
		PluginCallbacks: canonicalPluginCallbackCatalogNodes(),
		Tools:           canonicalToolCatalogEntries(),
		Scenarios:       canonicalScenarioSimulationSpecs(),
		ADRs:            canonicalADRCatalogEntries(),
		Sources:         sources,
	}, nil
}

// VerifyArchitectureCatalogDrift asserts that catalog stays 100% synchronized with all canonical
// BoundaryIDs, AegisSecurityPlugin callbacks, registered ADK functiontool names, ScenarioIDs,
// SVG topology node/edge references, and docs/adr/[0-9][0-9][0-9][0-9]-*.md files on disk.
func VerifyArchitectureCatalogDrift(catalog *ArchitectureTopologyCatalog, rt *Runtime, adrDir string) error {
	if catalog == nil {
		return fmt.Errorf("catalog is nil")
	}

	wantBoundaries := []BoundaryID{
		BoundaryGenerativeUI,
		BoundaryReasoningGuard,
		BoundaryIdentity3LO,
		BoundaryPlatformGovernance,
		BoundaryCrossAgentA2A,
		BoundarySandboxEgress,
	}
	gotBoundaries := make([]BoundaryID, 0, len(catalog.Boundaries))
	for _, b := range catalog.Boundaries {
		gotBoundaries = append(gotBoundaries, b.ID)
	}
	if !reflect.DeepEqual(gotBoundaries, wantBoundaries) {
		return fmt.Errorf("boundary drift: catalog has %v, want %v", gotBoundaries, wantBoundaries)
	}

	pluginRT := rt
	if pluginRT == nil {
		pluginRT = &Runtime{}
	}
	wantCallbacks := activePluginCallbacksFromConfig(pluginRT.securityPluginConfig())
	gotCallbacks := make([]string, 0, len(catalog.PluginCallbacks))
	for _, cb := range catalog.PluginCallbacks {
		gotCallbacks = append(gotCallbacks, cb.Name)
	}
	if !reflect.DeepEqual(gotCallbacks, wantCallbacks) {
		return fmt.Errorf("plugin callback drift: catalog has %v, securityPluginConfig() has %v", gotCallbacks, wantCallbacks)
	}

	wantTools := CanonicalGovernedToolNames()
	if rt != nil {
		wantTools = rt.RegisteredGovernedTools()
	}
	gotTools := make([]string, 0, len(catalog.Tools))
	for _, t := range catalog.Tools {
		gotTools = append(gotTools, t.Name)
	}
	if !reflect.DeepEqual(gotTools, wantTools) {
		return fmt.Errorf("governed tool drift: catalog has %v, want %v", gotTools, wantTools)
	}

	wantScenarios := []ScenarioID{
		Scenario01PromptInjectionAndPII,
		Scenario02ConfusedDeputy3LO,
		Scenario03AgentGatewayAndStepUp,
		Scenario04AttenuatedA2ASandbox,
		Scenario05FullChainZeroTrust,
	}
	gotScenarios := make([]ScenarioID, 0, len(catalog.Scenarios))
	for _, s := range catalog.Scenarios {
		gotScenarios = append(gotScenarios, s.ID)
	}
	if !reflect.DeepEqual(gotScenarios, wantScenarios) {
		return fmt.Errorf("scenario drift: catalog has %v, want %v", gotScenarios, wantScenarios)
	}

	validNodes := map[string]bool{}
	for _, n := range catalog.ContextNodes {
		validNodes[n.ID] = true
	}
	for _, b := range catalog.Boundaries {
		validNodes[string(b.ID)] = true
	}
	validEdges := map[string]bool{}
	for _, e := range catalog.Edges {
		if !validNodes[e.From] || !validNodes[e.To] {
			return fmt.Errorf("edge %q references unknown node (%q -> %q)", e.ID, e.From, e.To)
		}
		validEdges[e.ID] = true
	}
	for _, sc := range catalog.Scenarios {
		for _, traj := range []ScenarioPostureTrajectory{sc.Blue, sc.Red} {
			if len(traj.Pulses) == 0 {
				return fmt.Errorf("scenario %s (%s) has zero pulses", sc.ID, traj.Posture)
			}
			for _, p := range traj.Pulses {
				if !validEdges[p.EdgeID] || !validNodes[p.From] || !validNodes[p.To] {
					return fmt.Errorf("scenario %s (%s) pulse %d has invalid edge/node (%s: %s -> %s)", sc.ID, traj.Posture, p.Step, p.EdgeID, p.From, p.To)
				}
			}
		}
	}

	if err := verifyTopologyGeometryAndSummaries(catalog); err != nil {
		return err
	}

	if strings.TrimSpace(adrDir) != "" {
		matches, err := filepath.Glob(filepath.Join(adrDir, "[0-9][0-9][0-9][0-9]-*.md"))
		if err != nil {
			return fmt.Errorf("glob ADR directory %s: %w", adrDir, err)
		}
		sort.Strings(matches)
		if len(matches) == 0 {
			return fmt.Errorf("zero ADR files matched in %s", adrDir)
		}

		type parsedDiskADR struct {
			number   string
			slug     string
			fileName string
			title    string
			status   string
		}
		var acceptedDiskADRs []parsedDiskADR
		for _, fullPath := range matches {
			fileName := filepath.Base(fullPath)
			trimmed := strings.TrimSuffix(fileName, ".md")
			parts := strings.SplitN(trimmed, "-", 2)
			if len(parts) != 2 {
				return fmt.Errorf("malformed ADR filename %q", fileName)
			}
			wantNum, wantSlug := parts[0], parts[1]

			rawBytes, readErr := os.ReadFile(fullPath)
			if readErr != nil {
				return fmt.Errorf("read ADR %s: %w", fileName, readErr)
			}
			diskTitle, diskStatus, parseErr := parseADRMarkdownMetadata(string(rawBytes), wantNum)
			if parseErr != nil {
				return fmt.Errorf("parse ADR %s: %w", fileName, parseErr)
			}
			if strings.EqualFold(diskStatus, "Accepted") {
				acceptedDiskADRs = append(acceptedDiskADRs, parsedDiskADR{
					number:   wantNum,
					slug:     wantSlug,
					fileName: fileName,
					title:    diskTitle,
					status:   "Accepted",
				})
			}
		}

		if len(catalog.ADRs) != len(acceptedDiskADRs) {
			return fmt.Errorf("ADR count/status drift: catalog has %d Accepted ADRs, disk has %d Accepted ADRs in %s", len(catalog.ADRs), len(acceptedDiskADRs), adrDir)
		}
		for i, diskADR := range acceptedDiskADRs {
			got := catalog.ADRs[i]
			if got.Number != diskADR.number || got.Slug != diskADR.slug {
				return fmt.Errorf("ADR[%d] drift: catalog has (%s, %s), disk has (%s, %s)", i, got.Number, got.Slug, diskADR.number, diskADR.slug)
			}
			if got.FileName != "" && got.FileName != diskADR.fileName {
				return fmt.Errorf("ADR[%d] fileName drift: catalog has %q, disk has %q", i, got.FileName, diskADR.fileName)
			}
			gotStatus := strings.TrimSpace(got.Status)
			if gotStatus == "" {
				gotStatus = "Accepted"
			}
			if !strings.EqualFold(gotStatus, diskADR.status) {
				return fmt.Errorf("ADR %s-%s status drift: catalog has %q, disk has %q", got.Number, got.Slug, gotStatus, diskADR.status)
			}
			if normalizeADRTitle(got.Title) != diskADR.title {
				return fmt.Errorf("ADR %s-%s H1 title drift: catalog has %q, disk has %q", got.Number, got.Slug, normalizeADRTitle(got.Title), diskADR.title)
			}
			if strings.TrimSpace(got.Title) == "" || strings.TrimSpace(got.Summary) == "" || len(got.PrimaryBoundaries) == 0 {
				return fmt.Errorf("ADR %s-%s has empty title, summary, or primaryBoundaries", got.Number, got.Slug)
			}
		}
	}

	return nil
}

var adrHeadingNumberPrefixRe = regexp.MustCompile(`^([0-9]+)\.\s*`)

func normalizeADRTitle(raw string) string {
	cleaned := strings.ReplaceAll(strings.TrimSpace(raw), "`", "")
	return strings.Join(strings.Fields(cleaned), " ")
}

func parseADRMarkdownMetadata(markdown string, expectedNum string) (title string, status string, err error) {
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	var foundH1 bool
	var inStatusSection bool
	var explicitStatusSection bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !foundH1 && strings.HasPrefix(trimmed, "# ") {
			foundH1 = true
			heading := strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
			if m := adrHeadingNumberPrefixRe.FindStringSubmatch(heading); len(m) == 2 {
				hNum, err1 := strconv.Atoi(m[1])
				fNum, err2 := strconv.Atoi(expectedNum)
				if err1 == nil && err2 == nil && hNum != fNum {
					return "", "", fmt.Errorf("H1 number %d does not match filename number %s", hNum, expectedNum)
				}
				heading = adrHeadingNumberPrefixRe.ReplaceAllString(heading, "")
			}
			title = normalizeADRTitle(heading)
			continue
		}
		if strings.HasPrefix(trimmed, "## ") {
			if strings.EqualFold(trimmed, "## Status") {
				inStatusSection = true
				explicitStatusSection = true
			} else {
				inStatusSection = false
			}
			continue
		}
		if inStatusSection && trimmed != "" {
			status = strings.Trim(trimmed, "`* ")
			inStatusSection = false
		}
	}

	if !foundH1 || title == "" {
		return "", "", fmt.Errorf("missing H1 heading")
	}
	if explicitStatusSection {
		if status == "" {
			return "", "", fmt.Errorf("empty ## Status section")
		}
		return title, status, nil
	}
	return title, "Accepted", nil
}

func verifyTopologyGeometryAndSummaries(catalog *ArchitectureTopologyCatalog) error {
	if catalog.ViewBoxWidth <= 0 || catalog.ViewBoxHeight <= 0 {
		return fmt.Errorf("invalid viewBox (%dx%d)", catalog.ViewBoxWidth, catalog.ViewBoxHeight)
	}
	type rect struct {
		id   string
		zone string
		x    int
		y    int
		w    int
		h    int
	}
	rects := make([]rect, 0, len(catalog.ContextNodes)+len(catalog.Boundaries))
	for _, cn := range catalog.ContextNodes {
		if strings.TrimSpace(cn.NodeTag) == "" {
			return fmt.Errorf("context node %q has empty nodeTag", cn.ID)
		}
		zone := cn.Zone
		if zone == "" {
			zone = "INGRESS"
		}
		rects = append(rects, rect{id: cn.ID, zone: zone, x: cn.X, y: cn.Y, w: cn.Width, h: cn.Height})
	}
	allowedZones := map[string]bool{
		"INGRESS":          true,
		"REASONING_CORE":   true,
		"EXECUTION_PLANES": true,
	}
	for _, b := range catalog.Boundaries {
		if !allowedZones[b.Zone] {
			return fmt.Errorf("boundary %s has invalid zone %q", b.ID, b.Zone)
		}
		if strings.TrimSpace(b.NodeTag) == "" || strings.TrimSpace(b.BlueSummary) == "" || strings.TrimSpace(b.RedSummary) == "" {
			return fmt.Errorf("boundary %s missing nodeTag, blueSummary, or redSummary", b.ID)
		}
		rects = append(rects, rect{id: string(b.ID), zone: b.Zone, x: b.X, y: b.Y, w: b.Width, h: b.Height})
	}
	for i, a := range rects {
		if a.w <= 0 || a.h <= 0 || a.x < 0 || a.y < 0 || a.x+a.w > catalog.ViewBoxWidth || a.y+a.h > catalog.ViewBoxHeight {
			return fmt.Errorf("node %s (%d,%d,%d,%d) out of viewBox (%dx%d)", a.id, a.x, a.y, a.w, a.h, catalog.ViewBoxWidth, catalog.ViewBoxHeight)
		}
		for j := i + 1; j < len(rects); j++ {
			b := rects[j]
			if a.x < b.x+b.w && b.x < a.x+a.w && a.y < b.y+b.h && b.y < a.y+a.h {
				return fmt.Errorf("topology nodes %s and %s overlap", a.id, b.id)
			}
		}
	}

	zoneSpan := func(z string) (int, int) {
		minX, maxX := catalog.ViewBoxWidth, 0
		for _, r := range rects {
			if r.zone != z {
				continue
			}
			if r.x < minX {
				minX = r.x
			}
			if r.x+r.w > maxX {
				maxX = r.x + r.w
			}
		}
		return minX, maxX
	}
	_, inMax := zoneSpan("INGRESS")
	coreMin, coreMax := zoneSpan("REASONING_CORE")
	execMin, _ := zoneSpan("EXECUTION_PLANES")
	if coreMin-inMax < 52 || execMin-coreMax < 52 {
		return fmt.Errorf("insufficient 3-zone horizontal separation: ingress->core=%dpx, core->exec=%dpx (want >=52px)", coreMin-inMax, execMin-coreMax)
	}

	for _, e := range catalog.Edges {
		x0, y0 := float64(e.FromX), float64(e.FromY)
		x3, y3 := float64(e.ToX), float64(e.ToY)
		dx := math.Max(24, math.Abs(x3-x0)*0.48)
		sign := 1.0
		if x3 < x0 {
			sign = -1.0
		}
		cx1, cy1 := x0+sign*dx, y0
		cx2, cy2 := x3-sign*dx, y3
		if e.CurveOffsetY != 0 {
			railY := math.Max(y0, y3) + float64(e.CurveOffsetY)
			cx1, cy1 = x0, railY
			cx2, cy2 = x3, railY
		}
		for step := 5; step < 195; step++ {
			tVal := float64(step) / 200.0
			u := 1 - tVal
			px := u*u*u*x0 + 3*u*u*tVal*cx1 + 3*u*tVal*tVal*cx2 + tVal*tVal*tVal*x3
			py := u*u*u*y0 + 3*u*u*tVal*cy1 + 3*u*tVal*tVal*cy2 + tVal*tVal*tVal*y3
			if px < 0 || px > float64(catalog.ViewBoxWidth) || py < 0 || py > float64(catalog.ViewBoxHeight) {
				return fmt.Errorf("edge %s curve escapes viewBox at (%.1f, %.1f)", e.ID, px, py)
			}
			for _, r := range rects {
				if r.id == e.From || r.id == e.To {
					continue
				}
				if px >= float64(r.x) && px <= float64(r.x+r.w) && py >= float64(r.y) && py <= float64(r.y+r.h) {
					return fmt.Errorf("edge %s intersects intermediate node %s at (%.1f, %.1f)", e.ID, r.id, px, py)
				}
			}
		}
	}
	return nil
}

func canonicalBoundaryCatalogNodes() []BoundaryCatalogNode {
	return []BoundaryCatalogNode{
		{
			ID:                   BoundaryGenerativeUI,
			Code:                 "B1",
			Zone:                 "INGRESS",
			Title:                "Presentation & Generative UI Boundary",
			ShortLabel:           "B1 · A2UI v0.9 & Step-Up",
			Subtitle:             "Schema-validated cards + adk_request_confirmation",
			NodeTag:              "A2UI · Step-Up",
			X:                    220,
			Y:                    144,
			Width:                196,
			Height:               72,
			ShieldKey:            "stepUpAndA2UICatalogEnabled",
			ShieldName:           "Step-Up Confirmation & A2UI Catalog",
			ComponentName:        "A2UI v0.9 Declarative Surface + ADK Go v2 toolconfirmation (adk_request_confirmation)",
			BlueSummary:          "Pauses mutating tool calls for explicit Operator Step-Up Confirmation and sanitizes Declarative UI Cards against the 6-component A2UI v0.9 schema.",
			RedSummary:           "Mutating pull requests execute without Operator approval and unvalidated script markup passes directly into rendered card payloads.",
			RedExploitMode:       "State-mutating create_github_pull_request executes immediately without Operator approval, and raw <script> XSS payloads pass into rendered card fields.",
			BlueDefenseMechanism: "Pauses state-mutating tool invocations with a signed StepUpConfirmationCard (adk_request_confirmation) until the Operator approves, and enforces strict 6-component A2UI v0.9 schema sanitization.",
			GovernedTools: []string{
				"create_github_pull_request",
			},
			ADRNumbers: []string{"0001", "0002", "0006", "0008", "0009", "0011"},
		},
		{
			ID:                   BoundaryReasoningGuard,
			Code:                 "B2",
			Zone:                 "REASONING_CORE",
			Title:                "In-Loop Reasoning & Content Guard Boundary",
			ShortLabel:           "B2 · Triage Orchestrator & Guard",
			Subtitle:             "ADK Go v2 + Model Armor + Cloud SDP",
			NodeTag:              "ADK v2 · Model Armor",
			X:                    472,
			Y:                    144,
			Width:                216,
			Height:               72,
			ShieldKey:            "promptScreenEnabled,piiRedactorEnabled",
			ShieldName:           "Prompt Screen + In-Flight PII Redactor",
			ComponentName:        "Gemini Enterprise Agent Platform (ADK Go v2 llmagent) + Model Armor v1 + Cloud SDP DeidentifyContent",
			BlueSummary:          "Hard-blocks indirect prompt injection via Model Armor while masking SSNs, emails, phones, and API keys in-flight with Cloud SDP.",
			RedSummary:           "Adversarial instructions inside untrusted emails hijack model reasoning and leak raw customer PII into downstream ticket comments.",
			RedExploitMode:       "Indirect prompt injection inside customer Gmail threads hijacks model reasoning toward https://evil.example.com, while raw customer SSN (123-45-6789) and API keys leak into LLM context and Jira comments.",
			BlueDefenseMechanism: "Hard-blocks Prompt Injection, Jailbreak, and Malicious URI matches in BeforeModel and AfterTool callbacks, while masking SSN, phone, email, and API keys in-flight ([REDACTED_SSN], [REDACTED_API_KEY]) and continuing safely on IsSdpOnlyBlock.",
			GovernedTools: []string{
				"read_gmail_escalation",
				"delegate_sandbox_test",
				"create_github_pull_request",
			},
			ADRNumbers: []string{"0002", "0005", "0007", "0008", "0009"},
		},
		{
			ID:                   BoundaryIdentity3LO,
			Code:                 "B3",
			Zone:                 "EXECUTION_PLANES",
			Title:                "Identity & Per-User Multi-IdP Token Brokering",
			ShortLabel:           "B3 · OAuth 2.0 S256 PKCE Vault",
			Subtitle:             "15m Ephemeral TokenBroker + Persona Session Partition",
			NodeTag:              "S256 PKCE · 15m Vault",
			X:                    744,
			Y:                    40,
			Width:                436,
			Height:               72,
			ShieldKey:            "tokenBrokerEnabled",
			ShieldName:           "Token Broker (Per-User 3LO PKCE)",
			ComponentName:        "ADK Go v2 auth.Transport + OAuth 2.0 S256 PKCE Ephemeral 15m In-Memory TokenBroker Vault (Google Workspace SSO, Jira, GitHub)",
			BlueSummary:          "Brokers per-persona 15-minute S256 PKCE OAuth grants on outbound wire transport and isolates SessionID:Persona conversation partitions.",
			RedSummary:           "Shared over-privileged service credentials and unpartitioned session history expose restricted SecOps records to unauthorized personas.",
			RedExploitMode:       "Confused Deputy privilege escalation: outbound Jira and GitHub requests share an over-privileged service token and unpartitioned session history, leaking restricted SecOps issue SEC-101 to contractor Bob.",
			BlueDefenseMechanism: "Issues RFC 7636 S256 PKCE ConsentChallenges with unified Google Workspace SSO scopes, stores short-lived 15m grants strictly in the backend TokenBroker in-memory vault with automatic TTL pruning (zero browser PATs), injects per-persona tokens via auth.Transport outside LLM context, and isolates SessionID:Persona partitions.",
			GovernedTools: []string{
				"read_gmail_escalation",
				"fetch_jira_issue",
				"fetch_github_advisory",
				"create_github_pull_request",
			},
			ADRNumbers: []string{"0002", "0003", "0007", "0008", "0010", "0012"},
		},
		{
			ID:                   BoundaryPlatformGovernance,
			Code:                 "B4",
			Zone:                 "EXECUTION_PLANES",
			Title:                "Platform Governance & Tool Discovery Boundary",
			ShortLabel:           "B4 · Agent Registry & Gateway UAP",
			Subtitle:             "adk/v2/agentregistry + AGENT_TO_ANYWHERE CEL",
			NodeTag:              "Registry · Gateway UAP",
			X:                    744,
			Y:                    144,
			Width:                436,
			Height:               72,
			ShieldKey:            "stepUpAndA2UICatalogEnabled",
			ShieldName:           "Agent Registry & Unified Access Policy",
			ComponentName:        "Gemini Enterprise Agent Platform Agent Registry (v1alpha) + Agent Gateway AGENT_TO_ANYWHERE UAP (roles/iap.egressor)",
			BlueSummary:          "Discovers governed MCP tools from Agent Registry and enforces Unified Access Policy CEL rules to block destructive cluster mutations.",
			RedSummary:           "Ungoverned MCP endpoints and destructive container.clusters.delete calls execute without catalog verification or per-tool CEL checks.",
			RedExploitMode:       "Ungoverned MCP endpoints and destructive cluster operations (container.clusters.delete) execute without catalog discovery or per-tool CEL authorization.",
			BlueDefenseMechanism: "Discovers governed MCP servers and A2A peers from Agent Registry and evaluates Unified Access Policy CEL rules at BeforeToolCallback, permitting read-only observability (logging.entries.list, container.clusters.get) while hard-blocking container.clusters.delete.",
			GovernedTools: []string{
				"query_cloud_logging",
				"get_gke_cluster",
				"delete_gke_cluster",
			},
			ADRNumbers: []string{"0004", "0006", "0007", "0008", "0010"},
		},
		{
			ID:                   BoundaryCrossAgentA2A,
			Code:                 "B5",
			Zone:                 "EXECUTION_PLANES",
			Title:                "Cross-Agent Federation Boundary",
			ShortLabel:           "B5 · Attenuated A2A v2",
			Subtitle:             "withoutCredentialParts + Peer Screen",
			NodeTag:              "Attenuated A2A v2",
			X:                    744,
			Y:                    248,
			Width:                200,
			Height:               72,
			ShieldKey:            "sandboxEgressMitmEnabled",
			ShieldName:           "Attenuated Delegation (A2A v2)",
			ComponentName:        "ADK Go v2 adka2a/v2 Federation + withoutCredentialParts Credential Scrubber",
			BlueSummary:          "Strips upstream 3LO credential parts before A2A delegation and screens Sandbox Remediator responses through Model Armor on return.",
			RedSummary:           "Unattenuated A2A delegation forwards upstream Operator 3LO tokens to the peer agent and accepts poisoned peer responses unscreened.",
			RedExploitMode:       "Triage Orchestrator forwards upstream Alice/Bob 3LO OAuth tokens inside A2A message parts directly to the untrusted Sandbox Remediator peer.",
			BlueDefenseMechanism: "Scrubs all adk_request_credential parts via withoutCredentialParts before A2A handoff, narrows task scope to repository verification, and routes the peer A2A response back through B2 Model Armor SanitizeUserPrompt.",
			GovernedTools: []string{
				"delegate_sandbox_test",
			},
			ADRNumbers: []string{"0001", "0004", "0006", "0008"},
		},
		{
			ID:                   BoundarySandboxEgress,
			Code:                 "B6",
			Zone:                 "EXECUTION_PLANES",
			Title:                "Compute & Network Sandbox Boundary",
			ShortLabel:           "B6 · gVisor + atenet MITM",
			Subtitle:             "svc/atenet-router -> Actor/remediator-1",
			NodeTag:              "gVisor · atenet MITM",
			X:                    980,
			Y:                    248,
			Width:                200,
			Height:               72,
			ShieldKey:            "sandboxEgressMitmEnabled",
			ShieldName:           "Sandbox Egress MITM (Agent Substrate)",
			ComponentName:        "GKE Sandbox (gVisor) + Agent Substrate svc/atenet-router -> Actor/remediator-1 (SNAPSHOT_FIDELITY_MEMORY Golden Snapshot + EgressPolicy)",
			BlueSummary:          "Executes untrusted tests inside a zero-secret gVisor Actor via svc/atenet-router while EgressPolicy blocks unauthorized outbound domains.",
			RedSummary:           "Malicious repository init() code reads ambient environment tokens and exfiltrates secrets over unrestricted container network egress.",
			RedExploitMode:       "Untrusted go test init() payload reads leaked GITHUB_TOKEN / GOOGLE_OAUTH_TOKEN env vars and exfiltrates os.Environ() over unrestricted egress to https://evil.example.com/exfil.",
			BlueDefenseMechanism: "Auto-bridges POST /sandbox/execute with ate-target-actor: aegis-system/remediator-1 over svc/atenet-router to wake the gVisor Actor from its SNAPSHOT_FIDELITY_MEMORY Golden Snapshot with zero container env secrets, out-of-sandbox atenet GitHub token injection, and EgressPolicy blocking evil.example.com.",
			GovernedTools: []string{
				"delegate_sandbox_test",
			},
			ADRNumbers: []string{"0002", "0004", "0007", "0010", "0013"},
		},
	}
}

func canonicalTopologyEdges() []TopologyEdgeSpec {
	return []TopologyEdgeSpec{
		{
			ID:    "EDGE_BROWSER_B1",
			From:  "OPERATOR_BROWSER",
			To:    string(BoundaryGenerativeUI),
			Label: "Prompt / PKCE / Step-Up",
			FromX: 188,
			FromY: 170,
			ToX:   220,
			ToY:   170,
		},
		{
			ID:    "EDGE_B1_B2",
			From:  string(BoundaryGenerativeUI),
			To:    string(BoundaryReasoningGuard),
			Label: "ADK Runner Loop",
			FromX: 416,
			FromY: 170,
			ToX:   472,
			ToY:   170,
		},
		{
			ID:    "EDGE_B2_B3",
			From:  string(BoundaryReasoningGuard),
			To:    string(BoundaryIdentity3LO),
			Label: "auth.Transport 3LO",
			FromX: 688,
			FromY: 158,
			ToX:   744,
			ToY:   66,
		},
		{
			ID:    "EDGE_B3_B2",
			From:  string(BoundaryIdentity3LO),
			To:    string(BoundaryReasoningGuard),
			Label: "Untrusted 3LO Output",
			FromX: 744,
			FromY: 88,
			ToX:   688,
			ToY:   170,
		},
		{
			ID:    "EDGE_B2_B4",
			From:  string(BoundaryReasoningGuard),
			To:    string(BoundaryPlatformGovernance),
			Label: "Gateway MCP + UAP CEL",
			FromX: 688,
			FromY: 182,
			ToX:   744,
			ToY:   180,
		},
		{
			ID:    "EDGE_B2_B5",
			From:  string(BoundaryReasoningGuard),
			To:    string(BoundaryCrossAgentA2A),
			Label: "Attenuated A2A Task",
			FromX: 688,
			FromY: 202,
			ToX:   744,
			ToY:   284,
		},
		{
			ID:    "EDGE_B5_B6",
			From:  string(BoundaryCrossAgentA2A),
			To:    string(BoundarySandboxEgress),
			Label: "svc/atenet-router",
			FromX: 944,
			FromY: 284,
			ToX:   980,
			ToY:   284,
		},
		{
			ID:           "EDGE_B6_B2",
			From:         string(BoundarySandboxEgress),
			To:           string(BoundaryReasoningGuard),
			Label:        "Peer Output Screen",
			FromX:        1080,
			FromY:        320,
			ToX:          560,
			ToY:          216,
			CurveOffsetY: 64,
		},
		{
			ID:    "EDGE_B2_B1",
			From:  string(BoundaryReasoningGuard),
			To:    string(BoundaryGenerativeUI),
			Label: "A2UI Card / Interrupt",
			FromX: 472,
			FromY: 192,
			ToX:   416,
			ToY:   192,
		},
		{
			ID:    "EDGE_B1_BROWSER",
			From:  string(BoundaryGenerativeUI),
			To:    "OPERATOR_BROWSER",
			Label: "SSE TurnStreamEvent",
			FromX: 220,
			FromY: 192,
			ToX:   188,
			ToY:   192,
		},
	}
}

func mustFormatSampleSSEFrame(ev TurnStreamEvent) string {
	raw, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func canonicalPluginCallbackCatalogNodes() []PluginCallbackCatalogNode {
	sampleTS := time.Date(2026, 10, 28, 18, 0, 0, 0, time.UTC)
	allTools := CanonicalGovernedToolNames()

	return []PluginCallbackCatalogNode{
		{
			StageIndex:           1,
			Name:                 "BeforeRun",
			ExecutionLabel:       "BeforeRun -> Session Partition",
			RoleSummary:          "Binds per-turn SecurityPosture (5 shields), active Persona, and Persona Session Partition key (SessionID:Persona) into ADK session state before the invocation starts.",
			ShortCircuitBehavior: "Initializes invocation state and emits turn.started over SSE; passes control into the runner loop unless invocation context is canceled.",
			GovernedBoundaries: []BoundaryID{
				BoundaryIdentity3LO,
				BoundaryReasoningGuard,
			},
			GovernedTools:           allTools,
			EmittedStreamEventTypes: []TurnStreamEventType{TurnStreamEventStarted},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventStarted,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario05FullChainZeroTrust,
			}),
		},
		{
			StageIndex:           2,
			Name:                 "BeforeModel",
			ExecutionLabel:       "BeforeModel -> Prompt Screen & SDP",
			RoleSummary:          "Screens Operator prompts with Model Armor (SanitizeUserPrompt) and masks incidental PII in-place via Cloud SDP (DeidentifyContent) before Model.GenerateContent executes.",
			ShortCircuitBehavior: "Returns a synthetic *model.LLMResponse{TurnComplete: true} to hard-block Model.GenerateContent when Prompt Screen detects prompt injection or malicious URIs; rewrites llmRequest.Contents in-place on IsSdpOnlyBlock.",
			GovernedBoundaries: []BoundaryID{
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
			},
			GovernedTools: allTools,
			EmittedStreamEventTypes: []TurnStreamEventType{
				TurnStreamEventBoundaryStep,
				TurnStreamEventA2UICard,
			},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventBoundaryStep,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario01PromptInjectionAndPII,
				Step: &BoundaryTraceEvent{
					Order:      1,
					Boundary:   BoundaryReasoningGuard,
					Shield:     "PII Redactor (Cloud SDP)",
					Component:  "CloudSDP DeidentifyContent (BeforeModelCallback)",
					Action:     "DeidentifyUserPrompt(operator_prompt)",
					Verdict:    VerdictRedacted,
					Provenance: ProvenanceLive,
					Detail:     "SDP-only match (US_SOCIAL_SECURITY_NUMBER, GCP_API_KEY): redacted sensitive PII in-place before Model.GenerateContent",
					Timestamp:  sampleTS,
				},
			}),
		},
		{
			StageIndex:           3,
			Name:                 "BeforeTool",
			ExecutionLabel:       "BeforeTool -> UAP, PKCE & Step-Up",
			RoleSummary:          "Evaluates Agent Registry + Agent Gateway UAP CEL rules, checks TokenBroker for active 15m S256 PKCE 3LO grants, and pauses mutating tools via ctx.RequestConfirmation (adk_request_confirmation).",
			ShortCircuitBehavior: "Short-circuits tool.Run with BLOCKED_BY_UAP on container.clusters.delete, CONSENT_REQUIRED (SkipSummarization=true) when a 3LO PKCE grant is missing or expired, or APPROVAL_REQUIRED on create_github_pull_request.",
			GovernedBoundaries: []BoundaryID{
				BoundaryPlatformGovernance,
				BoundaryIdentity3LO,
				BoundaryGenerativeUI,
			},
			GovernedTools: []string{
				"read_gmail_escalation",
				"query_cloud_logging",
				"get_gke_cluster",
				"delete_gke_cluster",
				"fetch_jira_issue",
				"fetch_github_advisory",
				"create_github_pull_request",
			},
			EmittedStreamEventTypes: []TurnStreamEventType{
				TurnStreamEventBoundaryStep,
				TurnStreamEventA2UICard,
			},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventBoundaryStep,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario03AgentGatewayAndStepUp,
				Step: &BoundaryTraceEvent{
					Order:      2,
					Boundary:   BoundaryPlatformGovernance,
					Shield:     "Agent Gateway UAP (roles/iap.egressor)",
					Component:  "AGENT_TO_ANYWHERE CEL Enforcer",
					Action:     "container.clusters.delete",
					Verdict:    VerdictBlocked,
					Provenance: ProvenanceLive,
					Detail:     "Denied destructive MCP tool container.clusters.delete via Unified Access Policy CEL rule",
					Timestamp:  sampleTS,
				},
			}),
		},
		{
			StageIndex:           4,
			Name:                 "AfterTool",
			ExecutionLabel:       "AfterTool -> Output & Peer Guard",
			RoleSummary:          "Screens untrusted Gmail threads, enforces 403/404 3LO ACL boundaries, and inspects returned Sandbox Remediator A2A outputs from Actor/remediator-1 before tool results enter session history.",
			ShortCircuitBehavior: "Replaces poisoned tool or peer A2A outputs with sanitized summaries or halts the turn with ThreatInterceptCard / AclDenialCard (SkipSummarization=true) before Gemini sees untrusted instructions.",
			GovernedBoundaries: []BoundaryID{
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundaryCrossAgentA2A,
				BoundarySandboxEgress,
			},
			GovernedTools: []string{
				"read_gmail_escalation",
				"fetch_jira_issue",
				"fetch_github_advisory",
				"delegate_sandbox_test",
				"create_github_pull_request",
			},
			EmittedStreamEventTypes: []TurnStreamEventType{
				TurnStreamEventWireRecord,
				TurnStreamEventBoundaryStep,
				TurnStreamEventA2UICard,
			},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventWireRecord,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario04AttenuatedA2ASandbox,
				Record: &OutboundWireRecord{
					Provider:          ProviderGitHub,
					ToolName:          "substrate.atenet.actor_execute",
					Method:            http.MethodPost,
					URL:               "http://atenet-router.ate-system.svc.cluster.local/sandbox/execute",
					AuthHeaderPresent: false,
					AuthPrincipal:     "attenuated-a2a-zero-3lo",
					StatusCode:        http.StatusOK,
					Provenance:        ProvenanceLive,
					Headers: map[string]string{
						"ate-target-actor": "aegis-system/remediator-1",
					},
				},
			}),
		},
		{
			StageIndex:           5,
			Name:                 "AfterModel",
			ExecutionLabel:       "AfterModel -> A2UI Schema Guard",
			RoleSummary:          "Re-validates all queued Declarative UI Cards against the 6-component A2UI v0.9 catalog and strips executable HTML/script tags from model-synthesized fields.",
			ShortCircuitBehavior: "Sanitizes card payloads in-place via ValidateAndSanitizeA2UICard so unvalidated markup never reaches the browser surface.",
			GovernedBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
			},
			GovernedTools: allTools,
			EmittedStreamEventTypes: []TurnStreamEventType{
				TurnStreamEventTextDelta,
				TurnStreamEventA2UICard,
			},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventA2UICard,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario04AttenuatedA2ASandbox,
				Card: &A2UICard{
					SurfaceID: "card-sandbox-s4",
					MimeType:  "application/json+a2ui",
					Version:   "0.9",
					Type:      CardSandboxExecution,
					Title:     "Sandbox Remediator Verification Passed in gVisor",
					Severity:  "SUCCESS",
					Body:      "Executed go test inside Actor/remediator-1 (4.19.0-gvisor) with 0 env secrets; atenet blocked evil.example.com.",
				},
			}),
		},
		{
			StageIndex:           6,
			Name:                 "OnEvent",
			ExecutionLabel:       "OnEvent -> CallID Bind & SSE Flush",
			RoleSummary:          "Captures native ADK FunctionCall IDs on adk_request_confirmation interrupts for stateless Step-Up resume and flushes terminal TurnStreamEvent frames to the SSE sink.",
			ShortCircuitBehavior: "Records StepUpConfirmation.CallID + ADKSessionID without mutating session history and completes the progressive SSE stream with turn.completed.",
			GovernedBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
			},
			GovernedTools: []string{
				"create_github_pull_request",
			},
			EmittedStreamEventTypes: []TurnStreamEventType{
				TurnStreamEventA2UICard,
				TurnStreamEventCompleted,
			},
			SampleSSEFrame: mustFormatSampleSSEFrame(TurnStreamEvent{
				Type:       TurnStreamEventCompleted,
				SessionID:  "arena-live-session",
				Persona:    PersonaAlice,
				ScenarioID: Scenario03AgentGatewayAndStepUp,
				Turn: &TurnResult{
					SessionID:     "arena-live-session",
					ADKSessionID:  "arena-live-session:alice",
					Persona:       PersonaAlice,
					ScenarioID:    Scenario03AgentGatewayAndStepUp,
					Posture:       AllBluePosture(),
					Outcome:       OutcomeApprovalRequired,
					AssistantText: "Paused create_github_pull_request: waiting for Operator Step-Up Confirmation.",
					Cards:         []A2UICard{},
					BoundaryTrace: []BoundaryTraceEvent{},
				},
			}),
		},
	}
}

func canonicalToolCatalogEntries() []ToolCatalogEntry {
	return []ToolCatalogEntry{
		{
			Name:            "read_gmail_escalation",
			WireOperation:   "gmail.users.messages.get",
			PrimaryBoundary: BoundaryReasoningGuard,
			Provider:        ProviderGoogleGmail,
			ExternalSource:  SourceGoogleGmail,
			StepUpPolicy:    "3LO S256 PKCE + AfterTool Model Armor & Cloud SDP",
			Description:     "Reads customer P0 escalation emails via Google Workspace SSO 3LO and screens untrusted bodies for prompt injection and PII.",
		},
		{
			Name:            "query_cloud_logging",
			WireOperation:   "logging.entries.list",
			PrimaryBoundary: BoundaryPlatformGovernance,
			Provider:        ProviderGCPIAM,
			ExternalSource:  SourceGCPObservability,
			StepUpPolicy:    "Read-Only Permitted by Agent Gateway UAP CEL",
			Description:     "Queries HTTP 502 checkout error logs through governed Cloud Logging MCP after Agent Registry discovery.",
		},
		{
			Name:            "get_gke_cluster",
			WireOperation:   "container.clusters.get",
			PrimaryBoundary: BoundaryPlatformGovernance,
			Provider:        ProviderGCPIAM,
			ExternalSource:  SourceGCPObservability,
			StepUpPolicy:    "Read-Only Permitted by Agent Gateway UAP CEL",
			Description:     "Inspects GKE cluster and WorkerPool status through governed GKE MCP with Unified Access Policy verification.",
		},
		{
			Name:            "delete_gke_cluster",
			WireOperation:   "container.clusters.delete",
			PrimaryBoundary: BoundaryPlatformGovernance,
			Provider:        ProviderGCPIAM,
			ExternalSource:  SourceGCPObservability,
			StepUpPolicy:    "Hard-Blocked by Agent Gateway UAP CEL (!isReadOnly)",
			Description:     "Destructive cluster deletion tool denied at BeforeToolCallback by Agent Gateway AGENT_TO_ANYWHERE CEL policy.",
		},
		{
			Name:            "fetch_jira_issue",
			WireOperation:   "jira_get_issue",
			PrimaryBoundary: BoundaryIdentity3LO,
			Provider:        ProviderAtlassianJira,
			ExternalSource:  SourceAtlassianJira,
			StepUpPolicy:    "Per-Persona 3LO S256 PKCE TokenBroker (15m TTL)",
			Description:     "Fetches Jira issues (SEC-101 / PUB-202) with Alice or Bob 3LO token injected on auth.Transport outside LLM context.",
		},
		{
			Name:            "fetch_github_advisory",
			WireOperation:   "github_get_security_advisory",
			PrimaryBoundary: BoundaryIdentity3LO,
			Provider:        ProviderGitHub,
			ExternalSource:  SourceGitHub,
			StepUpPolicy:    "Per-Persona 3LO S256 PKCE TokenBroker (15m TTL)",
			Description:     "Fetches repository security advisories and issues from Target Repository using per-persona 3LO credentials.",
		},
		{
			Name:            "delegate_sandbox_test",
			WireOperation:   "POST /sandbox/execute (ate-target-actor)",
			PrimaryBoundary: BoundarySandboxEgress,
			Provider:        ProviderGitHub,
			ExternalSource:  SourceSubstrateSandbox,
			StepUpPolicy:    "Attenuated A2A Scrub + gVisor Actor/remediator-1 MITM",
			Description:     "Strips 3LO credentials over A2A v2 and dispatches untrusted go test to gVisor Actor/remediator-1 via svc/atenet-router.",
		},
		{
			Name:            "create_github_pull_request",
			WireOperation:   "POST /repos/{owner}/{repo}/pulls",
			PrimaryBoundary: BoundaryGenerativeUI,
			Provider:        ProviderGitHub,
			ExternalSource:  SourceGitHub,
			StepUpPolicy:    "Mandatory Step-Up Confirmation (adk_request_confirmation)",
			Description:     "Opens remediation Pull Request and sanitized Jira comment only after explicit Operator Step-Up approval.",
		},
	}
}

func canonicalScenarioSimulationSpecs() []ScenarioSimulationSpec {
	return []ScenarioSimulationSpec{
		{
			ID:             Scenario01PromptInjectionAndPII,
			Title:          "Indirect Prompt Injection & In-Flight Cloud SDP Redaction",
			Subtitle:       "B2 Model Armor blocks adversarial HTML instructions while Cloud SDP masks SSN & API keys in-flight.",
			DefaultPersona: PersonaAlice,
			PrimaryBoundaries: []BoundaryID{
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundaryGenerativeUI,
			},
			Blue: ScenarioPostureTrajectory{
				Posture:         "BLUE",
				Outcome:         OutcomeBlocked,
				TerminalVerdict: PulseVerdictBlocked,
				Summary:         "TokenBroker fetches the Gmail thread via S256 PKCE 3LO; AfterToolCallback redacts customer SSN/API keys via Cloud SDP and Model Armor hard-blocks the embedded prompt injection before Gemini acts on it.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Triage Request", Detail: "Alice initiates P0 Gmail escalation triage"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "BeforeModel Screen", Detail: "Operator prompt passes Model Armor screening"},
					{Step: 3, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictPass, Label: "Gmail 3LO PKCE", Detail: "auth.Transport attaches Alice 15m Workspace SSO token"},
					{Step: 4, EdgeID: "EDGE_B3_B2", From: string(BoundaryIdentity3LO), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictRedacted, Label: "Cloud SDP Mask + Block", Detail: "Cloud SDP masks [REDACTED_SSN] & Model Armor blocks hidden injection"},
					{Step: 5, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictBlocked, Label: "ThreatInterceptCard", Detail: "Turn halted with schema-validated ThreatInterceptCard"},
					{Step: 6, EdgeID: "EDGE_B1_BROWSER", From: string(BoundaryGenerativeUI), To: "OPERATOR_BROWSER", Verdict: PulseVerdictBlocked, Label: "SSE Blocked Verdict", Detail: "Zero PII or exfiltration reaches LLM or Jira"},
				},
			},
			Red: ScenarioPostureTrajectory{
				Posture:         "RED",
				Outcome:         OutcomeExploitedRed,
				TerminalVerdict: PulseVerdictExfiltrated,
				Summary:         "With Prompt Screen and PII Redactor disabled, the hidden HTML instruction hijacks the reasoning loop and leaks raw customer SSN (123-45-6789) and API keys to Jira and https://evil.example.com.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Triage Request", Detail: "Operator sends Gmail triage prompt in Red posture"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "Unscreened Loop", Detail: "Prompt Screen & Cloud SDP disabled"},
					{Step: 3, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictExfiltrated, Label: "Shared Static Token", Detail: "Fetches poisoned Gmail body without per-user vault"},
					{Step: 4, EdgeID: "EDGE_B3_B2", From: string(BoundaryIdentity3LO), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "Injection + Raw SSN", Detail: "Hidden override + 123-45-6789 enter model context unmasked"},
					{Step: 5, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictExfiltrated, Label: "PII & Token Leak", Detail: "Exfiltrates customer PII and service credentials"},
				},
			},
		},
		{
			ID:             Scenario02ConfusedDeputy3LO,
			Title:          "Confused Deputy Prevention & Per-User 3LO PKCE Vault",
			Subtitle:       "B3 isolates SessionID:Persona partitions and injects Bob vs. Alice S256 PKCE tokens on auth.Transport.",
			DefaultPersona: PersonaBob,
			PrimaryBoundaries: []BoundaryID{
				BoundaryIdentity3LO,
				BoundaryReasoningGuard,
				BoundaryGenerativeUI,
			},
			Blue: ScenarioPostureTrajectory{
				Posture:         "BLUE",
				Outcome:         OutcomeBlocked,
				TerminalVerdict: PulseVerdictBlocked,
				Summary:         "Contractor Bob runs inside isolated session partition SessionID:bob; TokenBroker attaches Bob's 15m PKCE 3LO token on auth.Transport, and Jira/GitHub enforce HTTP 403 ACL denial on SEC-101.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Persona: Bob", Detail: "External contractor Bob requests restricted SEC-101"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "Partition SessionID:bob", Detail: "BeforeRun isolates Bob from Alice's session history"},
					{Step: 3, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictPass, Label: "Bob 3LO PKCE Token", Detail: "auth.Transport injects Bob's scoped 15m OAuth token"},
					{Step: 4, EdgeID: "EDGE_B3_B2", From: string(BoundaryIdentity3LO), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictBlocked, Label: "HTTP 403 ACL Denied", Detail: "Upstream Jira/GitHub reject Bob on restricted SEC-101"},
					{Step: 5, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictBlocked, Label: "AclDenialCard", Detail: "Emits schema-validated AclDenialCard"},
					{Step: 6, EdgeID: "EDGE_B1_BROWSER", From: string(BoundaryGenerativeUI), To: "OPERATOR_BROWSER", Verdict: PulseVerdictBlocked, Label: "Zero Confused Deputy", Detail: "SEC-101 stays confidential"},
				},
			},
			Red: ScenarioPostureTrajectory{
				Posture:         "RED",
				Outcome:         OutcomeExploitedRed,
				TerminalVerdict: PulseVerdictExfiltrated,
				Summary:         "With Token Broker disabled, outbound calls fall back to a shared root service account token and shared session memory, leaking restricted SecOps issue SEC-101 to contractor Bob.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Persona: Bob", Detail: "Contractor Bob requests restricted SEC-101"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "Shared Session", Detail: "Unpartitioned session exposes Alice's prior history"},
					{Step: 3, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictExfiltrated, Label: "Root Service Token", Detail: "Uses over-privileged shared agent credential"},
					{Step: 4, EdgeID: "EDGE_B3_B2", From: string(BoundaryIdentity3LO), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "200 OK Confused Deputy", Detail: "SEC-101 and GHSA-sec-101 returned to unauthorized persona"},
					{Step: 5, EdgeID: "EDGE_B1_BROWSER", From: string(BoundaryGenerativeUI), To: "OPERATOR_BROWSER", Verdict: PulseVerdictExfiltrated, Label: "Restricted Data Leaked", Detail: "Bob reads SecOps-only advisory"},
				},
			},
		},
		{
			ID:             Scenario03AgentGatewayAndStepUp,
			Title:          "Agent Registry Discovery, Agent Gateway UAP & Step-Up Confirmation",
			Subtitle:       "B4 CEL policy blocks container.clusters.delete while B1 pauses create_github_pull_request for human approval.",
			DefaultPersona: PersonaAlice,
			PrimaryBoundaries: []BoundaryID{
				BoundaryPlatformGovernance,
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
			},
			Blue: ScenarioPostureTrajectory{
				Posture:         "BLUE",
				Outcome:         OutcomeApprovalRequired,
				TerminalVerdict: PulseVerdictStepUp,
				Summary:         "Agent Gateway UAP permits read-only Cloud Logging & GKE diagnostics, hard-blocks destructive container.clusters.delete, and pauses GitHub PR #42 on adk_request_confirmation while stripping <script> XSS.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryPlatformGovernance,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Diagnostics + PR", Detail: "Alice triggers GKE diagnostics and rollback PR"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "ADK Tool Plan", Detail: "Orchestrator plans MCP diagnostics and PR"},
					{Step: 3, EdgeID: "EDGE_B2_B4", From: string(BoundaryReasoningGuard), To: string(BoundaryPlatformGovernance), Verdict: PulseVerdictBlocked, Label: "UAP Blocks Delete", Detail: "Permits logging/get, blocks container.clusters.delete via CEL"},
					{Step: 4, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictStepUp, Label: "adk_request_confirmation", Detail: "Pauses create_github_pull_request & strips <script> XSS"},
					{Step: 5, EdgeID: "EDGE_B1_BROWSER", From: string(BoundaryGenerativeUI), To: "OPERATOR_BROWSER", Verdict: PulseVerdictStepUp, Label: "StepUpConfirmationCard", Detail: "Awaits explicit Operator click before PR creation"},
				},
			},
			Red: ScenarioPostureTrajectory{
				Posture:         "RED",
				Outcome:         OutcomeExploitedRed,
				TerminalVerdict: PulseVerdictExfiltrated,
				Summary:         "Without Agent Gateway UAP or Step-Up Confirmation, destructive container.clusters.delete and unapproved GitHub PR #42 execute immediately and raw <script> XSS enters card payloads.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryPlatformGovernance,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Unchecked Mutation", Detail: "Step-Up & UAP shields disabled"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "NoBeforeTool Gate", Detail: "Skips UAP CEL and confirmation interrupt"},
					{Step: 3, EdgeID: "EDGE_B2_B4", From: string(BoundaryReasoningGuard), To: string(BoundaryPlatformGovernance), Verdict: PulseVerdictExfiltrated, Label: "Cluster Deleted", Detail: "container.clusters.delete executes unblocked"},
					{Step: 4, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictExfiltrated, Label: "Unapproved PR + XSS", Detail: "PR opened without approval & unescaped <script> emitted"},
				},
			},
		},
		{
			ID:             Scenario04AttenuatedA2ASandbox,
			Title:          "Attenuated A2A v2 Delegation & Agent Substrate gVisor Egress MITM",
			Subtitle:       "B5 scrubs 3LO credentials on A2A handoff; B6 wakes Actor/remediator-1 via svc/atenet-router and blocks evil.example.com.",
			DefaultPersona: PersonaAlice,
			PrimaryBoundaries: []BoundaryID{
				BoundaryCrossAgentA2A,
				BoundarySandboxEgress,
				BoundaryReasoningGuard,
			},
			Blue: ScenarioPostureTrajectory{
				Posture:         "BLUE",
				Outcome:         OutcomeDefendedSuccess,
				TerminalVerdict: PulseVerdictBlocked,
				Summary:         "withoutCredentialParts strips upstream 3LO tokens before A2A handoff; svc/atenet-router wakes gVisor Actor/remediator-1 (SNAPSHOT_FIDELITY_MEMORY) with 0 env secrets, blocks init() exfiltration to evil.example.com, and B2 screens the peer response.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryCrossAgentA2A,
					BoundarySandboxEgress,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Verify Repo Tests", Detail: "Alice requests sandbox go test verification"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "Plan A2A Handoff", Detail: "Orchestrator invokes delegate_sandbox_test"},
					{Step: 3, EdgeID: "EDGE_B2_B5", From: string(BoundaryReasoningGuard), To: string(BoundaryCrossAgentA2A), Verdict: PulseVerdictPass, Label: "Scrub 3LO Tokens", Detail: "withoutCredentialParts strips upstream OAuth bearer part"},
					{Step: 4, EdgeID: "EDGE_B5_B6", From: string(BoundaryCrossAgentA2A), To: string(BoundarySandboxEgress), Verdict: PulseVerdictBlocked, Label: "gVisor + atenet Block", Detail: "Actor/remediator-1 has 0 env secrets; EgressPolicy blocks evil.example.com"},
					{Step: 5, EdgeID: "EDGE_B6_B2", From: string(BoundarySandboxEgress), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "Screen Peer A2A", Detail: "AfterToolCallback neutralizes poisoned peer test output"},
					{Step: 6, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "SandboxExecutionCard", Detail: "Validated gVisor proof emitted over SSE"},
				},
			},
			Red: ScenarioPostureTrajectory{
				Posture:         "RED",
				Outcome:         OutcomeExploitedRed,
				TerminalVerdict: PulseVerdictExfiltrated,
				Summary:         "Unattenuated A2A forwards Alice's 3LO token to the peer runner, and malicious init() test code POSTs GITHUB_TOKEN + GOOGLE_OAUTH_TOKEN from os.Environ() to https://evil.example.com/exfil.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryCrossAgentA2A,
					BoundarySandboxEgress,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Verify Repo Tests", Detail: "Sandbox Egress MITM shield disabled"},
					{Step: 2, EdgeID: "EDGE_B2_B5", From: string(BoundaryReasoningGuard), To: string(BoundaryCrossAgentA2A), Verdict: PulseVerdictExfiltrated, Label: "Unattenuated 3LO Credential Forwarding", Detail: "Raw upstream 3LO bearer token forwarded over A2A"},
					{Step: 3, EdgeID: "EDGE_B5_B6", From: string(BoundaryCrossAgentA2A), To: string(BoundarySandboxEgress), Verdict: PulseVerdictExfiltrated, Label: "init() Env Exfil", Detail: "os.Environ() + 3LO tokens POSTed to evil.example.com/exfil"},
					{Step: 4, EdgeID: "EDGE_B6_B2", From: string(BoundarySandboxEgress), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictExfiltrated, Label: "Poisoned Peer Return", Detail: "Unscreened peer injection re-enters parent orchestrator"},
				},
			},
		},
		{
			ID:             Scenario05FullChainZeroTrust,
			Title:          "Full-Chain Zero-Trust Incident Response Across All 6 Boundaries",
			Subtitle:       "End-to-end choreography spanning B1..B6: Cloud SDP -> Gateway UAP -> 3LO PKCE -> Attenuated A2A -> gVisor Actor -> Step-Up PR.",
			DefaultPersona: PersonaAlice,
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundaryPlatformGovernance,
				BoundaryCrossAgentA2A,
				BoundarySandboxEgress,
			},
			Blue: ScenarioPostureTrajectory{
				Posture:         "BLUE",
				Outcome:         OutcomeApprovalRequired,
				TerminalVerdict: PulseVerdictStepUp,
				Summary:         "Enforces all 6 boundaries in sequence: masks Gmail PII via Cloud SDP, verifies GKE/Logging MCP via UAP while blocking cluster delete, correlates SEC-101 with 15m PKCE 3LO, runs tests in gVisor Actor/remediator-1 blocking exfil, and pauses PR #42 for Step-Up approval.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
					BoundaryPlatformGovernance,
					BoundaryCrossAgentA2A,
					BoundarySandboxEgress,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictPass, Label: "Full-Chain Incident", Detail: "Alice launches end-to-end checkout 502 response"},
					{Step: 2, EdgeID: "EDGE_B1_B2", From: string(BoundaryGenerativeUI), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "BeforeRun + Guard", Detail: "SessionID:alice partition + prompt screen active"},
					{Step: 3, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictPass, Label: "3LO PKCE Vault", Detail: "Gmail, Jira SEC-101 & GitHub authorized via 15m S256 PKCE"},
					{Step: 4, EdgeID: "EDGE_B3_B2", From: string(BoundaryIdentity3LO), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictRedacted, Label: "Cloud SDP Redact", Detail: "Masks [REDACTED_SSN] & [REDACTED_API_KEY] in-flight"},
					{Step: 5, EdgeID: "EDGE_B2_B4", From: string(BoundaryReasoningGuard), To: string(BoundaryPlatformGovernance), Verdict: PulseVerdictBlocked, Label: "Gateway UAP CEL", Detail: "Allows read-only MCP; blocks container.clusters.delete"},
					{Step: 6, EdgeID: "EDGE_B2_B5", From: string(BoundaryReasoningGuard), To: string(BoundaryCrossAgentA2A), Verdict: PulseVerdictPass, Label: "Attenuated A2A", Detail: "Strips 3LO credentials before peer handoff"},
					{Step: 7, EdgeID: "EDGE_B5_B6", From: string(BoundaryCrossAgentA2A), To: string(BoundarySandboxEgress), Verdict: PulseVerdictBlocked, Label: "Actor/remediator-1", Detail: "svc/atenet-router wakes gVisor Actor & blocks evil.example.com"},
					{Step: 8, EdgeID: "EDGE_B6_B2", From: string(BoundarySandboxEgress), To: string(BoundaryReasoningGuard), Verdict: PulseVerdictPass, Label: "Peer Output Screen", Detail: "Model Armor screens Sandbox Remediator response"},
					{Step: 9, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictStepUp, Label: "Step-Up Pause", Detail: "Pauses create_github_pull_request on adk_request_confirmation"},
					{Step: 10, EdgeID: "EDGE_B1_BROWSER", From: string(BoundaryGenerativeUI), To: "OPERATOR_BROWSER", Verdict: PulseVerdictStepUp, Label: "Operator Approval", Detail: "Streams progressive SSE trace + StepUpConfirmationCard"},
				},
			},
			Red: ScenarioPostureTrajectory{
				Posture:         "RED",
				Outcome:         OutcomeExploitedRed,
				TerminalVerdict: PulseVerdictExfiltrated,
				Summary:         "All 5 Security Shields disabled across B1..B6: raw SSN leaks, contractor Bob reads SEC-101 via shared token, cluster delete executes, sandbox env secrets exfiltrate to evil.example.com, and unapproved PR opens.",
				ActiveBoundaries: []BoundaryID{
					BoundaryGenerativeUI,
					BoundaryReasoningGuard,
					BoundaryIdentity3LO,
					BoundaryPlatformGovernance,
					BoundaryCrossAgentA2A,
					BoundarySandboxEgress,
				},
				Pulses: []ScenarioPulseHop{
					{Step: 1, EdgeID: "EDGE_BROWSER_B1", From: "OPERATOR_BROWSER", To: string(BoundaryGenerativeUI), Verdict: PulseVerdictExfiltrated, Label: "0/5 Shields", Detail: "All security boundaries disabled"},
					{Step: 2, EdgeID: "EDGE_B2_B3", From: string(BoundaryReasoningGuard), To: string(BoundaryIdentity3LO), Verdict: PulseVerdictExfiltrated, Label: "Confused Deputy + PII", Detail: "Raw SSN 123-45-6789 + shared root token leak"},
					{Step: 3, EdgeID: "EDGE_B2_B4", From: string(BoundaryReasoningGuard), To: string(BoundaryPlatformGovernance), Verdict: PulseVerdictExfiltrated, Label: "UAP Bypassed", Detail: "Destructive container.clusters.delete executes"},
					{Step: 4, EdgeID: "EDGE_B5_B6", From: string(BoundaryCrossAgentA2A), To: string(BoundarySandboxEgress), Verdict: PulseVerdictExfiltrated, Label: "Sandbox Env Exfil", Detail: "init() POSTs secrets to evil.example.com/exfil"},
					{Step: 5, EdgeID: "EDGE_B2_B1", From: string(BoundaryReasoningGuard), To: string(BoundaryGenerativeUI), Verdict: PulseVerdictExfiltrated, Label: "Unapproved PR", Detail: "State-mutating PR created without human confirmation"},
				},
			},
		},
	}
}

func canonicalADRCatalogEntries() []ADRCatalogEntry {
	entries := []ADRCatalogEntry{
		{
			Number:   "0001",
			Slug:     "dual-entry-standalone-and-gemini-enterprise-a2a",
			FileName: "0001-dual-entry-standalone-and-gemini-enterprise-a2a.md",
			Title:    "Dual-Entry Architecture: Standalone A2UI Portal and Gemini Enterprise A2A Endpoint",
			Summary:  "Pairs a standalone A2UI v0.9 GKE web portal with a standards-compliant A2A JSON-RPC endpoint (POST /a2a + serverSideOauth2) for Gemini Enterprise.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryCrossAgentA2A,
			},
		},
		{
			Number:   "0002",
			Slug:     "red-vs-blue-toggleable-security-shields",
			FileName: "0002-red-vs-blue-toggleable-security-shields.md",
			Title:    "Red-vs-Blue Arena with Toggleable Security Shields",
			Summary:  "Evaluates every incident turn against five independently toggleable Security Shields to compare vulnerable Red exploits vs. defended Blue verdicts on identical code paths.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundarySandboxEgress,
			},
		},
		{
			Number:   "0003",
			Slug:     "dual-backend-3lo-token-broker-and-persona-vault",
			FileName: "0003-dual-backend-3lo-token-broker-and-persona-vault.md",
			Title:    "Dual-Backend 3LO Token Broker and Persona-Partitioned Credential Vault",
			Summary:  "Implements ADK Go v2 auth.Provider across Alice (SecOps) and Bob (Contractor) personas, injecting per-provider 3LO tokens on auth.Transport outside LLM context.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryIdentity3LO,
			},
		},
		{
			Number:   "0004",
			Slug:     "attenuated-a2a-and-agent-substrate-v050-egress-mitm",
			FileName: "0004-attenuated-a2a-and-agent-substrate-v050-egress-mitm.md",
			Title:    "Attenuated A2A v2 Delegation and Agent Substrate v0.5.0 gVisor Sandbox with Egress MITM",
			Summary:  "Scrubs upstream 3LO credentials on A2A handoff and runs untrusted go test suites inside gVisor Actors with zero env secrets, EgressPolicy, and atenet MITM.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryCrossAgentA2A,
				BoundarySandboxEgress,
			},
		},
		{
			Number:   "0005",
			Slug:     "model-armor-hard-block-vs-sdp-inflight-deidentification",
			FileName: "0005-model-armor-hard-block-vs-sdp-inflight-deidentification.md",
			Title:    "Model Armor Hard-Block on Prompt Injection vs. In-Flight Cloud SDP De-Identification",
			Summary:  "Hard-blocks prompt injection and malicious URIs while masking SSN, phone, email, and API keys in-flight on IsSdpOnlyBlock so incident triage continues safely.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryReasoningGuard,
			},
		},
		{
			Number:   "0006",
			Slug:     "agent-registry-discovery-and-agent-gateway-uap-enforcement",
			FileName: "0006-agent-registry-discovery-and-agent-gateway-uap-enforcement.md",
			Title:    "Agent Registry Discovery, Agent Gateway UAP Enforcement, and Gemini Enterprise A2A Wire Compatibility",
			Summary:  "Discovers governed MCP servers and A2A peers via adk/v2/agentregistry and enforces AGENT_TO_ANYWHERE Unified Access Policy CEL rules.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryPlatformGovernance,
				BoundaryGenerativeUI,
				BoundaryCrossAgentA2A,
			},
		},
		{
			Number:   "0007",
			Slug:     "per-provider-hybrid-live-and-fixture-source-connectors",
			FileName: "0007-per-provider-hybrid-live-and-fixture-source-connectors.md",
			Title:    "Per-Provider Hybrid Live and Fixture Source Connectors with ADK Go v2 Reasoning",
			Summary:  "Upgrades each of the 8 External Sources independently to LIVE cloud/SaaS APIs when configured while recording explicit LIVE vs. FIXTURE Source Provenance.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundaryPlatformGovernance,
				BoundarySandboxEgress,
			},
		},
		{
			Number:   "0008",
			Slug:     "adk-v2-security-lifecycle-plugin-and-runner-architecture",
			FileName: "0008-adk-v2-security-lifecycle-plugin-and-runner-architecture.md",
			Title:    "Unified ADK Go v2 Runner and Security Lifecycle Plugin Architecture",
			Summary:  "Unifies scenario and free-form execution through one ADK Go v2 runner.Runner and AegisSecurityPlugin intercepting BeforeRun, BeforeModel, BeforeTool, AfterTool, AfterModel, and OnEvent.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
				BoundaryIdentity3LO,
				BoundaryPlatformGovernance,
				BoundaryCrossAgentA2A,
			},
		},
		{
			Number:   "0009",
			Slug:     "sse-turn-event-stream-and-progressive-step-feed",
			FileName: "0009-sse-turn-event-stream-and-progressive-step-feed.md",
			Title:    "Real-Time SSE Turn Event Stream and Progressive Chat Step-Feed Protocol",
			Summary:  "Flushes 6 typed SSE TurnStreamEvent frames in real time as boundaries evaluate, rendering progressive boundary steps and A2UI v0.9 cards with zero artificial delay.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryReasoningGuard,
			},
		},
		{
			Number:   "0010",
			Slug:     "live-substrate-gvisor-actor-and-zero-click-source-wiring",
			FileName: "0010-live-substrate-gvisor-actor-and-zero-click-source-wiring.md",
			Title:    "Live Agent Substrate gVisor Actor Execution and Zero-Click External Source Auto-Discovery",
			Summary:  "Adds --mode=remediator-actor gVisor guest probes and zero-click ConfigFromEnv() discovery for regional Model Armor, Cloud SDP, Agent Registry, and GitHub.",
			PrimaryBoundaries: []BoundaryID{
				BoundarySandboxEgress,
				BoundaryPlatformGovernance,
				BoundaryIdentity3LO,
			},
		},
		{
			Number:   "0011",
			Slug:     "path-based-routing-and-interactive-about-architecture-catalog",
			FileName: "0011-path-based-routing-and-interactive-about-architecture-catalog.md",
			Title:    "Path-Based Routing (/ & /about) and Interactive Architecture Topology Catalog",
			Summary:  "Serves / and /about via HTML5 History API routing and drives the progressive-disclosure 3-tab workspace, decluttered 3-zone SVG topology, Run in Arena handoff, and stage-safe External Source provenance from GET /api/about/catalog.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryGenerativeUI,
				BoundaryPlatformGovernance,
			},
		},
		{
			Number:   "0012",
			Slug:     "oauth2-s256-pkce-and-ephemeral-tokenbroker-vault",
			FileName: "0012-oauth2-s256-pkce-and-ephemeral-tokenbroker-vault.md",
			Title:    "OAuth 2.0 + S256 PKCE Login Flows and Ephemeral In-Memory TokenBroker Vault",
			Summary:  "Enforces RFC 7636 S256 PKCE handshakes, unified Google Workspace SSO scopes, and strict 15-minute in-memory TokenBroker TTL pruning with zero browser PATs.",
			PrimaryBoundaries: []BoundaryID{
				BoundaryIdentity3LO,
			},
		},
		{
			Number:   "0013",
			Slug:     "auto-bridged-atenet-router-remediator-actor-dispatch",
			FileName: "0013-auto-bridged-atenet-router-remediator-actor-dispatch.md",
			Title:    "Auto-Bridged atenet-router Sandbox Remediator Actor Dispatch & Verified Manifests",
			Summary:  "Routes POST /sandbox/execute with ate-target-actor: aegis-system/remediator-1 over svc/atenet-router to wake the SNAPSHOT_FIDELITY_MEMORY gVisor Actor.",
			PrimaryBoundaries: []BoundaryID{
				BoundarySandboxEgress,
				BoundaryCrossAgentA2A,
			},
		},
	}
	for i := range entries {
		if entries[i].Status == "" {
			entries[i].Status = "Accepted"
		}
	}
	return entries
}
