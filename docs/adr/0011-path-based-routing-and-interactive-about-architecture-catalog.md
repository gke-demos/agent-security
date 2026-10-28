# 11. Path-Based Routing (`/` & `/about`) and Interactive Architecture Topology Catalog

Date: 2026-10-28

## Status

Accepted

## Context

Phase 3 of **AegisSRE** unified the runtime around a single ADK Go v2 `runner.Runner` and `AegisSecurityPlugin` with real-time Server-Sent Events (`SSE`) streaming in the Chat Arena (`/`). However:

1. [`registerPortalRoutes`](../../internal/aegis/portal.go) originally served `static/index.html` only on `GET /`, returning `404 Not Found` on `/about`.
2. Operators and stage audiences inspecting **AegisSRE** on a `1440x900` stage display need a calm, progressive-disclosure `/about` ("How It Works") Architecture Workspace that fits the primary interactive 6-boundary topology within a single screen without stacking twenty-nine simultaneously expanded cards, clipped idle SVG edge labels, or crossing return lines.
3. Live cloud runs configured with `GOOGLE_CLOUD_PROJECT` and `GKE_CLUSTER_NAME` must preserve real outbound Google Cloud URLs inside `RuntimeConfig` while keeping `/api/sources/status`, `/api/about/catalog`, and on-stage UI tables free of raw project identifiers or cluster names.
4. Without a strongly typed backend catalog and automated test assertions, architectural changes (new boundaries, geometry coordinates, callbacks, tools, or ADRs) risk drifting out of sync with `/about`.

## Decision

1. **Path-Based SPA Routing (`GET /` and `GET /about`)**:
   - `registerPortalRoutes` in `internal/aegis/portal.go` serves `static/index.html` on both `GET /` and `GET /about` (returning `404` on unknown paths and never using query parameters such as `?view=about` or `?tab=` to switch pages).
   - `.chat-topbar` includes a compact, zero-layout-shift segmented navigation switcher (`Arena` -> `/` and `Architecture` -> `/about`) in `.topbar-left`.
   - `static/app.js` uses the HTML5 History API (`window.history.pushState` and `window.addEventListener("popstate", ...)`) to switch cleanly between `<main id="chat-stream">` (with `.chat-composer-bar`) and `<main id="about-view">` without full-page reloads, preserving Dark Mode and Projector Light Mode state with zero layout shift.

2. **Backend-Driven 3-Zone `ArchitectureTopologyCatalog` & Stage-Safe External Source Provenance (`GET /api/about/catalog` & `GET /api/sources/status`)**:
   - Define `ArchitectureTopologyCatalog` in `internal/aegis/about_catalog.go` (`1200x390` SVG `viewBox`) and expose it at `GET /api/about/catalog`, returning:
     - `contextNodes` and `boundaries` arranged across three non-overlapping horizontal zones with `>= 52px` separation: `Ingress` (`OPERATOR_BROWSER` + `B1`), `Reasoning Core` (`B2`), and `Execution Planes` (`B3` upper lane, `B4` middle lane, `B5` -> `B6` lower lane), each carrying a concise 2-to-3-word `nodeTag` for 2-line SVG node boxes plus crisp one-sentence `blueSummary` and `redSummary` fields alongside full boundary metadata,
     - `edges` (`[]TopologyEdgeSpec` for all 10 canonical directed edges, with `curveOffsetY` routing `EDGE_B6_B2` cleanly along the bottom margin underneath `B5` without intersecting intermediate boundary boxes),
     - `pluginCallbacks` (`[]PluginCallbackCatalogNode` for all 6 `AegisSecurityPlugin` lifecycle hooks: `BeforeRun`, `BeforeModel`, `BeforeTool`, `AfterTool`, `AfterModel`, `OnEvent`),
     - `tools` (`[]ToolCatalogEntry` for all 8 governed `functiontool` tools),
     - `scenarios` (`[]ScenarioSimulationSpec` for `SCENARIO-01`..`05` across `Blue` and `Red` postures),
     - `adrs` (`[]ADRCatalogEntry` for all accepted ADRs in `docs/adr/`), and
     - `sources` (live `[]SourceStatus` from `rt.GetSourcesStatus(ctx)`).
   - Keep `ConfigFromEnvWithLookup` and `RuntimeConfig` outbound URLs untouched while sanitizing live `SourceStatus.Endpoint` and `SourceStatus.Detail` inside `GetSourcesStatus` (`internal/aegis/sources.go`) so raw `GOOGLE_CLOUD_PROJECT` and `GKE_CLUSTER_NAME` values never appear in `/api/sources/status` or `/api/about/catalog` (e.g., `https://modelarmor.<loc>.rep.googleapis.com/v1 · Template aegis-prompt-screen`, `https://agentregistry.googleapis.com/v1alpha · Global Catalog`, and `Live Cloud Logging & GKE cluster telemetry (Active GKE Context)`).

3. **Single-Lens Progressive-Disclosure 3-Tab Workspace on `/about`**:
   - A slim single-row `/about` header pairs the workspace title with a segmented 3-tab switcher (`Security Topology` visible by default, `ADK Plugin Flow` and `System Reference` `hidden` when inactive) and bidirectional cross-links across boundaries, governed tools, and ADRs:
     - **Tab 1 — `Security Topology`**: Combines scenario pills (`S1`..`S5`), the `Blue / Red` posture switch, `Replay`, and a `Run in Arena` handoff button (which syncs the Arena's 5 Security Shields to `AllBlue` or `AllRed`, pre-fills the selected Security Scenario's starter prompt in `#input-prompt`, and routes to `/` via History API without auto-submitting) above the decluttered 3-zone SVG canvas (2-line nodes, quiet idle curves with zero permanent edge text pills, top-layer active-hop callout badge, and soft dimming of non-participating boundaries/edges), paired with a compact horizontal step scrubber and Selected-Boundary Micro-Inspector below.
     - **Tab 2 — `ADK Plugin Flow`**: Renders a non-wrapping horizontal lifecycle pipeline (`BeforeRun` -> `BeforeModel` -> `BeforeTool` -> `adk_request_confirmation / tool.Run` -> `AfterTool` -> `AfterModel` -> `OnEvent -> SSE`), a balanced two-column hook enforcement card, and a collapsed-by-default `Inspect Sample SSE Frame` wire preview drawer.
     - **Tab 3 — `System Reference`**: Uses a segmented sub-switcher (`Governed Tools`, `External Sources`, `ADR Index`) with compact click-to-expand rows, boundary filter pills on `ADR Index`, and stage-safe External Source provenance labels.

4. **Automated Architectural Drift, Geometry & Stage-Safety Verification**:
   - `go test ./...` validates 1:1 catalog parity across all 6 boundaries, 6 `AegisSecurityPlugin` callbacks, 8 governed tools, 5 Security Scenarios, and all accepted `docs/adr/00*.md` records, verifies non-overlapping 3-zone coordinates and non-crossing `EDGE_B6_B2` Bezier curves, and asserts zero `GOOGLE_CLOUD_PROJECT` or `GKE_CLUSTER_NAME` leakage on loopback (`127.0.0.1`) HTTP endpoints.

## Consequences

- **Positive**: Operators can open `/about` on a `1440x900` stage screen to inspect all 6 security boundaries in a single calm viewport, jump directly into a live turn via `Run in Arena`, explore plugin hooks and system reference tables via progressive disclosure, and present against live Google Cloud clusters without leaking project or cluster identifiers.
- **Negative**: Adds 3-zone coordinate/curve invariants (`internal/aegis/about_catalog.go`), stage-safe `SourceStatus` formatting (`internal/aegis/sources.go`), and progressive-disclosure tab state (`static/app.js` + `static/styles.css`) that must stay synchronized when new boundaries, tools, or ADRs are added.
