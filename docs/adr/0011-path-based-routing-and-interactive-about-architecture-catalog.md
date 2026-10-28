# 11. Path-Based Routing (`/` & `/about`) and Interactive Architecture Topology Catalog

Date: 2026-10-28

## Status

Accepted

## Context

Phase 3 of **AegisSRE** unified the runtime around a single ADK Go v2 `runner.Runner` and `AegisSecurityPlugin` with real-time Server-Sent Events (`SSE`) streaming in the Chat Arena (`/`). However:

1. [`registerPortalRoutes`](../../internal/aegis/portal.go) currently serves `static/index.html` only on `GET /`, returning `404 Not Found` on `/about`.
2. Operators and stage audiences inspecting **AegisSRE** need an interactive, visual `/about` ("How It Works") page that explains the 6 defense-in-depth security boundaries (`B1`..`B6`), the `AegisSecurityPlugin` lifecycle callback state machine (`BeforeRun` → `BeforeModel` → `BeforeTool` → `adk_request_confirmation` / `tool.Run` → `AfterTool` → `AfterModel` → `OnEvent` → `SSE`), the 8 governed tools, and the live 8-source provenance matrix through animated SVG diagrams and packet-pulse simulations rather than static walls of text.
3. Without a strongly typed backend catalog and automated test assertions, architectural changes (new boundaries, callbacks, tools, or ADRs) risk drifting out of sync with the `/about` page.

## Decision

1. **Path-Based SPA Routing (`GET /` and `GET /about`)**:
   - `registerPortalRoutes` in `internal/aegis/portal.go` serves `static/index.html` on both `GET /` and `GET /about` (returning `404` on unknown paths and never using query parameters such as `?view=about` to switch pages).
   - `.chat-topbar` adds a compact, zero-layout-shift segmented navigation switcher (`Arena` → `/` and `Architecture` → `/about`) in `.topbar-left`.
   - `static/app.js` uses the HTML5 History API (`window.history.pushState` and `window.addEventListener("popstate", ...)`) to switch cleanly between `<main id="chat-stream">` (with `.chat-composer-bar`) and `<main id="about-view">` without full-page reloads, preserving Dark and Projector Light Mode state with zero layout shift.

2. **Backend-Driven `ArchitectureTopologyCatalog` (`GET /api/about/catalog`)**:
   - Define `ArchitectureTopologyCatalog` in `internal/aegis/about_catalog.go` and expose it at `GET /api/about/catalog`, returning:
     - `boundaries` (`[]BoundaryCatalogNode` for all 6 `BoundaryID`s `B1`..`B6`: SVG node coordinates, shield key, Google Cloud / GKE component, Red failure mode, Blue defense mechanism, and linked ADRs),
     - `pluginCallbacks` (`[]PluginCallbackCatalogNode` for all 6 `AegisSecurityPlugin` lifecycle hooks: `BeforeRun`, `BeforeModel`, `BeforeTool`, `AfterTool`, `AfterModel`, `OnEvent`, including short-circuit behavior and emitted `TurnStreamEventType` frames),
     - `tools` (`[]ToolCatalogEntry` for all 8 governed `functiontool` tools, their primary `BoundaryID`, `ProviderID`, and `adk_request_confirmation` step-up rule),
     - `scenarios` (`[]ScenarioSimulationSpec` for `SCENARIO-01`..`05` with ordered SVG edge paths and packet-pulse verdicts under `Blue` vs. `Red` posture),
     - `adrs` (`[]ADRCatalogEntry` for all accepted ADRs in `docs/adr/`), and
     - `sources` (live `[]SourceStatus` from `rt.SourceStatuses(ctx)`).

3. **Three Interactive Visual Canvas Modules on `/about`**:
   - **Module 1 — Interactive 6-Boundary SVG Topology & Red-vs-Blue Packet-Pulse Simulator**: An interactive SVG topology graph (`Operator Browser (A2UI)` → `B1 A2UI & Step-Up` → `Triage Orchestrator + B2 Model Armor & Cloud SDP` → `B3 Per-User 3LO Ephemeral PKCE Vault` → `B4 Agent Registry & Gateway UAP` → `B5 Attenuated A2A Handoff` → `B6 Agent Substrate gVisor Actor + atenet MITM`) with scenario selector pills (`SCENARIO-01`..`05`), a `Blue (Defended)` vs. `Red (Vulnerable)` posture toggle that animates SVG signal pulses (`PASS`, `REDACTED`, `BLOCKED`, `STEP-UP`, `EXFILTRATED`), and a click-to-inspect boundary detail card.
   - **Module 2 — `AegisSecurityPlugin` Callback State Machine & Wire Preview**: An interactive 6-stage horizontal state machine (`BeforeRun` → `BeforeModel` → `BeforeTool` → `adk_request_confirmation / tool.Run` → `AfterTool` → `AfterModel` → `OnEvent → SSE`) where clicking any stage highlights the governed tools and boundaries active at that hook and previews the corresponding SSE `TurnStreamEvent` JSON frame.
   - **Module 3 — Live 8-Source Provenance, Tool Governance & ADR Matrix**: Interactive cards binding the 8 live `ExternalSourceID` connectors (`LIVE` vs. `FIXTURE`), the 8 governed tools, and the ADR index.

4. **Automated Architectural Drift Verification**:
   - `go test ./...` validates that `ArchitectureTopologyCatalog` contains every canonical `BoundaryID` (`B1`..`B6`), every `AegisSecurityPlugin` callback (`BeforeRun`, `BeforeModel`, `BeforeTool`, `AfterTool`, `AfterModel`, `OnEvent`), all 8 governed tool names, all 5 `ScenarioID`s (`SCENARIO-01`..`05`), and every `docs/adr/00*.md` file on disk.

## Consequences

- **Positive**: Operators can navigate directly to `/about` (or switch via the top bar) to explore the 6 security boundaries and ADK v2 plugin lifecycle interactively, and automated drift tests guarantee `/about` stays synchronized with the codebase and ADR directory.
- **Negative**: Adds a dedicated catalog builder (`internal/aegis/about_catalog.go`) and SVG/state-machine renderer (`static/app.js` + `static/styles.css`) that must be updated when new boundaries, tools, or ADRs are introduced.
