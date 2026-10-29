# AegisSRE — Zero-Trust Agent Security Reference Stack on GKE

**AegisSRE** is an end-to-end reference implementation and interactive **Red-vs-Blue Arena** demonstrating the six core security boundaries of enterprise AI agents on Google Kubernetes Engine (GKE), built with **ADK Go v2 (`google.golang.org/adk/v2`)**, **Gemini Enterprise Agent Platform** (`Gemini on Agent Platform`, `Model Armor`, `Cloud SDP`, `Agent Identity / IAM Connector`, `Agent Registry`, `Agent Gateway`), **MCP**, **A2A v2**, **A2UI v0.9**, and **Agent Substrate (`v0.5.0`)**.

---

## The Six Security Boundaries

| Boundary | Security Shield | Google Cloud / Open Protocol Stack | Threat Mitigated |
| :--- | :--- | :--- | :--- |
| **B1. Presentation & Generative UI** | `Step-Up Confirmation & A2UI Catalog` | **A2UI v0.9** (`application/json+a2ui`) + ADK Go v2 `toolconfirmation` (`adk_request_confirmation`) + `:8443` `ExtProcGRPC` `Authz Extension Callout` + strict CSP (`script-src 'self'`) | Generative UI XSS (`<script>`, `<iframe>`, `javascript:`) and unapproved state-mutating tool execution |
| **B2. In-Loop Reasoning & Content** | `Prompt Screen` + `PII Redactor` | **Model Armor** + **Cloud SDP (DLP)** (`IsSdpOnlyBlock` in-flight de-identification) + `:8443` `ExtProcGRPC` (`Service/aegis-model-armor-ext-proc`, `GCPAuthzExtension`, `GCPTrafficExtension`) | Indirect prompt injection inside emails/issues and raw customer PII/API key leakage into Gemini or Jira |
| **B3. Identity & 3LO Token Broker** | `Token Broker (Per-User 3LO)` | ADK Go v2 `auth.Provider`, Pod Agent Identity SPIFFE SVIDs (`/var/run/secrets/workload-spiffe-credentials/`), `auth/gcp` IAM Connector + RFC 7636 OAuth 2.0 `S256` PKCE (`15m` ephemeral in-memory vault via `auth.Transport`) | Confused Deputy privilege escalation (`Alice` vs. `Bob`), browser-stored PAT theft, and raw bearer tokens inside LLM context |
| **B4. Platform Governance** | `Step-Up Confirmation & A2UI Catalog` | **Agent Registry** (`adk/v2/agentregistry`) + GKE `GCPAgentGateway` / `GCPAuthzPolicy` / `GCPAuthzExtension` / `GCPTrafficExtension` + **Agent Gateway** (`AGENT_TO_ANYWHERE`, `iap.googleapis.com/resources.egressViaIAP`, `roles/iap.egressor` CEL) | Rogue MCP endpoints and destructive tool calls (`container.clusters.delete` vs. `logging.entries.list` ingesting live `Deployment/checkout-service` `502` logs) |
| **B5. Cross-Agent Federation** | `Sandbox Egress MITM` | **A2A v2** (`adk/v2/server/adka2a/v2`) with `withoutCredentialParts` + `SanitizeUserPrompt` | Upstream 3LO credential bleed to peer agents and poisoned peer A2A responses |
| **B6. Compute & Network Sandbox** | `Sandbox Egress MITM` | **Agent Substrate `v0.5.0`** (`ate.dev/v1alpha1` `gvisor` `Actor/remediator-1`, `SNAPSHOT_FIDELITY_MEMORY`, `EgressPolicy`, `svc/atenet-router` Egress MITM) | Malicious `go test` `init()` exfiltrating container `os.Environ()` secrets to `evil.example.com` |

---

## Dual-Entry Architecture & Path-Based Portal Routes (`ADR-0001`–`0015`)

Because managed enterprise portal trials expire monthly, AegisSRE provides a **Dual-Entry Architecture**:

1. **Standalone GKE A2UI v0.9 Web Portal (`GET /` and `GET /about`)**:
   - **`GET /` (Incident Response Arena)**: Minimalist chat-first interface with progressive SSE streaming (`POST /api/sessions/{sessionId}/turns/stream`), inline collapsible 6-Boundary Security Trace drawers, `⌘K` Security Controls modal (5-Shield Red-vs-Blue posture toggles, `Alice` vs. `Bob` Persona Switcher, OAuth 2.0 + PKCE vault status), and an icon-only **Projector Light Mode** toggle (`aegis_theme` is the sole key ever stored in `localStorage`).
   - **`GET /about` (`Architecture Topology Catalog`)**: Progressive-disclosure 3-tab Architecture Workspace backed by `GET /api/about/catalog` (verified against `docs/adr/0001`..`0015` via `VerifyArchitectureCatalogDrift`), keeping strictly one focused conceptual lens visible at a time:
     1. **`Security Topology`**: Single-screen 3-zone (`Ingress` / `Reasoning Core` / `Execution Planes`) 6-Boundary SVG canvas with 2-line node summaries, active-path dimming, top-layer active-hop callout badges, a unified scenario/posture toolbar with **`Run in Arena`** handoff, a horizontal step scrubber, and a Selected-Boundary Micro-Inspector,
     2. **`ADK Plugin Flow`**: Non-wrapping horizontal `AegisSecurityPlugin` 6-callback + `adk_request_confirmation / tool.Run` pipeline with a 2-column hook rule inspector and a collapsed-by-default `TurnStreamEvent` SSE wire drawer,
     3. **`System Reference`**: Segmented sub-switcher (`Governed Tools (8)`, `External Sources (8)`, `ADR Index (15)`) with compact click-to-expand rows and stage-safe `LIVE` vs. `FIXTURE` provenance labels that never expose personal Google Cloud project or cluster identifiers.
2. **Gemini Enterprise A2A v2 Endpoint (`POST /a2a` & `GET /.well-known/agent-card.json`)**: Advertises `"text/plain"` input/output modes and `serverSideOauth2` token forwarding, deduplicates consecutive identical `TextPart`s sent by Discovery Engine, and binds forwarded user OAuth tokens into the caller's `Token Broker` partition.

For the 10-minute live keynote presenter walkthrough across `/about`, `/`, `⌘K`, and wire-level `Gateway/aegis-ingress-gateway` CLI checks, see [`docs/stage-runbook.md`](docs/stage-runbook.md).

---

## The Five Canonical Red-vs-Blue Scenarios

| Scenario ID | Scenario Name | Red Mode (`ALL_RED_VULNERABLE`) | Blue Mode (`ALL_BLUE_DEFENDED`) |
| :--- | :--- | :--- | :--- |
| **`SCENARIO-01`** | Indirect Prompt Injection & In-Flight PII Redaction | Agent follows hidden email injection (`evil.example.com`) and leaks raw SSN `123-45-6789` & API key | Model Armor hard-blocks injection (`ThreatInterceptCard`); SDP-only match (`IsSdpOnlyBlock`) masks `[REDACTED_SSN]` & `[REDACTED_API_KEY]` in-flight and continues |
| **`SCENARIO-02`** | Multi-IdP 3LO Token Broker & Confused Deputy | Shared root service token leaks restricted SecOps Jira issue `SEC-101` to contractor `Bob` | `auth.Transport` injects `Bob`'s personal 3LO token on the wire; Jira enforces `403 Forbidden` (`AclDenialCard`) while `Alice` succeeds with `200 OK` |
| **`SCENARIO-03`** | Agent Registry, Agent Gateway UAP & Step-Up Confirmation | Destructive `container.clusters.delete` and unapproved PR creation execute; raw `<script>` XSS renders | Agent Gateway UAP CEL permits `logging.entries.list` & `container.clusters.get`, blocks `container.clusters.delete`, strips XSS, and pauses `create_github_pull_request` on `adk_request_confirmation` |
| **`SCENARIO-04`** | Attenuated A2A v2 & Agent Substrate `v0.5.0` Sandbox | Upstream 3LO tokens leak over A2A into container env and `init()` exfiltrates `os.Environ()` to `evil.example.com` | `withoutCredentialParts` strips 3LO tokens, `svc/atenet-router` (`ate-target-actor: aegis-system/remediator-1`) wakes `gvisor` `Actor/remediator-1` with `0` env secrets, `atenet` MITM injects GitHub header out-of-sandbox, `EgressPolicy` blocks `evil.example.com`, and `SanitizeUserPrompt` screens peer output |
| **`SCENARIO-05`** | Full-Chain Zero-Trust Incident Triage & Remediation | End-to-end compromise across all 6 boundaries (PII leak + Confused Deputy + UAP bypass + sandbox exfil + unapproved PR) | Complete 6-boundary defense: Gmail SDP redaction -> Agent Gateway read-only MCP -> Alice 3LO `SEC-101` -> Attenuated A2A + `gvisor` `Actor/remediator-1` Egress MITM -> Step-Up approved GitHub PR `#42` |

---

## Quickstart

### 1. Run the Red-vs-Blue & Phase 4 Evaluation Suite

```bash
make evals
# or run the full test suite with race detector:
make test
```

### 2. Run Standalone Locally (Deterministic Fixtures or Hybrid Live Sources)

```bash
make run
# Open http://localhost:8080 (Arena) or http://localhost:8080/about (Architecture Topology Catalog)
```

To configure and run against live External Sources (Gemini on Agent Platform `gemini-2.5-flash`, Model Armor + Cloud SDP, GitHub companion target repo `gke-demos/aegis-checkout-target`, Google Workspace / Jira Cloud 3LO, and auto-bridged Agent Substrate `v0.5.0` gVisor `Actor/remediator-1`):

```bash
make setup-live
make run-live
```

### 3. Deploy to GKE with Agent Substrate `v0.5.0` & Agent Gateway (`ADR-0013`, `ADR-0014`, `ADR-0015`)

All scripts and targets automatically use `kubectl config current-context` and `gcloud config get-value project`:

```bash
make deploy-gke
make seed-fixtures
```

- `manifests/01-agent-substrate-v050.yaml` provisions the `aegis-system` namespace (`ate.dev/api-access: "true"`) and `WorkerPool/aegis-remediator-pool` (`gvisor` sandbox class).
- `manifests/01b-substrate-actor-template.yaml` defines the `ActorTemplate` (`SNAPSHOT_FIDELITY_MEMORY` Golden Snapshot running `--mode=remediator-actor` with `/run/ate/trust-bundle.pem`) and default-deny `EgressPolicy` allowing HTTPS (`443`) strictly to `api.github.com`.
- `manifests/02-aegis-deployment.yaml` mounts Pod Agent Identity SPIFFE SVIDs (`/var/run/secrets/workload-spiffe-credentials/`), exposes containerPort `8080` (`http`) alongside `:8443` (`ext-proc-tls`, `EXT_PROC_TLS_ADDR=":8443"`), and configures `LIVE_SUBSTRATE=true`, `SUBSTRATE_GATEWAY_URL=http://atenet-router.ate-system.svc.cluster.local/sandbox/execute`, and `SUBSTRATE_TARGET_ACTOR=aegis-system/remediator-1` (locally auto-bridged on `127.0.0.1` via short-lived `kubectl port-forward` to `svc/atenet-router` when `KUBERNETES_SERVICE_HOST` is unset).
- `manifests/03-gke-diy-agent-gateway.yaml` provisions `Gateway/aegis-ingress-gateway` (`gke-l7-regional-external-managed`), `HTTPRoute/aegis-a2a-route`, `GCPAgentGateway/aegis-client-to-agent-gateway`, `GCPAuthzPolicy/aegis-a2a-ingress-policy`, and the in-cluster `:8443` HTTP/2 TLS `ExtProcGRPC` callout (`Service/aegis-model-armor-ext-proc` with `appProtocol: HTTP2`, `GCPAuthzExtension/aegis-model-armor-ext-proc`, and `GCPTrafficExtension/aegis-model-armor-body-ext`).
- `manifests/04-checkout-target-workload.yaml` deploys `Deployment/checkout-service` (`app: checkout-service`, `version: v2.4.0`) in `aegis-system`, emitting structured JSON `502 Bad Gateway` logs (`checkout_handler.go:142`) to `stdout` every `15s` for live Cloud Logging (`logging.entries.list`) ingestion.

### 4. Register with Gemini Enterprise Agent Platform (Optional)

When an active Gemini Enterprise (Discovery Engine) environment is available:

```bash
AEGIS_PUBLIC_URL="https://aegis.your-domain.example.com" \
GEMINI_ENTERPRISE_ENGINE_ID="your-engine-id" \
make register-gemini-enterprise
```

---

## OAuth 2.0 + S256 PKCE & Ephemeral In-Memory Token Vault (`ADR-0012`)

AegisSRE never prompts for or stores Personal Access Tokens (PATs) in browser storage (`localStorage` / `sessionStorage`) or databases. Instead, `Token Broker` (`internal/aegis/token_broker.go`) combines Google Cloud IAM Connector (`google.golang.org/adk/v2/auth/gcp`) with RFC 7636 `S256` PKCE OAuth 2.0 3LO login flows (`GET /oauth/{provider}/authorize`, `GET /oauth/{provider}/callback`, `POST /api/sessions/{sessionId}/oauth/grant`) and stores short-lived access tokens strictly in an ephemeral in-memory vault with an automatic `15m` (`900s`) TTL and lazy expiry pruning:

1. **Unified Google Workspace SSO (`google_gmail`)**: OAuth 2.0 Web Client (`S256` PKCE) requesting unified scopes `openid`, `email`, `https://www.googleapis.com/auth/gmail.readonly`, `https://www.googleapis.com/auth/drive.readonly`, and `https://www.googleapis.com/auth/calendar.readonly` with redirect URI `/oauth/google_gmail/callback`.
2. **Atlassian Jira Cloud Free (`atlassian_jira`)**: Atlassian 3LO App (`https://auth.atlassian.com/authorize`, `S256` PKCE) with scopes `read:jira-work write:jira-work` and redirect URI `/oauth/atlassian_jira/callback`.
3. **GitHub (`github`)**: GitHub OAuth App (`https://github.com/login/oauth/authorize`, `S256` PKCE) with scopes `repo security_events` and redirect URI `/oauth/github/callback`.
4. **Google Cloud Official Remote MCPs (`gcp_iam`)**: Governed via Agent Registry (`https://logging.googleapis.com/mcp`, `https://container.googleapis.com/mcp`) and Agent Gateway UAP (`manifests/agw-egress-config.yaml`, `manifests/iap-policy.json`).
