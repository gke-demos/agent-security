# AegisSRE Agent Security

AegisSRE is a zero-trust incident triage and sandbox remediation platform that enforces six defense-in-depth security boundaries across enterprise AI agents, tools, and execution sandboxes.

## Actors & Agents

**Operator**:
A human security or reliability engineer who initiates an incident investigation, grants per-user OAuth consent, and approves privileged remediation actions.
_Avoid_: End user, client, caller

**Persona**:
A named Operator identity profile (`Alice` for privileged SecOps, `Bob` for restricted contractor) with an isolated third-party 3LO credential partition used to verify per-user authorization boundaries and prevent Confused Deputy access.
_Avoid_: Mock user, role account, test user

**Persona Session Partition**:
An isolated conversation history key scoped to both a session identifier and the active Persona (`SessionID:Persona`) when the Token Broker shield is enabled, preventing cross-persona context leakage of prior tool outputs across multi-turn follow-ups.
_Avoid_: Shared transcript, global chat memory

**Triage Orchestrator**:
The primary reasoning agent that coordinates incident analysis across mail, issue trackers, and observability tools on behalf of the invoking Operator.
_Avoid_: Main agent, root bot, controller

**Sandbox Remediator**:
A peer agent that executes untrusted repository code and verification suites inside an isolated kernel and network boundary.
_Avoid_: Worker bot, code runner, child process

**External Source**:
An upstream SaaS or cloud system (`Gmail`, `Jira Cloud`, `GitHub`, `Cloud Logging`, `GKE`, `Model Armor`, `Agent Registry`, or `Agent Substrate`) queried or mutated by an agent through a governed tool boundary.
_Avoid_: Plugin, backend, third-party integration

**Source Provenance**:
An indicator attached to each tool call and boundary trace event (`LIVE` or `FIXTURE`) that records whether the operation executed against a real external cloud/SaaS endpoint or the deterministic local fixture fallback.
_Avoid_: Mock flag, simulation status, test mode

**Target Repository**:
A dedicated companion GitHub repository (`gke-demos/aegis-checkout-target`) containing the sample `checkout-service` codebase, seeded issues, and verification tests against which the agent reads advisories and opens remediation pull requests.
_Avoid_: Dummy repo, test repo, scratch branch

## Security Boundaries & Defenses

**Security Shield**:
One of the five independently toggleable defense mechanisms in the Red-vs-Blue Arena that enforces a specific trust boundary.
_Avoid_: Feature flag, filter toggle, guardrail switch

**Security Lifecycle Plugin**:
A runtime interceptor registered on the agent execution loop that inspects user prompts, model invocations, and tool calls before and after execution to enforce the five Security Shields dynamically on any tool chain.
_Avoid_: Scenario switch, wrapper function, middleware hook

**Prompt Screen**:
An in-loop content inspection gate that detects indirect prompt injection and policy violations in untrusted inputs and tool outputs before the reasoning model acts on them.
_Avoid_: Input validator, regex filter

**PII Redactor**:
An in-flight data protection transform that masks sensitive personal or secret identifiers before text reaches a reasoning model or an external ticket comment, allowing execution to continue when sensitive data is the sole policy match.
_Avoid_: Log scrubber, string sanitizer

**Unified Access Policy**:
A principal-and-tool access rule evaluated at the Agent Gateway boundary that permits or denies individual MCP tool invocations based on workload identity and tool metadata.
_Avoid_: Firewall rule, IAM role binding

**Token Broker**:
A credential vaulting boundary that exchanges and attaches an Operator's per-provider OAuth token onto outbound tool transport requests outside the reasoning model's context window.
_Avoid_: Auth helper, secret store, token cache

**Step-Up Confirmation**:
A mandatory human-in-the-loop pause that requires explicit Operator approval before a state-mutating tool invocation can execute.
_Avoid_: Popup prompt, warning dialog

**Egress MITM**:
An out-of-sandbox network proxy that enforces domain allowlists and injects service credentials on the wire so the execution sandbox never holds secrets in memory or environment variables.
_Avoid_: Sidecar proxy, NAT gateway

## Protocols & Artifacts

**Declarative UI Card**:
A schema-validated, non-executable visual component descriptor (`application/json+a2ui`) emitted by an agent and rendered by the portal from a trusted six-component catalog.
_Avoid_: HTML snippet, iframe widget, raw markdown card

**Consent Challenge**:
A structured interrupt emitted when a tool requires a per-user 3LO authorization grant that is not yet present in the Token Broker.
_Avoid_: Auth error, login redirect

**Ephemeral PKCE Grant**:
A short-lived per-persona OAuth 2.0 access token obtained via an S256 Proof Key for Code Exchange (`PKCE`) authorization code flow and held strictly inside the Token Broker's in-memory vault with an automatic TTL expiration timestamp, never persisted in browser storage or databases.
_Avoid_: Stored PAT, long-lived API key, localStorage token

**Architecture Topology Catalog**:
The canonical structured specification of AegisSRE's six security boundaries, `AegisSecurityPlugin` callback state machine, Red-vs-Blue signal trajectories, and ADR pointers rendered by the interactive `/about` visualizer.
_Avoid_: Static docs page, markdown wall

**Attenuated Delegation**:
A cross-agent task handoff that strips upstream user credentials, narrows permission scope, and screens the peer agent's response as untrusted input before updating parent state.
_Avoid_: Token passthrough, full impersonation

**Boundary Trace Waterfall**:
A real-time ordered sequence of security inspection, credential brokering, policy evaluation, and sandbox isolation events recorded across all six boundaries for a single agent turn.
_Avoid_: Audit log, debug trace

**Turn Event Stream**:
A server-to-browser event channel that emits progressive boundary inspection verdicts, outbound wire records, declarative UI cards, and reasoning text deltas as each tool call executes within a turn.
_Avoid_: Polling endpoint, batch response

**Security Scenario**:
A reproducible incident and attack trajectory evaluated across both Red Mode (shields disabled, exploit succeeds) and Blue Mode (shields enabled, boundary blocks or redacts).
_Avoid_: Test case, demo script
