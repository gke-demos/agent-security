# AegisSRE Agent Security

AegisSRE is a zero-trust incident triage and sandbox remediation platform that enforces six defense-in-depth security boundaries across enterprise AI agents, tools, and execution sandboxes.

## Actors & Agents

**Operator**:
A human security or reliability engineer who initiates an incident investigation, grants per-user OAuth consent, and approves privileged remediation actions.
_Avoid_: End user, client, caller

**Persona**:
A named Operator identity profile with a distinct set of third-party resource permissions used to verify per-user authorization boundaries.
_Avoid_: Mock user, role account, test user

**Triage Orchestrator**:
The primary reasoning agent that coordinates incident analysis across mail, issue trackers, and observability tools on behalf of the invoking Operator.
_Avoid_: Main agent, root bot, controller

**Sandbox Remediator**:
A peer agent that executes untrusted repository code and verification suites inside an isolated kernel and network boundary.
_Avoid_: Worker bot, code runner, child process

## Security Boundaries & Defenses

**Security Shield**:
One of the five independently toggleable defense mechanisms in the Red-vs-Blue Arena that enforces a specific trust boundary.
_Avoid_: Feature flag, filter toggle, guardrail switch

**Prompt Screen**:
An in-loop content inspection gate that detects indirect prompt injection and policy violations in untrusted inputs and tool outputs before the reasoning model acts on them.
_Avoid_: Input validator, regex filter

**PII Redactor**:
An in-flight data protection transform that masks sensitive personal or secret identifiers before text reaches a reasoning model or an external ticket comment.
_Avoid_: Log scrubber, string sanitizer

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
A schema-validated, non-executable visual component descriptor emitted by an agent and rendered by the portal from a trusted component catalog.
_Avoid_: HTML snippet, iframe widget, raw markdown card

**Consent Challenge**:
A structured interrupt emitted when a tool requires a per-user 3LO authorization grant that is not yet present in the Token Broker.
_Avoid_: Auth error, login redirect

**Attenuated Delegation**:
A cross-agent task handoff that strips upstream user credentials and narrows permission scope to the minimum required by the receiving peer agent.
_Avoid_: Token passthrough, full impersonation
