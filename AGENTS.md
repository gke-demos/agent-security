# AGENTS.md

Context for AI coding agents working in the `gke-demos/agent-security` repository (**AegisSRE** — Zero-Trust Agent Security Stack on GKE with ADK Go v2, Gemini Agent Platform, MCP, A2A, A2UI, and Agent Substrate).

## Project overview

`agent-security` (**AegisSRE**) is an end-to-end reference implementation and interactive Red-vs-Blue security playground demonstrating the 6 core security boundaries of enterprise AI agents on Google Kubernetes Engine (GKE):

1. **Presentation & Generative UI Boundary (`A2UI` v0.9 + HITL Confirmation):** Schema-validated declarative UI catalog (`application/json+a2ui`) preventing generative XSS, paired with `adk_request_confirmation` step-up human approval cards and `adk_request_credential` 3LO OAuth link cards.
2. **In-Loop Reasoning & Content Boundary (`ADK Go v2` + `Model Armor` + `Cloud SDP`):** Lifecycle plugin hooks screening prompts and untrusted tool outputs for indirect prompt injection, plus in-flight Sensitive Data Protection (SDP) PII redaction before data reaches Gemini or downstream tools.
3. **Identity & Per-User Multi-IdP Token Brokering (`auth/gcp` + `auth.Transport`):** Per-user 3-legged OAuth (3LO) token vaulting across heterogeneous identity providers (**Google OAuth** for Gmail, **Atlassian 3LO** for Jira Cloud, **GitHub OAuth** for repos/PRs, and **GCP IAM** for Cloud Logging/GKE MCP), injected on the HTTP wire via `auth.Transport` outside the LLM context window.
4. **Platform Governance & Discovery (`Agent Registry` + `Agent Gateway`):** Dynamic discovery of governed MCP servers and A2A peers via `agentregistry.googleapis.com` and outbound policy enforcement via `Agent-to-Anywhere` Agent Gateway and Gemini Enterprise Agent Platform Model Armor Floor Settings.
5. **Cross-Agent Federation Boundary (`A2A` v2):** Zero-trust delegation between the `Triage Orchestrator` and the `Sandbox Remediator`, scrubbing credential parts from session history (`_without_credential_parts`), attenuating scope, and screening inbound peer A2A responses via `SanitizeUserPrompt`.
6. **Compute & Network Sandbox Boundary (`GKE Sandbox / gVisor` + `Agent Substrate`):** Isolated execution of untrusted repository tests inside gVisor sandboxes with **zero secrets in container `env` or disk**, strict `EgressPolicy` domain allowlisting, and out-of-sandbox **Egress MITM** credential injection.

## Agent skills

### Issue tracker

Issues and specs for this repo live in GitHub Issues (`gke-demos/agent-security`) managed via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five canonical triage labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`GLOSSARY.md` at repo root and ADRs in `docs/adr/`). See `docs/agents/domain.md`.
