# 14. GKE-Native Gemini Enterprise Agent Platform Governance and Dual-Path In-Cluster Rollout

Date: 2026-10-29

## Status

Accepted

## Context

In [GKE 1.37 DIY Agent Gateway CRDs (GCPAgentGateway, GCPAuthzPolicy, GCPAuthzExtension) & Agent Registry Auto-Registration Contract](https://github.com/gke-demos/agent-security/issues/44), [Cloud AGENT_TO_ANYWHERE Agent Gateway, UAP Policy V2, Agent Identity SPIFFE & Go IAM Connectors Contract](https://github.com/gke-demos/agent-security/issues/45), and [Enable GKE Gateway API, Verify Agent Identity SPIFFE SVIDs & Provision Live Ingress/Egress Agent Gateway Testbed](https://github.com/gke-demos/agent-security/issues/46), we verified the live GKE `1.37.1-gke.1697000` (`RAPID`) and **Gemini Enterprise Agent Platform** control and data planes:

1. **Ingress (`CLIENT_TO_AGENT`) GKE Gateway API & `networking.gke.io/v1` Stack**:
   - Enabling `--gateway-api=standard` with `HttpLoadBalancing=ENABLED` and an active `REGIONAL_MANAGED_PROXY` subnet (`regional-proxy-subnetwork`) in `${REGION}` (`us-central1`) provisions `Gateway/aegis-ingress-gateway` (`gke-l7-regional-external-managed`, `Programmed: True`), `HTTPRoute/aegis-a2a-route`, `GCPAgentGateway/aegis-client-to-agent-gateway`, `GCPAuthzExtension/aegis-modelarmor-content-ext` + `aegis-iap-request-ext`, and `GCPAuthzPolicy/aegis-a2a-ingress-policy` (`Attached: True`, translated into a regional `networksecurity.googleapis.com` `AuthzPolicy` targeting the gateway's regional forwarding rule).
   - On the hosted GKE `1.37.1` Gateway controller, `GCPAuthzPolicy` fields `policyProfile: CONTENT_AUTHZ` and `operations[].mcp` pass API server admission (`--dry-run=server`) while translation into `networksecurity.googleapis.com` is gated behind the hosted controller's `enable_gcp_agent_gateway_policy` rollout flag.
2. **Egress (`AGENT_TO_ANYWHERE`) Agent Gateway, Agent Registry & UAP Policy V2**:
   - `gemini-enterprise-agent-gateway` (`googleManaged.governedAccessPath: AGENT_TO_ANYWHERE`) links `//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/global` and `locations/${REGION}` (`container.googleapis.com` and `logging.googleapis.com` MCP tool catalogs carrying `readOnlyHint` and `destructiveHint` annotations).
   - IAM v3 **Unified Access Policy** (`AccessPolicy` on `iam.googleapis.com/v3/projects/${PROJECT_ID}/locations/global/accessPolicies` with `rules[].conditions["iap.googleapis.com"]`) validates `destination.is_registered` and `destination.agent_registry.mcp_server.tool.annotations.read_only_hint` / `destructive_hint` with Absolute `DENY` Precedence.
   - Manual Consumer PSC Forwarding Rules targeting a `googleManaged` `AGENT_TO_ANYWHERE` producer `serviceAttachment` remain `pscConnectionStatus: PENDING` unless created by a producer Agent Connectivity Template or GKE Ambient Mesh SWP binding.
3. **Pod-Level `Agent Identity` SPIFFE SVIDs & Zonal vs. Regional Locations**:
   - Pods in `aegis-system` (`serviceAccountName: aegis-sre`) annotated with `iam.gke.io/spiffe-identity-type: "agent-identity"`, `iam.gke.io/identity: "spiffe://agents.global.org-${ORG_ID}.system.id.goog/*"`, and `iam.gke.io/inject-podcertificates: "true"` mount `/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem` with zonal SPIFFE URI SAN `spiffe://agents.global.org-${ORG_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre` (`${CLUSTER_LOCATION}=us-central1-a`), while `GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN="false"` ensures Go `golang.org/x/oauth2/google` retrieves unbound `ya29.*` access tokens from the GKE metadata server.

## Decision

1. **Dual-Path Blue-Governed vs. Red-Bypass Runtime Contract**:
   - **Blue Mode (Shields ON)**:
     - **Ingress & Content Guard (`BoundaryReasoningGuard` & `BoundaryCrossAgentA2A`)**: `AegisSecurityPlugin` screens user prompts, tool outputs, and peer A2A payloads through live `Model Armor` (`aegis-prompt-screen`) + `Cloud SDP` (`dlp.googleapis.com/v2`), attaches live `Gateway/aegis-ingress-gateway`, `GCPAgentGateway/aegis-client-to-agent-gateway`, and `GCPAuthzPolicy/aegis-a2a-ingress-policy` metadata on boundary trace and wire records, and routes peer A2A federation probes through `AGENT_GATEWAY_INGRESS_URL` when configured.
     - **Egress & Tool Governance (`BoundaryPlatformGovernance`)**: `AegisSecurityPlugin` verifies target MCP servers against the live **Agent Registry** (`locations/global` + `locations/${REGION}`) and evaluates outbound MCP tool calls (`query_cloud_logging_mcp`, `get_gke_cluster_status_mcp`, `delete_gke_cluster_mcp`) against the **Unified Access Policy** (`UAP Policy V2` `iam.googleapis.com/v3` `AccessPolicy`) contract (`destination.is_registered == true && destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true` with Absolute `DENY` Precedence when `destructive_hint == true`), plus optional `AGENT_GATEWAY_EGRESS_PROXY_URL` (`HTTPS CONNECT` + `Workload-Access-Token` + `rootCertificates`) when an explicit SWP/PSC proxy is bound.
   - **Red Mode (Shields OFF)**:
     - Toggling a **Security Shield** OFF in the Arena dynamically bypasses the corresponding gateway, UAP Policy V2, or Model Armor/SDP enforcement on the direct transport so all `10/10` Red-vs-Blue trajectories remain live and demonstrable in-cluster.

2. **Pod-Level `Agent Identity` SPIFFE Inspection, `Agent Registry` Auto-Registration & Persona-First Dual-Backend `TokenBroker`**:
   - Configure `Deployment/aegis-sre` (`manifests/02-aegis-deployment.yaml`) with `metadata.labels["registry.gke.io/functional-type"]: "AGENT"`, explicit `metadata.annotations["a2a-protocol.org/agent-card"]` (`/.well-known/agent-card.json` on HTTP port `8080`), pod template `agent-identity` SPIFFE annotations, and `GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN: "false"`.
   - Inspect `/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem` at runtime when present, extracting the X.509 URI SAN (sanitized to `${ORG_ID}` / `${PROJECT_NUMBER}` / `${CLUSTER_NAME}` on stage-facing endpoints) and surfacing it in `GET /api/sources/status` and `OutboundWireRecord` headers.
   - Keep `TokenBroker` Persona-first (`Alice` vs. `Bob` 15-minute S256 `Ephemeral PKCE Grants` and `.env.local` / `gh auth token` seeded tokens) while supporting `GCP_AUTH_PROVIDER_ID` (`projects/${PROJECT_ID}/locations/${REGION}/authProviders/*` or `connectors/*` via `adk/v2/auth/gcp`) when configured.

3. **In-Cluster `Deployment/aegis-sre` Rollout, Gateway Routing & Pure-JS S256 PKCE Fallback**:
   - Deploy `Deployment/aegis-sre` (`1/1 Running` in `aegis-system`) behind `Service/aegis-sre` (`ports: 80 -> 8080` and `8080 -> 8080`) and `Gateway/aegis-ingress-gateway` (`HTTPRoute/aegis-a2a-route` exposing `/.well-known/agent-card.json`, `/a2a`, `/mcp`, `/healthz`, `/`, and `/about`).
   - Include a deterministic pure-JS RFC 7636 SHA-256 fallback in `app.js` whenever `window.crypto.subtle` is unavailable (such as plain HTTP `http://<GATEWAY_EXTERNAL_IP>`) so S256 PKCE handshakes work identically on both `http://localhost:8088` and the regional Gateway IP.

4. **Parameterized Authoritative `manifests/` Suite, `hack/` Scripts & Stage-Safe `/about` Sync**:
   - Replace schematic placeholders in `manifests/` with validated, parameterized (`${PROJECT_ID}`, `${PROJECT_NUMBER}`, `${ORG_ID}`, `${CLUSTER_NAME}`, `${CLUSTER_LOCATION}`, `${REGION}`) manifests (`02-aegis-deployment.yaml`, `03-gke-diy-agent-gateway.yaml`, `agw-egress-config.yaml`, `iap-policy.json`, `model-armor-config.yaml`, and optional `manifests/ambient-egress/01-ambient-egress-policy.yaml`) and auto-resolving `hack/deploy-gke.sh` + `hack/register-gemini-enterprise.sh`.
   - Synchronize `ArchitectureTopologyCatalog` (`internal/aegis/about_catalog.go`), `VerifyArchitectureCatalogDrift`, and `internal/evals` (both offline `go test ./...` and live `AEGIS_LIVE_EVALS=true`) with zero personal GCP project, org, or GKE cluster names.

## Consequences

- **Positive**: Both local `:8088` and in-cluster `Deployment/aegis-sre` executions enforce and surface authoritative GKE `1.37` and **Gemini Enterprise Agent Platform** governance (`GCPAgentGateway`, `GCPAuthzPolicy`, `AGENT_TO_ANYWHERE` UAP Policy V2, and Pod `Agent Identity` SPIFFE SVIDs) while preserving full `10/10` Red-vs-Blue Arena toggleability and zero-leakage stage hygiene.
- **Negative**: Maintaining both `networking.gke.io/v1` Kubernetes manifests and Cloud `gcloud` / IAM v3 UAP Policy V2 specs requires automated drift assertions in `go test ./...`.
