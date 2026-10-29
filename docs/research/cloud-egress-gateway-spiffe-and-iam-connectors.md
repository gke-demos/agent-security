# Cloud `AGENT_TO_ANYWHERE` Egress Gateway, UAP Policy V2, Agent Identity SPIFFE & Go IAM Connectors Contract

- **Date**: 2026-10-29
- **Status**: Verified Primary-Source Contract
- **Related Issues**: `#45` (Research Ticket), `#43` (Wayfinder Map: Full Cloud-Native Live GCP & SaaS Security Stack)
- **Primary Sources**:
  - Google Cloud Gemini Enterprise Agent Platform Governance Documentation (`https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/create-managed-egress`, `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/gke`, `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/policy-evaluation`, `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/create-mcp-access-policies`, `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/iam-v1-policies`, `https://docs.cloud.google.com/gemini-enterprise-agent-platform/troubleshooting/troubleshoot-agent-gateway`)
  - Google Kubernetes Engine Security Documentation (`https://docs.cloud.google.com/kubernetes-engine/security/agent-identity`, `https://docs.cloud.google.com/kubernetes-engine/security/agent-registry`, `https://docs.cloud.google.com/kubernetes-engine/security/agent-policies`, `https://docs.cloud.google.com/kubernetes-engine/security/troubleshoot-auth-manager`)
  - Google Cloud IAM Documentation (`https://docs.cloud.google.com/iam/docs/iam-connectors`)
  - Google Cloud SDK (`gcloud`) Leaf Command Reference (`gcloud network-services agent-gateways`, `gcloud service-extensions authz-extensions`, `gcloud network-security authz-policies`, `gcloud iam access-policies`, `gcloud iam policy-bindings`, `gcloud iap web set-iam-policy`, `gcloud agent-registry`, `gcloud compute forwarding-rules`, `gcloud alpha agent-identity connectors`, `gcloud agent-identity auth-providers`)
  - ADK Go v2 (`google.golang.org/adk/v2` `v2.6.0`: `auth/gcp`, `auth`, `tool/mcptoolset`)
  - Go OAuth2 Google Credentials (`golang.org/x/oauth2` `v0.37.0`: `google/default.go`, `google/google.go`)
  - Repository baseline (`manifests/agw-egress-config.yaml`, `manifests/iap-policy.json`, `manifests/02-aegis-deployment.yaml`, `internal/aegis/token_broker.go`, `internal/aegis/live_gcp.go`)

---

## Executive Summary & Architectural Decisions for AegisSRE

1. **Cloud-Managed `AGENT_TO_ANYWHERE` Egress Gateway & Standard GKE Pod Routing**:
   - The real `networkservices.googleapis.com/v1` `AgentGateway` resource replaces the schematic `networkservices.googleapis.com/v1alpha1` placeholder in `manifests/agw-egress-config.yaml`. It uses `protocols: [MCP]`, `googleManaged.governedAccessPath: AGENT_TO_ANYWHERE`, and up to **two** `registries` (`locations/global` + `locations/${LOCATION}`).
   - **Data-Plane Boundary**: Google Cloud natively wires turnkey `AGENT_TO_ANYWHERE` egress for managed **Agent Platform Runtime** (`ReasoningEngine`) and **Gemini Enterprise** (`Engine`), whereas turnkey transparent pod interception on GKE (`GCPBackend` + `GCPEgressPolicy` + `GCPAgentGateway`) requires **GKE Ambient Networking** (`--enable-ambient-networking`). On a standard GKE `1.37` cluster **without** Ambient Networking, the Google-managed `AgentGateway` exposes `agentGatewayCard.mtlsEndpoint` as a **Private Service Connect (PSC) Service Attachment URI** fronting a regional TLS-inspecting Secure Web Proxy. A standard GKE Pod can reach this gateway by provisioning a **Consumer PSC Forwarding Rule** in the cluster VPC and configuring an explicit Go `http.Transport` HTTPS `CONNECT` proxy (`AGENT_GATEWAY_PROXY_URL`) that trusts `agentGatewayCard.rootCertificates` and attaches `Workload-Access-Token: <RAW_UNBOUND_AGENT_TOKEN>` alongside upstream `Authorization: Bearer <UPSTREAM_TOKEN>`. Because `Workload-Access-Token` is currently a platform-injected wire header rather than a stability-versioned Go SDK surface, AegisSRE should support optional `AGENT_GATEWAY_PROXY_URL` routing for live gateway verification while defaulting cleanly to direct HTTPS MCP calls (`https://logging.googleapis.com/mcp`, `https://container.googleapis.com/mcp`) paired with in-process ADK `SecurityLifecyclePlugin` tool governance when unset.
2. **Unified Access Policy (UAP Policy V2) over IAM v1**:
   - **UAP Policy V2** (`iapPolicyVersion: "V2"` on `AuthzExtension` + `iam.googleapis.com/v3` `AccessPolicy` and `PolicyBinding`) is strictly preferred over legacy IAM v1 (`roles/iap.egressor`). UAP Policy V2 supports explicit `ALLOW` and `DENY` rules with **Absolute `DENY` Precedence**, `DRY_RUN` staging, governed unregistered endpoints, and clean CEL attributes (`destination.agent_registry.mcp_server.tool.name` and `destination.agent_registry.mcp_server.tool.annotations.read_only_hint`).
   - Current repository placeholders in `manifests/iap-policy.json` contain two defects that must be corrected: they reference `svc.id.goog` instead of the Agent Identity `principal://agents.global...` URI and use `request.auth.claims[...]` instead of UAP Policy V2 `destination.agent_registry.mcp_server.*` (or IAM v1 `api.getAttribute(...)`).
3. **Agent Identity SPIFFE on GKE (`1.37.0-gke.3503000+`) for Go Workloads**:
   - Adding Deployment label `registry.gke.io/functional-type: "AGENT"` and Pod template annotations `iam.gke.io/spiffe-identity-type: "agent-identity"`, `iam.gke.io/identity: "spiffe://${TRUST_DOMAIN}/*"`, and `iam.gke.io/inject-podcertificates: "true"` automatically registers AegisSRE in Agent Registry and mounts `/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem` plus `${TRUST_DOMAIN}.spiffe-trust-bundle.pem`.
   - Go's `golang.org/x/oauth2/google` (`v0.37.0`) `ComputeTokenSource` queries the GKE Metadata Server over standard HTTP and receives **unbound** Agent Identity OAuth access tokens (`principal://agents.global...`) usable directly against standard `*.googleapis.com` TLS endpoints without mTLS client-certificate binding (`*.mtls.googleapis.com` bound tokens are currently negotiated only by Python `google-auth >= 2.61.0`). Setting `GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN="false"` in Pod `env` guarantees consistent unbound-token behavior across any helper tools while keeping the X.509 SVID bundle mounted on disk.
4. **GCP IAM Connectors (`v1alpha`) & Agent Identity Auth Manager (`v1`) with ADK Go v2 `TokenBroker`**:
   - There is **no** `gcloud iam connectors` CLI group in Google Cloud SDK. Instead, two CLI/API tracks exist—and `google.golang.org/adk/v2/auth/gcp` (`v2.6.0`) natively supports **both** by routing on the resource path:
     - **Agent Identity Auth Manager (`v1`, Recommended)**: `gcloud agent-identity auth-providers` (`agentidentity.googleapis.com` / `agentidentitycredentials.googleapis.com`, resource `projects/.../locations/.../authProviders/*`, role `roles/agentidentity.user`).
     - **IAM Connectors (`v1alpha` Preview — legacy track)**: `gcloud alpha agent-identity connectors` (`iamconnectors.googleapis.com` / `iamconnectorcredentials.googleapis.com`, resource `projects/.../locations/.../connectors/*`, role `roles/iamconnectors.user`).
   - AegisSRE's `internal/aegis/token_broker.go` already wires `gcp.Client.RetrieveCredential` (`lines 414-437`), and needs three concrete additions for live 3LO operation: (a) env-driven singleton `gcp.NewClient` + per-provider resource configuration (`GCP_GITHUB_AUTH_RESOURCE`, `GCP_GOOGLE_AUTH_RESOURCE`, `GCP_JIRA_AUTH_RESOURCE`, `GCP_AUTH_CONTINUE_URI`) with automatic fallback to the 15-minute S256 PKCE `Alice`/`Bob` in-memory vault when unset; (b) a `GET /oauth/gcp/finalize` callback endpoint that verifies the active browser session and `POST`s `{userId, userIdValidationState, consentNonce}` to `/credentials:finalize` using ADC; and (c) a `GCPResourceName != ""` branch in `TokenBroker.Refresh` passing `PriorToken` to `RetrieveCredential` on `401`/`403` retries.

---

## 1. Cloud-Managed `AGENT_TO_ANYWHERE` Egress `AgentGateway` & Unified Access Policy

### 1.1 Real `networkservices.googleapis.com/v1` `AgentGateway` Import Schema

`manifests/agw-egress-config.yaml` currently uses a schematic Kubernetes-style `apiVersion: networkservices.googleapis.com/v1alpha1` object with `governedTargets`. In production Google Cloud Network Services (`networkservices.googleapis.com/v1`), a Google-managed egress Agent Gateway is a regional control-plane resource imported via `gcloud network-services agent-gateways import` from a flat YAML representation of the `AgentGateway` resource:

```yaml
# agw-egress.yaml
name: projects/${PROJECT_ID}/locations/${LOCATION}/agentGateways/aegis-agent-to-anywhere-gateway
description: "AegisSRE Cloud-managed AGENT_TO_ANYWHERE egress gateway"
protocols:
  - MCP
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
registries:
  - "//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/global"
  - "//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/${LOCATION}"
```

#### Key `AgentGateway` Schema Constraints
- **`protocols`**: Currently requires `["MCP"]`.
- **`googleManaged.governedAccessPath`**: Set to `AGENT_TO_ANYWHERE` for outbound agent-to-tool governance (distinct from `CLIENT_TO_AGENT` ingress gateways and `selfManaged` Secure Web Proxy / Load Balancer gateways).
- **`registries` (Maximum 2)**:
  - `//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/global`: Required to resolve Google-managed remote MCP servers (`https://logging.googleapis.com/mcp` and `https://container.googleapis.com/mcp`), which auto-populate in the `global` Agent Registry location once enabled in the project (`gcloud beta api-registry mcp enable logging.googleapis.com` and `container.googleapis.com`).
  - `//agentregistry.googleapis.com/projects/${PROJECT_ID}/locations/${LOCATION}`: Resolves regional GKE agents and custom manually registered third-party MCP servers (`Service` entries in Agent Registry). When both `global` and a regional registry are attached, **regional entries take precedence** on URL collisions. Each `AgentGateway` supports up to **5,000** governed resources.
- **`agentGatewayCard` (Output-Only on `describe`)**:
  When provisioning completes (`1-3` minutes), `gcloud network-services agent-gateways describe` returns:
  - `agentGatewayCard.mtlsEndpoint`: A **Private Service Connect (PSC) Service Attachment URI** (`projects/<TENANT_PROJECT_ID>/regions/${LOCATION}/serviceAttachments/<ATTACHMENT_NAME>`) fronting the Google-managed regional Secure Web Proxy (`SECURE_WEB_GATEWAY`) with TLS inspection enabled.
  - `agentGatewayCard.rootCertificates`: One or more PEM-encoded X.509 CA root certificates used by the gateway's TLS-inspection (`Egress MITM`) loopback to decrypt, inspect JSON-RPC `method`/`params.name` and `CONTENT_AUTHZ` payloads, and re-sign outbound HTTPS sessions.
  - `agentGatewayCard.serviceExtensionsServiceAccount`: `service-${PROJECT_NUMBER}@gcp-sa-dep.iam.gserviceaccount.com` (the data-plane service account that invokes `AuthzExtension` backends such as IAP and Model Armor).

---

### 1.2 `AuthzExtension` & `AuthzPolicy` Schemas (`REQUEST_AUTHZ` & `CONTENT_AUTHZ`)

Cloud-managed egress gateways support up to **4 `AuthzPolicy` attachments**, evaluated in strict phase order: `REQUEST_AUTHZ` policies (such as IAP / Unified Access Policy) execute **before** `CONTENT_AUTHZ` policies (such as Model Armor prompt/output inspection).

#### A. IAP `AuthzExtension` (`service-extensions authz-extensions import`)

```yaml
# iap-authz-ext.yaml
name: aegis-iap-request-authz-ext
description: "IAP Unified Access Policy V2 evaluator for AegisSRE Agent Gateway"
service: iap.googleapis.com
failOpen: false
timeout: 1s
metadata:
  iapPolicyVersion: "V2"
  # Optional audit-only staging flag before enforcing blocks:
  # iamEnforcementMode: "DRY_RUN"
```

- **Mandatory `metadata.iapPolicyVersion`**: Must be `"V2"` (Unified Access Policy) or `"V1"` (legacy per-resource IAM) whenever the `AuthzExtension` is referenced by an `AgentGateway`-targeted `AuthzPolicy`. Omit `loadBalancingScheme` when targeting an `AgentGateway`.
- **Fail-Closed Posture**: `failOpen: false` guarantees tool invocations are blocked if policy evaluation times out or errors.

#### B. IAP `AuthzPolicy` (`network-security authz-policies import`)

```yaml
# iap-authz-policy.yaml
name: aegis-iap-request-authz-policy
description: "Bind IAP UAP Policy V2 REQUEST_AUTHZ to AegisSRE egress Agent Gateway"
target:
  resources:
    - "projects/${PROJECT_ID}/locations/${LOCATION}/agentGateways/aegis-agent-to-anywhere-gateway"
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/${PROJECT_ID}/locations/${LOCATION}/authzExtensions/aegis-iap-request-authz-ext"
```

#### C. Optional Gateway-Level Model Armor `CONTENT_AUTHZ` Attachment
In addition to in-process ADK `SecurityLifecyclePlugin` screening, an `AgentGateway` can attach a `CONTENT_AUTHZ` `AuthzExtension` pointing to `modelarmor.${LOCATION}.rep.googleapis.com` (`wireFormat: EXT_PROC_GRPC`, `supportedEvents: [REQUEST_HEADERS, REQUEST_BODY, REQUEST_TRAILERS, RESPONSE_HEADERS, RESPONSE_BODY, RESPONSE_TRAILERS]`, with `metadata` keys `request_template` and `response_template` or per-principal `httpRules` headers) after granting `roles/modelarmor.user` to `agentGatewayCard.serviceExtensionsServiceAccount`.

---

### 1.3 Egress Data-Plane Wire Routing: Managed Runtimes vs. Standard GKE `1.37` Pod

#### Platform Support Boundary
| Workload Environment | Turnkey Platform Egress Wiring | Underlying Data-Plane Mechanism |
| :--- | :--- | :--- |
| **Agent Platform Runtime** (`ReasoningEngine`) | Native (`agentGatewayConfig.agentToAnywhereConfig.agentGateway`) | Runtime platform automatically tunnels container egress to `agentGatewayCard.mtlsEndpoint`, trusts `rootCertificates`, and injects `Workload-Access-Token`. |
| **Gemini Enterprise** (`Engine`) | Native (`agentGatewaySetting.defaultAgentToAnywhereConfig`) | Managed engine automatically routes outbound MCP calls through the configured `AgentGateway`. |
| **GKE with Ambient Networking** (`--enable-ambient-networking`) | Native (`selfManaged` SWP + `GCPBackend`, `GCPEgressPolicy`, `GCPAgentGateway`) | Node/cluster waypoint (`gke-ambient-cluster-proxy`) transparently redirects pod egress (`excludeCIDRRanges` for cluster CIDRs) over mTLS to Secure Web Proxy. |
| **Standard GKE `1.37` Pod WITHOUT Ambient Networking** | **Explicit Consumer PSC Endpoint + HTTPS `CONNECT` Proxy** | Requires a regional Consumer PSC Forwarding Rule to `agentGatewayCard.mtlsEndpoint` plus an explicit Go `http.Transport` proxy configuration. |

#### Exact Wire Contract from a Standard GKE `1.37` Pod (No Ambient Mesh)
Inside a Google-managed `AGENT_TO_ANYWHERE` gateway, Envoy runs a two-layer listener pipeline (`outer` HTTPS forward proxy -> `egress_mitm` TLS-inspection loopback -> upstream origin):

1. **Consumer PSC Endpoint in Cluster VPC**:
   Because `agentGatewayCard.mtlsEndpoint` is a regional PSC Service Attachment (`projects/<TENANT>/regions/${LOCATION}/serviceAttachments/<SA>`), create a regional internal IP and Consumer PSC Forwarding Rule in the **same region and VPC** as the GKE cluster:
   ```bash
   gcloud compute addresses create aegis-agw-psc-ip \
     --region="${LOCATION}" \
     --subnet="${SUBNET}" \
     --project="${PROJECT_ID}" \
     --quiet

   gcloud compute forwarding-rules create aegis-agw-psc-endpoint \
     --region="${LOCATION}" \
     --network="${VPC_NETWORK}" \
     --address="aegis-agw-psc-ip" \
     --target-service-attachment="${MTLS_ENDPOINT_URI}" \
     --project="${PROJECT_ID}" \
     --quiet
   ```
   Verify `pscConnectionStatus: ACCEPTED` via `gcloud compute forwarding-rules describe aegis-agw-psc-endpoint --region="${LOCATION}" --project="${PROJECT_ID}" --format="yaml(IPAddress,pscConnectionStatus)"`.

2. **Explicit HTTPS `CONNECT` Tunnel & Dual-Layer Root CA Trust**:
   - The Go `http.Client` connects to `https://<PSC_IP>:443` as an HTTPS `CONNECT` proxy (`CONNECT logging.googleapis.com:443 HTTP/1.1`).
   - **Outer + Inner TLS Trust**: Both the outer TLS connection to `<PSC_IP>:443` and `http.Transport.TLSClientConfig` (used for the inner TLS handshake with `logging.googleapis.com:443` inside the `CONNECT` tunnel) **must** append `agentGatewayCard.rootCertificates` to `x509.SystemCertPool()`, because the gateway's TLS-inspection loopback dynamically mints an origin leaf certificate signed by `rootCertificates` so it can parse the MCP JSON-RPC request body (`method: "tools/call"`, `params.name`).
   - If the gateway listener requests a client certificate during TLS handshake, `GetClientCertificate` loads `/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem` dynamically from disk (ensuring seamless kubelet certificate rotation).

3. **Dual-Token Header Separation (`Workload-Access-Token` vs. `Authorization`)**:
   - **`Workload-Access-Token: <RAW_UNBOUND_AGENT_ACCESS_TOKEN>`**: Raw OAuth 2.0 access token string (`ya29....`, **without** a `"Bearer "` prefix!) minted by the GKE Metadata Server for the Pod's `principal://agents.global...` identity. Attach on both `ProxyConnectHeader` (for outer proxy `CONNECT` authorization) and the inner HTTP request. The gateway's IAP filter validates `Workload-Access-Token` to authenticate the calling **Agent Identity**, evaluates Unified Access Policy V2 against the decoded MCP tool call, and **scrubs `Workload-Access-Token`** before forwarding the request upstream.
   - **`Authorization: Bearer <UPSTREAM_DESTINATION_TOKEN>`**: Preserved untouched across the gateway to authenticate to the destination MCP server:
     - For `https://logging.googleapis.com/mcp` and `https://container.googleapis.com/mcp`: an unbound GCP access token with `roles/mcp.toolUser` plus `roles/logging.viewer` / `roles/container.viewer`.
     - For external SaaS MCP servers (GitHub, Jira): the Operator Persona's 3LO OAuth token (`Alice` or `Bob`) injected by AegisSRE's `TokenBroker`.
   - **`Accept-Encoding: identity`**: Recommended whenever a `CONTENT_AUTHZ` extension (Model Armor) is attached so response bodies remain uncompressed for streaming inspection.

> **Engineering Note for AegisSRE**: Because `Workload-Access-Token` is injected automatically by managed runtimes rather than exposed as a dedicated Go client library helper, AegisSRE should implement an optional `AgentGatewayEgressTransport` activated when `AGENT_GATEWAY_PROXY_URL` and `AGENT_GATEWAY_CA_CERT_FILE` are configured. When unset, `LiveGCPIntegration` continues invoking `https://logging.googleapis.com/mcp` and `https://container.googleapis.com/mcp` directly over standard TLS while enforcing L4 tool policies in-process via `AegisSecurityPlugin`.

---

### 1.4 IAM v1 (`roles/iap.egressor`) vs. Unified Access Policy V2 (`iam.googleapis.com/v3`)

| Capability | IAM v1 (`iapPolicyVersion: "V1"`) | Unified Access Policy V2 (`iapPolicyVersion: "V2"`, Recommended) |
| :--- | :--- | :--- |
| **API & Resource Type** | Per-resource IAM v1 policy on Agent Registry shadow IAP resources (`gcloud iap web set-iam-policy --resource-type=agent-registry`) | IAM v3 `AccessPolicy` + `PolicyBinding` (`iam.googleapis.com/v3`) bound to a project, folder, or organization |
| **Permission Checked** | `roles/iap.egressor` (`iap.Polling` / egress role) | `iap.googleapis.com/resources.egressViaIAP` |
| **Explicit `DENY` Rules** | **Not supported** (allow-only; cannot override broad grants) | **Supported with Absolute `DENY` Precedence** (any matching `DENY` rule overrides all `ALLOW` rules across the hierarchy) |
| **Audit / Dry-Run Mode** | Via `AuthzExtension` `iamEnforcementMode: "DRY_RUN"` only | Native `DRY_RUN` vs `ENFORCED` policy support plus `AuthzExtension` `DRY_RUN` |
| **Unregistered URLs** | **Cannot govern** unregistered hosts/paths | **Supported** via `destination.is_registered == false` and `destination.unregistered.*` |
| **MCP Tool Name CEL** | `api.getAttribute('iap.googleapis.com/mcp.toolName', '') == '...'` | `destination.agent_registry.mcp_server.tool.name in ['...']` |
| **MCP Read-Only Hint CEL** | `api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false) == true` | `destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true` |

#### Correction of Existing `manifests/iap-policy.json`
The existing placeholder `manifests/iap-policy.json` has two schema bugs:
1. It uses `principal://iam.googleapis.com/.../workloadIdentityPools/${PROJECT_ID}.svc.id.goog/...` instead of the Agent Identity principal `principal://agents.global.org-${ORGANIZATION_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre` (or `proj-${PROJECT_NUMBER}` for standalone projects).
2. It uses `request.auth.claims["iap.googleapis.com/mcp.tool.isReadOnly"]`, which never resolves in IAP. IAM v1 uses `api.getAttribute('iap.googleapis.com/mcp.tool.isReadOnly', false)`, and UAP Policy V2 uses `destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true`.

#### Authoritative UAP Policy V2 `details-rules` JSON for AegisSRE
> **Org Policy Prerequisite**: Newer Google Cloud organizations may enforce `constraints/iam.managed.disableAccessPolicyBindings` by default. Ensure this constraint is disabled on the target project or organization before creating IAM v3 `PolicyBinding` resources.

```json
{
  "description": "AegisSRE Unified Access Policy V2: allow read-only Cloud Logging and GKE MCP discovery/inspection; explicitly deny destructive cluster or log mutations",
  "rules": [
    {
      "description": "Allow AegisSRE Triage Orchestrator to invoke read-only tools on registered Cloud Logging and GKE MCP servers",
      "effect": "ALLOW",
      "principals": [
        "principal://agents.global.org-${ORGANIZATION_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre"
      ],
      "operation": {
        "permissions": [
          "iap.googleapis.com/resources.egressViaIAP"
        ]
      },
      "conditions": {
        "iap.googleapis.com": {
          "expression": "destination.is_registered == true && destination.agent_registry.resource_type == 'MCP_SERVER' && destination.agent_registry.mcp_server.method == 'tools' && (destination.agent_registry.mcp_server.tool.annotations.read_only_hint == true || destination.agent_registry.mcp_server.tool.name in ['list_log_entries', 'list_clusters', 'get_cluster'])"
        }
      }
    },
    {
      "description": "Explicitly deny destructive or state-mutating GKE and Cloud Logging MCP tools regardless of broader project/org ALLOW bindings",
      "effect": "DENY",
      "principals": [
        "principal://agents.global.org-${ORGANIZATION_ID}.system.id.goog/resources/container/projects/${PROJECT_NUMBER}/locations/${LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre"
      ],
      "operation": {
        "permissions": [
          "iap.googleapis.com/resources.egressViaIAP"
        ]
      },
      "conditions": {
        "iap.googleapis.com": {
          "expression": "destination.is_registered == true && destination.agent_registry.resource_type == 'MCP_SERVER' && (destination.agent_registry.mcp_server.tool.annotations.destructive_hint == true || destination.agent_registry.mcp_server.tool.name in ['delete_cluster', 'update_cluster', 'delete_log'])"
        }
      }
    }
  ]
}
```

#### Complete Verified UAP Policy V2 CEL Attribute Reference
- **Registration & Resource Metadata**:
  - `destination.is_registered` (`bool`: `==`, `!=`)
  - `destination.agent_registry.resource_type` (`string`: `'AGENT'`, `'ENDPOINT'`, `'MCP_SERVER'`, `'SKILL'`)
  - `destination.agent_registry.project_id`, `destination.agent_registry.location` (`string`: `==`, `!=`, `in`)
- **Registered MCP Server Attributes**:
  - `destination.agent_registry.mcp_server.name` (`'projects/${PROJECT_ID}/locations/global/mcpServers/${MCP_SERVER_ID}'`)
  - `destination.agent_registry.mcp_server.method` (`'tools'`, `'prompts'`, `'resources'`)
  - `destination.agent_registry.mcp_server.tool.name`, `prompt.name`, `resource.name` (`==`, `!=`, `in`)
  - `destination.agent_registry.mcp_server.tool.annotations.read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint` (`bool`: `==`, `!=`)
- **Unregistered Destination Attributes** (`destination.is_registered == false`):
  - `destination.unregistered.host`, `destination.unregistered.path` (`==`, `!=`, `in`, `.startsWith()`, `.endsWith()`, `.contains()` — string prefix/suffix/substring helpers are supported **only** on `host` and `path`)
  - `destination.unregistered.method` (`'GET'`, `'POST'`, etc.)
  - `destination.unregistered.mcp_server.method`, `tool.name`, `prompt.name`, `resource.name` (`==`, `!=`, `in`)
- **Exact Hostname Matching Rule**: Agent Registry matches hostnames **literally** (no wildcards). If platform/startup calls traverse the gateway toward Google APIs (`logging.googleapis.com`, `us-central1-aiplatform.googleapis.com`, `logging.mtls.googleapis.com`), register each exact hostname variant under a consolidated `googleapis` `Service` in Agent Registry (`gcloud agent-registry services create`) or permit them via `destination.unregistered.host`.

---

### 1.5 Verified Provisioning & Dry-Run Commands (`gcloud`)

> **IAM & Access Policy Safety Gate**: Creating IAM v3 `AccessPolicy` / `PolicyBinding` resources or modifying IAP IAM policies alters security boundaries. Always validate rules with `--validate-only` first and require explicit Operator confirmation before executing non-dry-run policy binding mutations.

```bash
# 1. Discover auto-registered MCP server IDs in global Agent Registry (bounded read)
gcloud agent-registry mcp-servers list \
  --location=global \
  --project="${PROJECT_ID}" \
  --limit=20 \
  --format="table(name,mcpServerId,displayName)"

# 2. Validate UAP Policy V2 rules syntax without mutating live state (--validate-only)
gcloud iam access-policies create aegis-egress-uap \
  --location=global \
  --display-name="AegisSRE Egress Unified Access Policy" \
  --details-rules=uap-rules.json \
  --project="${PROJECT_ID}" \
  --validate-only \
  --quiet

# 3. Create UAP Policy V2 AccessPolicy and bind it to the target project (requires human approval)
gcloud iam access-policies create aegis-egress-uap \
  --location=global \
  --display-name="AegisSRE Egress Unified Access Policy" \
  --details-rules=uap-rules.json \
  --project="${PROJECT_ID}" \
  --quiet

gcloud iam policy-bindings create aegis-egress-uap-binding \
  --location=global \
  --policy="projects/${PROJECT_ID}/locations/global/accessPolicies/aegis-egress-uap" \
  --target-resource="//cloudresourcemanager.googleapis.com/projects/${PROJECT_ID}" \
  --project="${PROJECT_ID}" \
  --quiet

# 4. Import the AgentGateway, IAP AuthzExtension, and REQUEST_AUTHZ AuthzPolicy
gcloud network-services agent-gateways import aegis-agent-to-anywhere-gateway \
  --source=agw-egress.yaml \
  --location="${LOCATION}" \
  --project="${PROJECT_ID}" \
  --quiet

gcloud service-extensions authz-extensions import aegis-iap-request-authz-ext \
  --source=iap-authz-ext.yaml \
  --location="${LOCATION}" \
  --project="${PROJECT_ID}" \
  --quiet

gcloud network-security authz-policies import aegis-iap-request-authz-policy \
  --source=iap-authz-policy.yaml \
  --location="${LOCATION}" \
  --project="${PROJECT_ID}" \
  --quiet

# 5. Inspect agentGatewayCard (mtlsEndpoint + rootCertificates + serviceExtensionsServiceAccount)
gcloud network-services agent-gateways describe aegis-agent-to-anywhere-gateway \
  --location="${LOCATION}" \
  --project="${PROJECT_ID}" \
  --format="yaml(name,state,agentGatewayCard)"
```

*(Fallback IAM v1 attachment command, only if `iapPolicyVersion: "V1"` is selected instead of V2: `gcloud iap web set-iam-policy iap-v1-policy.json --resource-type=agent-registry --mcp-server="${MCP_SERVER_ID}" --region=global --project="${PROJECT_ID}" --quiet`.)*

---

## 2. Agent Identity SPIFFE on GKE (`1.37.0-gke.3503000+`) for Go Workloads

### 2.1 Cluster & Project Prerequisites
1. **GKE Version**: Control plane and node pools running **`1.37.0-gke.3503000` or later** (Autopilot or Standard).
2. **Workload Identity Federation for GKE**: Enabled on the cluster (`--workload-pool="${PROJECT_ID}.svc.id.goog"` on Standard; enabled by default on Autopilot).
3. **Enabled APIs**: `container.googleapis.com`, `iam.googleapis.com`, `agentregistry.googleapis.com`, `apphub.googleapis.com`.
4. **Trust Domain (`${TRUST_DOMAIN}`)**:
   - **Organization-parented project**: `agents.global.org-${ORGANIZATION_ID}.system.id.goog`
   - **Standalone project (no organization)**: `agents.global.proj-${PROJECT_NUMBER}.system.id.goog`

---

### 2.2 Upgraded GKE `Deployment` Manifest (`manifests/02-aegis-deployment.yaml`)

Only Kubernetes `Deployment` workloads support automatic discovery and registration in Agent Registry. Below are the exact labels, Pod template annotations, and environment variables required on `aegis-sre`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegis-sre
  namespace: aegis-system
  labels:
    app.kubernetes.io/name: aegis-sre
    # Triggers automatic GKE -> Agent Registry discovery as an AGENT workload:
    registry.gke.io/functional-type: "AGENT"
  annotations:
    # Optional A2A Agent Card metadata harvested by the GKE Agent Registry controller:
    a2a-protocol.org/agent-card: '{"protocol":"HTTP","port":8080,"endpoint":"/.well-known/agent-card.json"}'
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: aegis-sre
  template:
    metadata:
      labels:
        app.kubernetes.io/name: aegis-sre
      annotations:
        # Issues per-Pod Agent Identity SPIFFE SVIDs and configures GKE Metadata Server token identity:
        iam.gke.io/identity: "spiffe://${TRUST_DOMAIN}/*"
        iam.gke.io/inject-podcertificates: "true"
        iam.gke.io/spiffe-identity-type: "agent-identity"
    spec:
      serviceAccountName: aegis-sre
      containers:
        - name: aegis-server
          image: ${LOCATION}-docker.pkg.dev/${PROJECT_ID}/aegis/aegis-server:latest
          env:
            - name: PORT
              value: "8080"
            # Ensures polyglot/Python helpers do not request X.509 thumbprint-bound tokens
            # requiring *.mtls.googleapis.com while keeping X.509 SVID certs mounted on disk:
            - name: GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN
              value: "false"
```

---

### 2.3 Injected Pod Volume, PEM File Paths & Principal URIs

When the three `iam.gke.io/*` Pod annotations are present, GKE automatically injects a read-only projected credential volume named `gke-workload-spiffe-credentials` mounted at **`/var/run/secrets/workload-spiffe-credentials/`** (no manual `volumes` or `volumeMounts` stanza is required in the Pod spec):

| Mounted File Path | Contents & Rotation |
| :--- | :--- |
| `/var/run/secrets/workload-spiffe-credentials/x509.credential-bundle.private-key.pem` | Concatenated PEM file containing the **24-hour leaf X.509 SVID certificate**, intermediate CA chain, and **kubelet-generated per-Pod ECDSA/RSA private key**. The leaf certificate `SubjectAlternativeName` (`URI` SAN) encodes the Pod's SPIFFE ID. Rotated automatically by kubelet before expiry; Go code reading it for mTLS must reload on handshake (`tls.Config.GetClientCertificate`) rather than caching once at startup. |
| `/var/run/secrets/workload-spiffe-credentials/${TRUST_DOMAIN}.spiffe-trust-bundle.pem` | PEM-encoded X.509 root CA trust bundle for `${TRUST_DOMAIN}` used to verify peer SPIFFE workloads. |

#### Exact Identity URI Formats
- **X.509 URI SAN (SPIFFE ID)**:
  ```text
  spiffe://${TRUST_DOMAIN}/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre
  ```
- **Google Cloud IAM / UAP Policy V2 / Model Armor / Auth Manager Principal URI**:
  ```text
  principal://${TRUST_DOMAIN}/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre
  ```
  *(Note: `${CLUSTER_LOCATION}` is the GKE cluster's control-plane region or zone. Trust-domain-wide policies may also bind `principalSet://${TRUST_DOMAIN}/*`. Never use Agent Registry catalog URNs like `urn:agent:...` in IAM or UAP bindings—IAM rejects them.)*

---

### 2.4 `GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN="false"` & Go `golang.org/x/oauth2/google` (`v0.37.0`)

1. **Why Bound Tokens Fail Outside Python `google-auth >= 2.61.0`**:
   - Certificate-bound Agent Identity access tokens embed an RFC 8705 `cnf.x5t#S256` certificate thumbprint claim, lock the OAuth scope to `https://www.googleapis.com/auth/cloud-platform`, and **must** be presented over mutual TLS (`*.mtls.googleapis.com`) using the matching leaf key in `x509.credential-bundle.private-key.pem`. Presenting a bound token to a standard TLS endpoint (`https://logging.googleapis.com/mcp`, `https://modelarmor.us-central1.rep.googleapis.com`, `https://agentidentitycredentials.googleapis.com`) fails token validation.
   - Currently, only Python `google-auth >= 2.61.0` reads the GKE-injected `GOOGLE_API_CERTIFICATE_CONFIG` auto-mTLS handshake configuration to negotiate bound tokens and rewrite endpoints to `*.mtls.googleapis.com`.
2. **Exact Behavior of Go `golang.org/x/oauth2/google` (`v0.37.0`)**:
   - Verified in `golang.org/x/oauth2@v0.37.0/google/default.go` and `google/google.go:271-309`: `google.FindDefaultCredentials(ctx, scopes...)` (called by `adk/v2/auth/gcp.NewClient`, `internal/aegis/live_gcp.go`, Model Armor REST/gRPC clients, and Gemini on Agent Platform clients) resolves on GKE to `ComputeTokenSource("")`.
   - `ComputeTokenSource` issues a standard HTTP `GET` to `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token?scopes=...` with `Metadata-Flavor: Google` and refreshes tokens `3m45s` (`225s`) prior to expiry.
   - Because the Pod carries `iam.gke.io/spiffe-identity-type: "agent-identity"` and `ComputeTokenSource` does **not** request certificate binding, the GKE Metadata Server mints an **unbound** OAuth 2.0 access token representing `principal://${TRUST_DOMAIN}/.../ns/aegis-system/sa/aegis-sre` with the caller's requested scopes.
   - This unbound token works **out-of-the-box** over standard TLS against Gemini (`aiplatform.googleapis.com`), Model Armor (`modelarmor.${LOCATION}.rep.googleapis.com`), Cloud Logging MCP (`logging.googleapis.com/mcp`), GKE MCP (`container.googleapis.com/mcp`), Agent Registry (`agentregistry.googleapis.com`), and Auth Manager / IAM Connectors (`agentidentitycredentials.googleapis.com` / `iamconnectorcredentials.googleapis.com`), while attributing every Cloud Audit Log entry to the Pod's Agent Identity principal.
   - Setting `GOOGLE_API_ENABLE_RUNTIME_BOUND_TOKEN="false"` in Pod `env` ensures any auxiliary Python CLI or sidecar container shares the exact same unbound-token behavior, while `iam.gke.io/inject-podcertificates: "true"` continues mounting the X.509 SVID files at `/var/run/secrets/workload-spiffe-credentials/`.

---

## 3. GCP IAM Connectors (`v1alpha`) & Agent Identity Auth Manager (`v1`) with ADK Go v2 `TokenBroker`

### 3.1 Two-Track Service & `gcloud` CLI Reality

> **Critical CLI Clarification**: There is **no** `gcloud iam connectors` command group in Google Cloud SDK. Google Cloud exposes two closely related 3LO credential-brokering surfaces, and ADK Go v2's `google.golang.org/adk/v2/auth/gcp` (`v2.6.0`) supports **both** transparently via resource-name regex routing:

| Dimension | Track A: Agent Identity Auth Manager (Recommended `v1`) | Track B: IAM Connectors (Preview `v1alpha` — Legacy Track) |
| :--- | :--- | :--- |
| **Lifecycle Status** | GA CLI surface (`gcloud agent-identity auth-providers`) / `v1` endpoints | Preview only (`gcloud alpha agent-identity connectors`); public docs note Preview IAM Connectors will **not** advance to GA and are superseded by Auth Manager |
| **Control-Plane API** | `agentidentity.googleapis.com` (`v1`) | `iamconnectors.googleapis.com` (`v1alpha`) |
| **Data-Plane Token API** | `agentidentitycredentials.googleapis.com` (`v1`) | `iamconnectorcredentials.googleapis.com` (`v1alpha`) |
| **Resource Name Pattern** | `projects/${PROJECT_ID}/locations/${LOCATION}/authProviders/${PROVIDER_ID}` | `projects/${PROJECT_ID}/locations/${LOCATION}/connectors/${CONNECTOR_ID}` |
| **External IdP OAuth Callback (Redirect URI)** | `https://agentidentitycredentials.googleapis.com/v1/projects/${PROJECT_ID}/locations/${LOCATION}/authProviders/${PROVIDER_ID}/oauthcallback` | `https://iamconnectorcredentials.googleapis.com/v1/projects/${PROJECT_ID}/locations/${LOCATION}/connectors/${CONNECTOR_ID}/oauthcallback` |
| **Required IAM Role on Agent Identity Principal** | `roles/agentidentity.user` (`agentidentity.authProviders.retrieveCredentials`) | `roles/iamconnectors.user` (`iamconnectors.connectors.retrieveCredentials`) |
| **PKCE Flag on Create** | `--three-legged-oauth-enable-pkce` + `--three-legged-oauth-default-continue-uri` | Managed automatically on 3LO connectors |
| **Known Scope Constraint** | Supports a **single** OAuth scope string per Auth Provider for **GitHub** (e.g. `repo`) and **Microsoft** | Supports comma-separated `--allowed-scopes` |

#### Verified Provisioning & IAM Binding Commands (Recommended Track A: `auth-providers`)

```bash
# 1. Create a 3LO Auth Provider for GitHub (single scope 'repo' per Auth Manager GitHub rule)
gcloud agent-identity auth-providers create aegis-github-3lo \
  --location="${LOCATION}" \
  --display-name="AegisSRE GitHub 3LO Auth Provider" \
  --three-legged-oauth-client-id="${GITHUB_OAUTH_CLIENT_ID}" \
  --three-legged-oauth-client-secret="${GITHUB_OAUTH_CLIENT_SECRET}" \
  --three-legged-oauth-authorization-url="https://github.com/login/oauth/authorize" \
  --three-legged-oauth-token-url="https://github.com/login/oauth/access_token" \
  --three-legged-oauth-enable-pkce \
  --three-legged-oauth-default-continue-uri="https://${AEGIS_PUBLIC_HOST}/oauth/gcp/finalize" \
  --allowed-scopes="repo" \
  --workload-ids="spiffe://${TRUST_DOMAIN}/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre" \
  --project="${PROJECT_ID}" \
  --quiet

# 2. Grant the AegisSRE GKE Agent Identity permission to retrieve credentials (requires human approval)
gcloud agent-identity auth-providers add-iam-policy-binding aegis-github-3lo \
  --location="${LOCATION}" \
  --member="principal://${TRUST_DOMAIN}/resources/container/projects/${PROJECT_NUMBER}/locations/${CLUSTER_LOCATION}/clusters/${CLUSTER_NAME}/ns/aegis-system/sa/aegis-sre" \
  --role="roles/agentidentity.user" \
  --project="${PROJECT_ID}" \
  --quiet
```

*(Equivalent Track B Preview commands use `gcloud alpha agent-identity connectors create aegis-github-3lo ...` and `gcloud alpha agent-identity connectors add-iam-policy-binding aegis-github-3lo --role="roles/iamconnectors.user" ...`.)*

---

### 3.2 Exact `google.golang.org/adk/v2/auth/gcp` (`v2.6.0`) & `FinalizeCredentials` Wire Contract

Inspection of `google.golang.org/adk/v2@v2.6.0/auth/gcp/{client.go,provider.go}` and `auth/{transport.go,store.go,credential.go}` establishes the exact runtime contract:

1. **Singleton `*gcp.Client` Initialization**:
   - `gcp.NewClient(ctx, &gcp.Config{...})` calls `google.FindDefaultCredentials(context.WithoutCancel(ctx), "https://www.googleapis.com/auth/cloud-platform")` (which uses the GKE Pod's unbound Agent Identity token) and configures an `http.Client` with redirects disabled.
   - `Client.CacheKey` hashes a random per-`Client` instance nonce (`auth/store.go:171-175`), so AegisSRE **must** construct **one long-lived `*gcp.Client`** at server startup (`NewTokenBroker` / `Runtime` init) rather than per tool call.
2. **Automatic Dual-API Routing in `RetrieveCredential`**:
   Calling `gcpClient.RetrieveCredential(ctx, gcp.Request{Resource, UserID, Scopes, ContinueURI, PriorToken})` matches `Resource`:
   - `^projects/[^/]+/locations/[^/]+/authProviders/[^/]+$` -> `POST https://agentidentitycredentials.googleapis.com/v1/{Resource}/credentials:retrieve` with `{userId, scopes, continueUri, forceRefreshToken: PriorToken}`.
   - `^projects/[^/]+/locations/[^/]+/connectors/[^/]+$` -> `POST https://iamconnectorcredentials.googleapis.com/v1alpha/{Resource}/credentials:retrieve` with `{userId, scopes, continueUri, forceRefresh: PriorToken != ""}`.
   - If the token is pending asynchronous minting, `RetrieveCredential` polls automatically with exponential backoff (`500ms` up to `8s`, bounded by `PollTimeout` default `10s`, returning `gcp.ErrPollTimeout`).
3. **Consent Challenge & Error Mapping**:
   - When the active `(SessionID, Persona)` (`userId: "<SessionID>:<Persona>"`) has not yet authorized the provider or requested scopes, `RetrieveCredential` returns `*auth.ConsentRequiredError{AuthURI, Nonce}` (inspectable via `errors.As(err, &consentErr)`).
   - Explicit Operator denial returns `gcp.ErrConsentRejected`; transport/IAM errors return `*gcp.APIError{StatusCode, Body}` (with automatic bearer/secret redaction in `Error()`).
4. **Mandatory `FinalizeCredentials` Browser Redirect Handshake (Preventing Session Fixation)**:
   When the Operator clicks `consentErr.AuthURI` and approves access on GitHub, Atlassian, or Google Workspace:
   1. The external IdP redirects to Google Cloud's `/oauthcallback` URI, which exchanges the authorization code using the vaulted client secret + PKCE verifier.
   2. Google Cloud does **not** activate the token for `userId` yet. Instead, it redirects the Operator's browser to AegisSRE's `ContinueURI` (`GET /oauth/gcp/finalize`) with query parameter **`user_id_validation_state=<OPAQUE_STATE>`** (plus `auth_provider_name` / `uuid`).
   3. AegisSRE's `GET /oauth/gcp/finalize` handler **must** verify that the browser request belongs to the same `(SessionID, Persona)` that initiated the `ConsentChallenge`, look up the stored `consentErr.Nonce` (`consentNonce`), and execute an ADC-authenticated `POST`:
      - **Auth Manager (`authProviders/*`)**:
        `POST https://agentidentitycredentials.googleapis.com/v1/{Resource}/credentials:finalize`
      - **IAM Connectors (`connectors/*`)**:
        `POST https://iamconnectorcredentials.googleapis.com/v1alpha/{Resource}/credentials:finalize`
      - **JSON Request Body**:
        ```json
        {
          "userId": "<SessionID>:<Persona>",
          "userIdValidationState": "<QUERY_PARAM_USER_ID_VALIDATION_STATE>",
          "consentNonce": "<STORED_CONSENT_REQUIRED_ERROR_NONCE>"
        }
        ```
   4. Once `/credentials:finalize` returns `200 OK`, subsequent `gcpClient.RetrieveCredential` calls for `userId: "<SessionID>:<Persona>"` immediately return the decrypted `auth.BearerCredential` and `ExpiresAt`.
5. **Multi-Persona MCP Transport Rule (`auth.Transport` vs. `mcptoolset`)**:
   - `adk/v2/tool/mcptoolset` (`mcptoolset.Config{Endpoint: ..., Auth: tokenBroker}`) wraps the HTTP client in `&auth.Transport{Provider: tokenBroker, Base: base}` (`auth/transport.go`), which calls `Credential(req.Context())` on every request and retries **once** on HTTP `401`/`403` via `RefreshingProvider.Refresh(ctx, rejected)`.
   - **Important Multi-Tenant Caveat** (`adk/v2/auth/gcp/provider.go:147-151`): `mcptoolset.New` maintains a single shared MCP session stream across tool invocations. Because AegisSRE switches dynamically between `Alice` (privileged SecOps) and `Bob` (restricted contractor) within the same server process, AegisSRE must either invoke external SaaS/MCP HTTP calls via stateless per-request JSON-RPC `POST` requests through `&http.Client{Transport: &auth.Transport{Provider: rt.TokenBroker()}}` with `WithAuthInvocation(ctx, inv)` (as `internal/aegis/live_gcp.go` already does for Cloud Logging and GKE MCP) or partition `mcptoolset` instances per `(SessionID, Persona)`.

---

### 3.3 Concrete Upgrade Specification for `internal/aegis/token_broker.go`

`internal/aegis/token_broker.go` already defines `AuthInvocation.GCPResourceName`, `AuthInvocation.ContinueURI`, `TokenBroker.SetGCPClient`, and the `RetrieveCredential` lookup path (`lines 414-437`). To make live GCP Auth Manager / IAM Connectors turnkey while preserving 100% deterministic fallback to the 15-minute ephemeral S256 PKCE vault when unconfigured, implement three targeted changes:

1. **Environment-Driven `*gcp.Client` & Per-Provider Resource Mapping**:
   - Add config fields on `RuntimeConfig`:
     - `GCPGitHubAuthResource` (`GCP_GITHUB_AUTH_RESOURCE`)
     - `GCPGoogleAuthResource` (`GCP_GOOGLE_AUTH_RESOURCE`)
     - `GCPJiraAuthResource` (`GCP_JIRA_AUTH_RESOURCE`)
     - `GCPAuthContinueURI` (`GCP_AUTH_CONTINUE_URI`, e.g., `https://<host>/oauth/gcp/finalize`)
   - Each `GCP_*_AUTH_RESOURCE` accepts **either** `projects/.../locations/.../authProviders/...` (`v1`) **or** `projects/.../locations/.../connectors/...` (`v1alpha`).
   - In `NewTokenBroker(rt)`, if any `GCP_*_AUTH_RESOURCE` is non-empty and `b.gcpClient == nil`, initialize a singleton client via `gcp.NewClient(context.Background(), nil)` and store it on `b.gcpClient`. When a `GCP_*_AUTH_RESOURCE` is empty for a given `ProviderID`, `Credential(ctx)` automatically falls through to the existing 15-minute S256 PKCE `Alice`/`Bob` in-memory vault (`lines 439-477`).

2. **Pending Consent State & `GET /oauth/gcp/finalize` Route**:
   - When `gcpClient.RetrieveCredential` returns `*auth.ConsentRequiredError` (`errors.As(err, &consentErr)`), record a short-lived (`5m` TTL) `pendingGCPConsent{SessionID, Persona, Provider, Resource, Scopes, ConsentNonce: consentErr.Nonce, ExpiresAt}` entry in `TokenBroker` and surface `consentErr.AuthURI` in the `ConsentChallenge` `Declarative UI Card` so the browser opens Google Cloud's 3LO consent flow.
   - Register `GET /oauth/gcp/finalize` in `registerTokenBrokerRoutes`:
     - Validate the active `(sessionID, persona)` cookie/session parameter and extract `user_id_validation_state` (and optional `auth_provider_name`) from `r.URL.Query()`.
     - Look up and consume the matching `pendingGCPConsent` record to obtain `Resource` and `ConsentNonce`.
     - Choose the finalize URL based on `strings.Contains(resource, "/authProviders/")` (`https://agentidentitycredentials.googleapis.com/v1/` + `resource` + `/credentials:finalize`) vs `connectors/` (`https://iamconnectorcredentials.googleapis.com/v1alpha/` + `resource` + `/credentials:finalize`), attach an ADC bearer token via `google.FindDefaultCredentials`, and `POST` `{userId: sessionID + ":" + string(persona), userIdValidationState, consentNonce}`.
     - Immediately call `gcpClient.RetrieveCredential` once to warm `b.store` and update `SessionSnapshot.GrantedProviders[persona]` + `EphemeralGrants` (`AuthMethod: "gcp_agent_identity_3lo"`), then redirect or return JSON to resume the Operator's turn.

3. **Server-Side Token Refresh in `TokenBroker.Refresh` (`lines 480-494`)**:
   - Currently, `TokenBroker.Refresh` only checks `b.store` and immediately returns an authorization-refusal error. Add a `inv.GCPResourceName != ""` branch before returning an error:
     ```go
     if inv.GCPResourceName != "" {
         b.mu.RLock()
         gcpClient := b.gcpClient
         b.mu.RUnlock()
         if gcpClient != nil {
             prior := extractBearerToken(rejected)
             retrieval, err := gcpClient.RetrieveCredential(ctx, gcp.Request{
                 Resource:    inv.GCPResourceName,
                 UserID:      fmt.Sprintf("%s:%s", inv.SessionID, inv.Persona),
                 Scopes:      inv.Scopes,
                 ContinueURI: inv.ContinueURI,
                 PriorToken:  prior,
             })
             if err != nil {
                 return nil, err
             }
             if !retrieval.ExpiresAt.IsZero() {
                 _ = b.store.Set(ctx, key, retrieval.Credential, retrieval.ExpiresAt)
             }
             return retrieval.Credential, nil
         }
     }
     ```
   - `extractBearerToken(rejected)` applies `rejected.Apply(hdr)` on a scratch `http.Header` and strips `"Bearer "` so `RetrieveCredential` works seamlessly even when `auth.Credential` is wrapped via `auth.WithHeaders`.
