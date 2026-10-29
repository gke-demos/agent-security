# 0015. In-Cluster `ExtProcGRPC` Authz Extension Callout, Live `checkout-service` Pod Telemetry, and Stage Presenter Runbook

Date: 2026-10-29

## Status

Accepted

## Context

Phase 6 (`ADR-0014`) upgraded AegisSRE to live GKE `1.37` `Gateway/aegis-ingress-gateway` (`gke-l7-regional-external-managed`), `GCPAgentGateway`, `GCPAuthzPolicy`, Cloud `AGENT_TO_ANYWHERE` UAP Policy V2 (`iap.googleapis.com/resources.egressViaIAP`), and Pod Agent Identity SPIFFE SVIDs. Two live data-plane and presentation gaps remained:

1. **In-Cluster `GCPAuthzExtension` / `GCPTrafficExtension` Wire Callout (`ExtProcGRPC`)**:
   - On GKE `1.37.1-gke.1697000`, `GCPAuthzPolicy` with `policyProfile: CONTENT_AUTHZ` and first-party `googleAPIServiceName: modelarmor.<region>.rep.googleapis.com` is gated behind `enable_gcp_agent_gateway_policy` in the hosted GKE Gateway controller, whereas `REQUEST_AUTHZ` (`action: CUSTOM`) targeting an in-cluster Kubernetes `Service` via `GCPAuthzExtension.spec.backendRef` reconciles immediately (`Programmed: True`, `Attached: True`).
   - Primary-source verification (`#54`) established that `gcpauthzextensions.networking.gke.io/v1` mandates `wireFormat: ExtProcGRPC` (`/envoy.service.ext_proc.v3.ExternalProcessor/Process`) and a referenced `ServicePort` with `appProtocol: HTTP2` (`port: 443 -> targetPort: 8443`), which provisions a Compute Engine regional `BackendService` (`protocol: HTTP2`) and `HTTP2` `HealthCheck` (`requestPath: "/"` over TLS `h2` ALPN).
   - Furthermore, Cloud Application Load Balancer (Service Extensions Envoy) populates `HeaderValue.raw_value` (`bytes`, field `3`) rather than `HeaderValue.value` (`string`, field `2`), and pairing `GCPAuthzExtension` with `GCPTrafficExtension` (`supportedEvents: [RequestHeaders, RequestBody]`, `requestBodySendMode: FullDuplexStreamed`) streams both request headers and HTTP `POST` bodies (`/a2a`, `/api/sessions/*/turns/stream`) to the same callout service.
2. **Live In-Cluster `checkout-service` Telemetry in Cloud Logging**:
   - Previously, `GCPObservabilityConnector.QueryCloudLogging` (`internal/aegis/live_gcp.go`) issued an unfiltered `POST https://logging.googleapis.com/v2/entries:list` request (`pageSize: 5`) and discarded the response body, returning a static summary string.
   - Live cluster verification (`#55`) confirmed that deploying `Deployment/checkout-service` (`app: checkout-service`, `version: v2.4.0`) in `aegis-system` emitting structured `502 Bad Gateway` JSON logs (`checkout_handler.go:142`) to `stdout` results in `~150ms` ingestion via GKE's built-in `fluentbit-gke` agent under filter `resource.type="k8s_container" AND resource.labels.namespace_name="aegis-system" AND labels."k8s-pod/app"="checkout-service" AND severity>=ERROR`.
3. **Documentation & Stage Presenter Runbook Sync (`README.md` & `docs/stage-runbook.md`)**:
   - `README.md` still referenced `ADR-0013` (`13` ADRs), and presenters lacked a concise, zero-fluff stage runbook (`docs/stage-runbook.md`) walking through the 10-minute Red-vs-Blue keynote flow across `/` (Arena), `⌘K` (Security Controls & OAuth 2.0 `S256` PKCE), `/about` (3-tab `Architecture Topology Catalog`), and live `Gateway/aegis-ingress-gateway` CLI probes.

## Decision

We will complete the live GKE data-plane callout, live target workload telemetry, and stage documentation as follows:

1. **Co-Hosted `:8443` `ExtProcGRPC` + HTTP/2 TLS Multiplexer (`internal/aegis/ext_proc.go`)**:
   - Co-host the `ExtProcGRPC` (`/envoy.service.ext_proc.v3.ExternalProcessor/Process`) + HTTP/2 TLS (`EXT_PROC_TLS_ADDR`, defaulting to `:8443`, plus standalone `--mode=ext-proc`) multiplexer inside `aegis-server` (`Deployment/aegis-sre`) using an ephemeral self-signed ECDSA P-256 certificate (`NextProtos: []string{"h2", "http/1.1"}`).
   - Serve `200 OK` (`{"status":"ok","component":"aegis-model-armor-ext-proc"}`) on HTTP/2 health probes (`GET /`, `GET /healthz`) and route `Content-Type: application/grpc*` requests to a pure-Go `protowire` `ExternalProcessor/Process` stream handler (`internal/aegis/ext_proc.go`) that reads `HeaderValue.raw_value` (`bytes`, field `3`) with fallback to `HeaderValue.value` (`string`, field `2`).
   - Expose `:8443` via `Service/aegis-model-armor-ext-proc` (`port: 443 -> targetPort: 8443`, `appProtocol: HTTP2`, `cloud.google.com/neg: '{"ingress":true}'`) and wire both `GCPAuthzExtension/aegis-model-armor-ext-proc` and `GCPTrafficExtension/aegis-model-armor-body-ext` (`supportedEvents: [RequestHeaders, RequestBody]`) in `manifests/03-gke-diy-agent-gateway.yaml`.
2. **Dual-Path Edge Enforcement vs. Browser Arena SSE Telemetry**:
   - On `POST /a2a` (when `X-Aegis-Prompt-Screen` is not `"false"`) or whenever `X-Aegis-Edge-Enforce: true` is set, adversarial payloads matching Model Armor / `Prompt Screen` rules in headers or body are short-circuited right at the Google Cloud Envoy edge with `ImmediateResponse{Status: 403}` (`{"error":"blocked_by_gcp_authz_extension","plane":"CLIENT_TO_AGENT","extension":"aegis-model-armor-ext-proc","verdict":"BLOCK"}`).
   - On interactive Browser Arena SSE turns (`POST /api/sessions/{sessionId}/turns/stream`), the `ext_proc` callout evaluates the payload and injects verified upstream headers (`X-Aegis-Authz-Extension: verified`, `X-Aegis-Ext-Proc-Verdict: ALLOW|MATCH_FOUND|BYPASSED_RED`) onto the forwarded request, which `AegisSecurityPlugin` records in `BoundaryReasoningGuard` / `BoundaryPresentation` trace metadata while preserving `200 OK` `text/event-stream` `ThreatInterceptCard` delivery in Blue Mode and full execution in Red Mode.
3. **Live `checkout-service` Pod Telemetry (`manifests/04-checkout-target-workload.yaml` & `GCPObservabilityConnector`)**:
   - Commit `manifests/04-checkout-target-workload.yaml` (`Deployment/checkout-service` in `aegis-system`) and apply it in `hack/deploy-gke.sh`.
   - Upgrade `GCPObservabilityConnector.QueryCloudLogging` (`internal/aegis/live_gcp.go`) to query `POST https://logging.googleapis.com/v2/entries:list` with filter `resource.type="k8s_container" AND resource.labels.namespace_name="aegis-system" AND labels."k8s-pod/app"="checkout-service" AND severity>=ERROR` (`orderBy: "timestamp desc"`, `pageSize: 5`), parse the returned live `LogEntry` (`jsonPayload.message`, `sourceLocation.file` + `line`, `httpRequest.status`, and stage-safe `resource.labels.pod_name`), populate `OutboundWireRecord.Headers` (`x-aegis-log-source: checkout_handler.go:142`, `x-aegis-log-pod: <pod>`, `x-aegis-log-status: 502`) and the `query_cloud_logging` tool summary, and fall back to an unfiltered project `entries:list` query when no `checkout-service` entry is present.
4. **Synchronized `/about` Catalog (`15` ADRs), `README.md`, and Stage Presenter Runbook (`docs/stage-runbook.md`)**:
   - Update `ArchitectureTopologyCatalog` (`internal/aegis/about_catalog.go`) to include `ADR-0015`, the `:8443` `ExtProcGRPC` callout, and live `checkout-service` telemetry (verified by `VerifyArchitectureCatalogDrift`).
   - Update `README.md` (`ADR-0001`–`0015`) and author `docs/stage-runbook.md` using crisp, natural prose (`unslop`) with zero personal project or cluster identifiers.

## Consequences

- **Positive**: `Gateway/aegis-ingress-gateway` enforces real wire-level Envoy `ExtProcGRPC` callouts (`GCPAuthzExtension` + `GCPTrafficExtension`) against an in-cluster `:8443` HTTP/2 TLS service without extra pod footprint; `Cloud Logging` queries real `502 Bad Gateway` logs emitted by `Deployment/checkout-service` in `aegis-system`; and `README.md`, `/about`, and `docs/stage-runbook.md` stay 100% aligned with `ADR-0001`–`0015`.
- **Negative**: Co-hosting the `:8443` TLS multiplexer inside `aegis-server` adds an ephemeral ECDSA P-256 certificate generator and `protowire` stream handler, mitigated by deterministic unit and live in-cluster evaluation tests (`TestPhase7_InClusterExtProcCalloutLiveCheckoutTelemetryAndRunbookEval`).
