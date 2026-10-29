# Envoy `ext_proc` Callout Contract for GKE `GCPAuthzExtension` (`CLIENT_TO_AGENT`) & Model Armor Inspection

## Executive Summary

1. **`ExtProcGRPC` (`envoy.service.ext_proc.v3.ExternalProcessor/Process`) is the Mandatory Wire Protocol**:
   - While Google Cloud Network Services (`google.cloud.networkservices.v1.AuthzExtension`) defines both `EXT_PROC_GRPC` and `EXT_AUTHZ_GRPC` wire formats in the underlying Cloud API, the GKE Gateway Controller CRD `GCPAuthzExtension` (`networking.gke.io/v1` on GKE `1.37+`) **exclusively allows `wireFormat: ExtProcGRPC`** in its OpenAPI schema (`enum: [ExtProcGRPC]`).
   - Any in-cluster callout backend referenced by `GCPAuthzExtension` (or `GCPTrafficExtension`) must implement the bidirectional streaming RPC `/envoy.service.ext_proc.v3.ExternalProcessor/Process`.

2. **Why `googleAPIServiceName: modelarmor.<region>.rep.googleapis.com` Failed on `REQUEST_AUTHZ` and How an In-Cluster `backendRef` Callout Resolves It**:
   - First-party managed `googleAPIServiceName: modelarmor.<region>.rep.googleapis.com` in `GCPAuthzExtension` is restricted by the Cloud Network Security API (`AuthzPolicy`) to `CONTENT_AUTHZ` policy profiles, which require a feature-gated controller flag not active on standard GKE `1.37` regional external Application Load Balancers (`gke-l7-regional-external-managed`). When reconciled without that flag, `GCPAuthzPolicy` defaults to `REQUEST_AUTHZ` (`UNSPECIFIED` profile) and rejects first-party `modelarmor.*.rep.googleapis.com` with:
     `InvalidArgument: The request was invalid: Model Armor service is not supported for REQUEST_AUTHZ/UNSPECIFIED policy profile.`
   - Replacing `googleAPIServiceName` with an in-cluster Kubernetes `Service` via `spec.backendRef` (`Service/aegis-model-armor-ext-proc`) satisfies `REQUEST_AUTHZ` validation (`GCPAuthzPolicy` reaches `Programmed: True`), invokes the in-cluster `ExternalProcessor` callout at the Envoy edge, and lets the callout invoke the regional Model Armor REST API (`https://modelarmor.<region>.rep.googleapis.com/v1/...:sanitizeUserPrompt`) and deterministic security rules directly.

3. **`GCPAuthzExtension` (`REQUEST_HEADERS`) vs. `GCPTrafficExtension` (`RequestHeaders` + `RequestBody`)**:
   - In Cloud Service Extensions, an `AuthzExtension` attached to a `REQUEST_AUTHZ` `GCPAuthzPolicy` (`action: CUSTOM`) is invoked **only on `REQUEST_HEADERS`** (`ProcessingRequest.request_headers`).
   - To inspect both HTTP request headers (`Authorization`, `X-Aegis-Prompt-Screen`, `:path`, `:method`) **and** HTTP POST request bodies (`POST /a2a` and `POST /api/sessions/{id}/turns/stream`), the exact same in-cluster `ExternalProcessor` callout `Service` (`aegis-model-armor-ext-proc`) can be referenced by:
     1. `GCPAuthzExtension` (`aegis-modelarmor-content-ext`) + `GCPAuthzPolicy` (`aegis-agent-gateway-uap`, `action: CUSTOM`) for `REQUEST_AUTHZ` header-stage authorization and prompt-header screening.
     2. `GCPTrafficExtension` (`aegis-modelarmor-body-ext`, `networking.gke.io/v1`) with `supportedEvents: [RequestHeaders, RequestBody]` and `requestBodySendMode: FullDuplexStreamed` (or buffered chunk inspection) for full HTTP POST body inspection at `Gateway/aegis-ingress-gateway`.
   - Implementing both `request_headers` (`field 2`) and `request_body` (`field 3`) in a single `ExternalProcessor/Process` stream handler inside `aegis-server` supports both extension CRDs simultaneously with zero duplicated infrastructure.

4. **Mandatory Kubernetes `Service` & Health Check Contract (`appProtocol: HTTP2` over TLS)**:
   - The GKE Gateway Controller translator strictly validates that a `Service` referenced by `GCPAuthzExtension.spec.backendRef` or `GCPTrafficExtension` declares **`appProtocol: HTTP2`** (exact uppercase string `"HTTP2"`) on the target `ServicePort`. If `appProtocol` is omitted or set to `kubernetes.io/h2c`, translation fails with:
     `service <namespace>/<name> in GCPAuthzExtension does not have port <port> with protocol HTTP2`.
   - When `appProtocol: HTTP2` is set on the `ServicePort`, the GKE Gateway Controller provisions:
     - A standalone zonal Network Endpoint Group (`cloud.google.com/neg: '{"ingress":true}'`).
     - A regional Compute Engine `BackendService` with `"protocol": "HTTP2"` (which connects from the Google Cloud Envoy proxy to Pod backends over **HTTP/2 over TLS**, ignoring self-signed certificate chains by default).
     - A default regional `HTTP2` Compute Engine `HealthCheck` (`type: HTTP2`, `requestPath: "/"` on the serving port), which can optionally be customized via `HealthCheckPolicy` (`networking.gke.io/v1`).
   - Therefore, the callout listener inside `aegis-server` (e.g. container port `8443`, exposed as Service port `443` with `appProtocol: HTTP2`) must serve **HTTP/2 over TLS** (using an ephemeral self-signed `crypto/tls` certificate generated at startup) and multiplex:
     - gRPC `POST /envoy.service.ext_proc.v3.ExternalProcessor/Process` (`Content-Type: application/grpc`), and
     - HTTP/2 `GET /` and `GET /healthz` returning `200 OK` for the Compute Engine `HTTP2` health check prober.

---

## 1. GKE `1.37` `GCPAuthzExtension` CRD Schema & CEL Validation Rules

On GKE `1.37+`, `gcpauthzextensions.networking.gke.io/v1` enforces the following OpenAPI schema and CEL validation rules on `spec`:

| Field | Type | Required / Validation Rule | Recommended Value for `aegis-system` |
|---|---|---|---|
| `spec.backendRef` | `Object` (`group`, `kind`, `name`, `port`) | Mutually exclusive with `googleAPIServiceName` and `backendService`. `kind` defaults to `Service`; `port` (`1..65535`) is **required**. | `kind: Service`, `name: aegis-model-armor-ext-proc`, `port: 443` |
| `spec.authority` | `string` | **Required and non-empty** whenever `backendRef` is specified (`has(self.backendRef) ? (has(self.authority) && self.authority != '') : true`). Sets the `:authority` pseudo-header on Envoy callout streams. | `aegis-model-armor-ext-proc.aegis-system.svc.cluster.local` |
| `spec.timeout` | `string` (Duration) | **Required** whenever `backendRef` is specified (`has(self.backendRef) ? has(self.timeout) : true`). Must be between `0.01s` (`10ms`) and `10s` (`10000ms`). | `2000ms` (or `2s`) |
| `spec.wireFormat` | `string` | Enum: `[ExtProcGRPC]`. Translates to `WireFormat_EXT_PROC_GRPC` in Cloud Service Extensions. | `ExtProcGRPC` |
| `spec.failOpen` | `boolean` | Optional (defaults to `false` in Cloud Service Extensions when omitted). Setting `false` enforces fail-closed zero-trust behavior when the extension returns an error, while setting `true` allows traffic if the extension times out. | `false` |
| `spec.forwardHeaders` | `[]string` | Optional list of HTTP request headers forwarded to the callout service. If omitted, Envoy forwards all request headers in `ProcessingRequest.request_headers`. | Omit (forward all headers) or list `[":method", ":path", ":authority", "authorization", "content-type", "x-aegis-prompt-screen", "x-agent-gateway-ingress"]` |
| `spec.metadata` | `map[string]string` | Optional static key-value metadata passed to the extension (max 1024 bytes total). | `{"policy_plane": "CLIENT_TO_AGENT", "guardrail": "model-armor"}` |

### How `GCPAuthzPolicy` References `GCPAuthzExtension`

In `gcpauthzpolicies.networking.gke.io/v1`, a policy with `spec.action: CUSTOM` must populate `spec.customProvider.authzExtension.resources` with the `GCPAuthzExtension` reference:

```yaml
apiVersion: networking.gke.io/v1
kind: GCPAuthzPolicy
metadata:
  name: aegis-agent-gateway-uap
  namespace: aegis-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: aegis-ingress-gateway
  default:
    requestAuthz: {}
  action: CUSTOM
  customProvider:
    authzExtension:
      resources:
        - group: networking.gke.io
          kind: GCPAuthzExtension
          name: aegis-modelarmor-content-ext
          namespace: aegis-system
  httpRules:
    - to:
        operations:
          - methods: ["POST"]
            paths:
              - exact: "/a2a"
              - prefix: "/api/sessions/"
          - methods: ["GET"]
            paths:
              - exact: "/.well-known/agent.json"
              - exact: "/.well-known/agent-card.json"
```

When reconciled by the GKE Gateway Controller:
1. The controller validates that `Service/aegis-model-armor-ext-proc` exists in `aegis-system` and exposes port `443` with `appProtocol: HTTP2`.
2. The controller creates the Compute Engine regional `BackendService`, `HealthCheck` (`HTTP2`), `ServiceLbPolicy`, and `AuthzExtension` (`loadBalancingScheme: EXTERNAL_MANAGED`, `wireFormat: EXT_PROC_GRPC`).
3. The controller creates the Cloud Network Security `AuthzPolicy` referencing the `AuthzExtension` resource URI and attaches it to `Gateway/aegis-ingress-gateway`'s regional forwarding rule.

---

## 2. Envoy `ext_proc` v3 gRPC & Protobuf Wire Contract

### Service Definition (`envoy/service/ext_proc/v3/external_processor.proto`)

- **Package**: `envoy.service.ext_proc.v3`
- **Service Name**: `envoy.service.ext_proc.v3.ExternalProcessor`
- **Method**: `Process`
- **Full gRPC Method Path**: `/envoy.service.ext_proc.v3.ExternalProcessor/Process`
- **Streaming Type**: Bidirectional streaming (`ClientStreams: true`, `ServerStreams: true`)

```protobuf
syntax = "proto3";
package envoy.service.ext_proc.v3;

service ExternalProcessor {
  rpc Process(stream ProcessingRequest) returns (stream ProcessingResponse) {}
}
```

### Incoming Message: `ProcessingRequest`

For each HTTP request matching the policy/extension, Envoy opens a bidirectional stream to `ExternalProcessor/Process` and sends one or more `ProcessingRequest` messages:

```protobuf
message ProcessingRequest {
  bool async_mode = 1;
  oneof request {
    HttpHeaders request_headers = 2;
    HttpBody request_body = 3;
    HttpHeaders response_headers = 4;
    HttpBody response_body = 5;
    HttpTrailers request_trailers = 6;
    HttpTrailers response_trailers = 7;
  }
  // envoy.config.core.v3.Metadata metadata_context = 8;
  // map<string, google.protobuf.Struct> attributes = 9;
  // bool observability_mode = 10;
}

message HttpHeaders {
  envoy.config.core.v3.HeaderMap headers = 1;
  // map<string, google.protobuf.Struct> attributes = 2;
  bool end_of_stream = 3;
}

message HttpBody {
  bytes body = 1;
  bool end_of_stream = 2;
}
```

Where `envoy.config.core.v3.HeaderMap` (`envoy/config/core/v3/base.proto`) is:

```protobuf
message HeaderMap {
  repeated HeaderValue headers = 1;
}

message HeaderValue {
  string key = 1;       // Lowercase header name (e.g., ":path", ":method", "x-aegis-prompt-screen")
  string value = 2;     // String value (used by classic Envoy configurations)
  bytes raw_value = 3;  // Raw byte value (populated by Google Cloud Application Load Balancer Envoy!)
}
```

> **Critical Implementation Gotcha (`value` vs. `raw_value`)**:
> Google Cloud Application Load Balancer (Service Extensions Envoy) populates `HeaderValue.raw_value` (field `3`, `bytes`) rather than `HeaderValue.value` (field `2`, `string`) for HTTP headers! Any `ExternalProcessor` implementation **must** inspect `string(hv.RawValue)` when `hv.Value == ""` (or prefer `raw_value` whenever non-empty).

### Outgoing Message: `ProcessingResponse`

In response to each `ProcessingRequest`, the callout server sends a `ProcessingResponse` on the stream:

```protobuf
message ProcessingResponse {
  oneof response {
    HeadersResponse request_headers = 1;
    BodyResponse request_body = 2;
    HeadersResponse response_headers = 3;
    BodyResponse response_body = 4;
    TrailersResponse request_trailers = 5;
    TrailersResponse response_trailers = 6;
    ImmediateResponse immediate_response = 7;
  }
  google.protobuf.Struct dynamic_metadata = 8;
  ProcessingMode mode_override = 9;
  google.protobuf.Duration override_message_timeout = 10;
}
```

#### Case A: **ALLOW** (`CONTINUE` with Audit Response / Upstream Headers)

When the callout inspects `request_headers` (or `request_body`) and determines the request is safe:

1. **Responding to `request_headers` (`field 2` in `ProcessingRequest`)**:
   Return `ProcessingResponse` with `request_headers` (`field 1`, `HeadersResponse`):
   ```protobuf
   message HeadersResponse {
     CommonResponse response = 1;
   }

   message CommonResponse {
     enum ResponseStatus {
       CONTINUE = 0;
       CONTINUE_AND_REPLACE = 1;
     }
     ResponseStatus status = 1;
     HeaderMutation header_mutation = 2;
     BodyMutation body_mutation = 3;
     envoy.config.core.v3.HeaderMap trailers = 4;
     bool clear_route_cache = 5;
   }

   message HeaderMutation {
     repeated envoy.config.core.v3.HeaderValueOption set_headers = 1;
     repeated string remove_headers = 2;
   }

   message HeaderValueOption {
     envoy.config.core.v3.HeaderValue header = 1;
     // google.protobuf.BoolValue append = 2;
     enum HeaderAppendAction {
       APPEND_IF_EXISTS_OR_ADD = 0;
       ADD_IF_ABSENT = 1;
       OVERWRITE_IF_EXISTS_OR_ADD = 2;
       OVERWRITE_IF_EXISTS = 3;
     }
     HeaderAppendAction append_action = 3;
   }
   ```
   The callout can inject verified headers into the upstream request forwarded to `aegis-server`, such as:
   - `x-aegis-authz-extension: verified`
   - `x-aegis-model-armor-verdict: SAFE`
   - `x-aegis-extension-latency-ms: <ms>`

2. **Responding to `request_body` (`field 3` in `ProcessingRequest`)**:
   Return `ProcessingResponse` with `request_body` (`field 2`, `BodyResponse`):
   ```protobuf
   message BodyResponse {
     CommonResponse response = 1;
   }
   ```

#### Case B: **DENY** (`ImmediateResponse` with HTTP `403 Forbidden`)

When the callout detects an adversarial prompt injection, jailbreak attempt, SSRF/metadata exfiltration payload, or Model Armor `MATCH_FOUND` verdict (in either `request_headers` or `request_body`), it short-circuits the request at the Google Cloud Envoy proxy before the request ever reaches the upstream ADK agent container by returning `ProcessingResponse` with `immediate_response` (`field 7`):

```protobuf
message ImmediateResponse {
  envoy.type.v3.HttpStatus status = 1;
  HeaderMutation headers = 2;
  bytes body = 3;
  GrpcStatus status_details = 4; // field 4 is GrpcStatus, field 5 is string details
  string details = 5;
}

// envoy/type/v3/http_status.proto
message HttpStatus {
  StatusCode code = 1; // 403 = Forbidden, 401 = Unauthorized, 400 = BadRequest
}
```

When Envoy receives `immediate_response`:
- Envoy immediately terminates upstream forwarding and returns HTTP `403 Forbidden` directly to the caller.
- The response includes custom headers from `ImmediateResponse.headers` (e.g., `Content-Type: application/json`, `X-Aegis-Verdict: BLOCKED_BY_GCP_AUTHZ_EXTENSION`, `X-Aegis-Policy-ID: POL-GATEWAY-EXT-PROC-01`) and the structured JSON block payload in `ImmediateResponse.body`:
  ```json
  {
    "error": "blocked_by_gcp_authz_extension",
    "plane": "CLIENT_TO_AGENT",
    "policy": "aegis-agent-gateway-uap",
    "extension": "aegis-modelarmor-content-ext",
    "verdict": "BLOCK",
    "reason": "Model Armor + GCPAuthzExtension callout detected adversarial prompt injection / metadata exfiltration",
    "matched_filters": ["pi_and_jailbreak", "malicious_uris"]
  }
  ```

---

## 3. Zero-Dependency Protobuf Wire Encoding in Go (`google.golang.org/grpc` + `google.golang.org/protobuf`)

`github.com/gke-demos/agent-security/go.mod` **already includes**:
- `google.golang.org/grpc v1.84.0`
- `google.golang.org/protobuf v1.36.12`
- `golang.org/x/net v0.59.0` (`http2`)

Because adding `github.com/envoyproxy/go-control-plane` pulls in dozens of transitive xDS dependencies, we can define a compact, self-contained package (`internal/extproc`) using `google.golang.org/protobuf/encoding/protowire` (or lightweight structs implementing `proto.Message` / custom `grpc.Codec` or standard protobuf struct tags) with exact wire-compatible field numbers verified against `envoy/service/ext_proc/v3/external_processor.proto`:

| Message | Field Name | Field Number | Wire Type | Notes |
|---|---|---|---|---|
| `ProcessingRequest` | `async_mode` | `1` | Varint (`0`) | `bool` |
| `ProcessingRequest` | `request_headers` | `2` | Bytes (`2`) | `HttpHeaders` submessage |
| `ProcessingRequest` | `request_body` | `3` | Bytes (`2`) | `HttpBody` submessage |
| `ProcessingRequest` | `response_headers` | `4` | Bytes (`2`) | `HttpHeaders` submessage |
| `ProcessingRequest` | `response_body` | `5` | Bytes (`2`) | `HttpBody` submessage |
| `HttpHeaders` | `headers` | `1` | Bytes (`2`) | `HeaderMap` submessage |
| `HttpHeaders` | `end_of_stream` | `3` | Varint (`0`) | `bool` |
| `HeaderMap` | `headers` | `1` | Bytes (`2`) | Repeated `HeaderValue` |
| `HeaderValue` | `key` | `1` | Bytes (`2`) | `string` |
| `HeaderValue` | `value` | `2` | Bytes (`2`) | `string` |
| `HeaderValue` | `raw_value` | `3` | Bytes (`2`) | `bytes` (used by Cloud Load Balancing Envoy) |
| `HttpBody` | `body` | `1` | Bytes (`2`) | `bytes` |
| `HttpBody` | `end_of_stream` | `2` | Varint (`0`) | `bool` |
| `ProcessingResponse` | `request_headers` | `1` | Bytes (`2`) | `HeadersResponse` submessage |
| `ProcessingResponse` | `request_body` | `2` | Bytes (`2`) | `BodyResponse` submessage |
| `ProcessingResponse` | `response_headers` | `3` | Bytes (`2`) | `HeadersResponse` submessage |
| `ProcessingResponse` | `response_body` | `4` | Bytes (`2`) | `BodyResponse` submessage |
| `ProcessingResponse` | `immediate_response` | `7` | Bytes (`2`) | `ImmediateResponse` submessage |
| `HeadersResponse` | `response` | `1` | Bytes (`2`) | `CommonResponse` submessage |
| `BodyResponse` | `response` | `1` | Bytes (`2`) | `CommonResponse` submessage |
| `CommonResponse` | `status` | `1` | Varint (`0`) | `0 = CONTINUE`, `1 = CONTINUE_AND_REPLACE` |
| `CommonResponse` | `header_mutation` | `2` | Bytes (`2`) | `HeaderMutation` submessage |
| `HeaderMutation` | `set_headers` | `1` | Bytes (`2`) | Repeated `HeaderValueOption` |
| `HeaderMutation` | `remove_headers` | `2` | Bytes (`2`) | Repeated `string` |
| `HeaderValueOption` | `header` | `1` | Bytes (`2`) | `HeaderValue` (`key` + `raw_value`) |
| `HeaderValueOption` | `append_action` | `3` | Varint (`0`) | `2 = OVERWRITE_IF_EXISTS_OR_ADD` |
| `ImmediateResponse` | `status` | `1` | Bytes (`2`) | `HttpStatus` submessage (`field 1` = Varint `403`) |
| `ImmediateResponse` | `headers` | `2` | Bytes (`2`) | `HeaderMutation` submessage |
| `ImmediateResponse` | `body` | `3` | Bytes (`2`) | `bytes` (UTF-8 JSON payload) |
| `ImmediateResponse` | `details` | `5` | Bytes (`2`) | `string` (audit reason) |

Using `protowire` in `internal/extproc` takes ~120 lines of pure Go with `google.golang.org/grpc` and `google.golang.org/protobuf/encoding/protowire`, requires zero external `.proto` codegen or `go.mod` additions, and can be unit-tested deterministically against standard Envoy wire payloads.

---

## 4. Kubernetes `Service`, TLS/HTTP2 Transport & Health Check Architecture

### Why `appProtocol: HTTP2` Over TLS is Required

In the GKE Gateway Controller (`gke-l7-regional-external-managed`), translating any `GCPAuthzExtension` or `GCPTrafficExtension` with a `Service` `backendRef` runs a strict check on the referenced `Service`:
1. The `Service` must contain a `ServicePort` matching `backendRef.port`.
2. That `ServicePort` **must** have `appProtocol: HTTP2` (exact string).
3. The controller creates a Compute Engine `BackendService` with `protocol: HTTP2` and a default `HealthCheck` with `type: HTTP2` and `requestPath: "/"`.
4. Compute Engine `BackendService` with `protocol: HTTP2` establishes **TLS-encrypted HTTP/2 (`h2` ALPN)** connections from the Google Cloud Envoy proxies and Google Cloud health check probers (`35.191.0.0/16`, `130.211.0.0/22`) to the Pod endpoints in the standalone NEG (`cloud.google.com/neg: '{"ingress":true}'`). Compute Engine does not validate the leaf certificate authority on backend TLS connections by default, so an ephemeral self-signed ECDSA P-256 certificate generated at process startup with `NextProtos: []string{"h2", "http/1.1"}` works out-of-the-box without external certificate management.

### Unified HTTP/2 + gRPC Multiplexer on Port `8443`

By listening on `:8443` (or `-ext-proc-addr=:8443`) inside `aegis-server` with a `tls.Listener` (`NextProtos: []string{"h2", "http/1.1"}`) and `golang.org/x/net/http2.Server`, a single port handles both:
- **GCE `HTTP2` Health Check Probes**: Any request where `r.ProtoMajor == 2` and `Content-Type` does not start with `application/grpc` (such as `GET /` or `GET /healthz`) returns `200 OK` (`{"status":"ok","service":"aegis-model-armor-ext-proc"}`).
- **Envoy `ext_proc` gRPC Streams**: Any request with `Content-Type: application/grpc*` is delegated to `grpcServer.ServeHTTP(w, r)`.

```go
mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		grpcServer.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","component":"aegis-model-armor-ext-proc"}`))
})
```

### Kubernetes `Service` & `GCPAuthzExtension` Manifests

```yaml
apiVersion: v1
kind: Service
metadata:
  name: aegis-model-armor-ext-proc
  namespace: aegis-system
  annotations:
    cloud.google.com/neg: '{"ingress": true}'
spec:
  selector:
    app: aegis-sre
  ports:
    - name: grpc-ext-proc
      port: 443
      targetPort: 8443
      protocol: TCP
      appProtocol: HTTP2
---
apiVersion: networking.gke.io/v1
kind: GCPAuthzExtension
metadata:
  name: aegis-modelarmor-content-ext
  namespace: aegis-system
spec:
  authority: aegis-model-armor-ext-proc.aegis-system.svc.cluster.local
  timeout: 2000ms
  failOpen: false
  wireFormat: ExtProcGRPC
  backendRef:
    group: ""
    kind: Service
    name: aegis-model-armor-ext-proc
    port: 443
```

### Pairing `GCPAuthzExtension` with `GCPTrafficExtension` for Full Request Body Screening

Because Cloud Service Extensions `AuthzExtension` (`REQUEST_AUTHZ`) only sends `REQUEST_HEADERS` to the callout, while `POST /a2a` and `POST /api/sessions/{id}/turns/stream` carry JSON prompts in the HTTP request body:
1. **Header Inspection (`REQUEST_HEADERS` via `GCPAuthzExtension` + `GCPAuthzPolicy`)**:
   - Inspects `:path`, `:method`, `x-aegis-prompt-screen` (or `x-aegis-red-payload`), and `user-agent` headers during the `REQUEST_AUTHZ` phase.
   - If `x-aegis-prompt-screen` (or any inspected header) contains a prompt injection / jailbreak / SSRF pattern or triggers a Model Armor `sanitizeUserPrompt` match, `GCPAuthzExtension` immediately returns `ImmediateResponse{Status: 403}` during `REQUEST_AUTHZ`.
2. **Body Inspection (`RequestHeaders` + `RequestBody` via `GCPTrafficExtension`)**:
   - Attaching a `GCPTrafficExtension` (`aegis-modelarmor-body-ext`) to `Gateway/aegis-ingress-gateway` referencing the **same** `Service/aegis-model-armor-ext-proc` (`port: 443`) with `supportedEvents: [RequestHeaders, RequestBody]` causes the regional Envoy proxy to stream the HTTP POST body (`POST /a2a`, `POST /api/sessions/*/turns/stream`) to `ExternalProcessor/Process` as `ProcessingRequest.request_body` (`HttpBody`).
   - If the POST JSON body contains an adversarial prompt injection or triggers Model Armor `sanitizeUserPrompt`, the callout returns `ImmediateResponse{Status: 403}` before the request reaches the ADK agent handler!

```yaml
apiVersion: networking.gke.io/v1
kind: GCPTrafficExtension
metadata:
  name: aegis-modelarmor-body-ext
  namespace: aegis-system
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: aegis-ingress-gateway
  extensionChains:
    - name: model-armor-body-chain
      matchCondition:
        celExpression: "request.method == 'POST' && (request.path == '/a2a' || request.path.startsWith('/api/sessions/'))"
      extensions:
        - name: model-armor-ext-proc
          authority: aegis-model-armor-ext-proc.aegis-system.svc.cluster.local
          timeout: 2000ms
          failOpen: false
          supportedEvents:
            - RequestHeaders
            - RequestBody
          requestBodySendMode: FullDuplexStreamed
          backendRef:
            group: ""
            kind: Service
            name: aegis-model-armor-ext-proc
            port: 443
```

---

## 5. Dual-Path Red-vs-Blue Behavior (`:8080` Unprotected vs. `:80` Gateway Protected)

This architecture gives the live stage demo a true, verifiable network-edge split:

1. **Red Path (`UNPROTECTED` Direct Baseline — `:8080` LoadBalancer `Service/aegis-red-direct`)**:
   - Sends `POST /a2a` or `POST /api/sessions/{id}/turns/stream` directly to `aegis-red-direct` (`X-Agent-Gateway-Ingress: false`), bypassing `Gateway/aegis-ingress-gateway`, `GCPAuthzPolicy`, `GCPAuthzExtension`, and `GCPTrafficExtension`.
   - Furthermore, the in-cluster `ExternalProcessor` callout exposes a lightweight telemetry ring buffer (`GET /api/gateway/ext-proc/events`) on `aegis-server` so the UI and presenter can see live `ext_proc` callout invocations, latency, Model Armor verdicts, and blocked headers/payloads in real time.

2. **Blue Path (`PROTECTED` GKE Agent Gateway — `:80` `Gateway/aegis-ingress-gateway`)**:
   - Every request matching `GCPAuthzPolicy/aegis-agent-gateway-uap` and `GCPTrafficExtension/aegis-modelarmor-body-ext` triggers an Envoy `ExternalProcessor/Process` gRPC stream from the Google Cloud regional Application Load Balancer to `Service/aegis-model-armor-ext-proc:443` (`aegis-server:8443`).
   - Safe requests receive `CommonResponse{Status: CONTINUE}` with injected header `X-Aegis-Authz-Extension: verified` and proceed to the ADK runner.
   - Adversarial requests (e.g., prompt injection `"Ignore all previous instructions..."`, metadata SSRF `169.254.169.254`, or secret exfiltration) receive `ImmediateResponse{Status: 403 Forbidden}` directly from the Google Cloud Envoy proxy at the `CLIENT_TO_AGENT` edge.
