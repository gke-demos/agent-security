# Envoy `ext_proc` `FullDuplexStreamed` `StreamedBodyResponse` & In-Flight `ImmediateResponse` Wire Contract on Google Cloud Application Load Balancer

## Question

What is the exact protobuf wire encoding (`protowire` field numbers and wire types) and stream state-machine contract required for an Envoy `ext_proc` (`envoy.service.ext_proc.v3.ExternalProcessor/Process`) server backing a Google Cloud Application Load Balancer (`gke-l7-regional-external-managed`) `GCPTrafficExtension` (`requestBodySendMode: FullDuplexStreamed`) to:

1. Echo/forward unmodified HTTP request body bytes (`POST /a2a` and `POST /api/sessions/{sessionId}/turns/stream`) to the upstream backend without truncating the body to `0` bytes (`EOF`)?
2. Short-circuit malicious `POST` request bodies mid-stream with an in-flight `ImmediateResponse` (`field 7`, `HttpStatus: 403`) on edge-enforced routes (`POST /a2a` or `X-Aegis-Edge-Enforce: true`) while allowing browser Arena turns (`POST /api/sessions/{sessionId}/turns/stream`) to pass through with `MATCH_FOUND` telemetry for in-process `AegisSecurityPlugin` (`BeforeModel`) interception?

---

## Executive Summary

When a `GCPTrafficExtension` on Google Cloud Application Load Balancer configures `supportedEvents: [RequestHeaders, RequestBody, RequestTrailers]` with `requestBodySendMode: FullDuplexStreamed` (`ProcessingMode.BodySendMode.FULL_DUPLEX_STREAMED = 4`), Envoy's `ext_proc` filter **immediately drains every incoming downstream request body chunk** from its internal buffer (`data.drain(data.length())`) as soon as it sends `ProcessingRequest.request_body` (`field 4`) to the `ext_proc` gRPC stream. Envoy relies on the `ext_proc` server to return the body bytes inside `ProcessingResponse.request_body` (`field 3` `BodyResponse`) -> `CommonResponse` (`field 1`) -> `body_mutation` (`field 3` `BodyMutation`) -> `streamed_response` (`field 3` `StreamedBodyResponse`).

Investigation of the upstream Envoy `external_processor.proto` specification, Envoy's `Filter` / `ProcessorState` C++ state machine, the live `gcptrafficextensions.networking.gke.io` CRD schema, and `internal/aegis/ext_proc.go` uncovered **three root causes** explaining why `POST` request bodies reached the upstream `aegis-sre` backend as `0` bytes (`EOF`):

1. **`ProcessingRequest` Field Number Offset (`reserved 1` in `ProcessingRequest`)**:
   In `envoy.service.ext_proc.v3.ProcessingRequest`, field `1` is `reserved 1; reserved "async_mode";`, shifting every `oneof request` field by `+1`:
   - `request_headers` = **field `2`**
   - `response_headers` = **field `3`**
   - `request_body` = **field `4`** (`HttpBody`: `body = 1`, `end_of_stream = 2`)
   - `response_body` = **field `5`**
   - `request_trailers` = **field `6`**
   - `response_trailers` = **field `7`**
   - `protocol_config` = **field `11`** (`ProtocolConfiguration`: `request_body_mode = 1`, `response_body_mode = 2`, `send_body_without_waiting_for_header_response = 3`)

   In [`internal/aegis/ext_proc.go`](../../internal/aegis/ext_proc.go), `decodeExtProcProcessingRequest` had `case 3:` mapped to `request_body` and `case 4:` mapped to `response_headers` (and `EncodeExtProcRequestBody` encoded tag `3` instead of `4`). When Google Cloud Application Load Balancer sent `ProcessingRequest.request_body` on **field `4`**, `ext_proc.go` misclassified the request body chunk as `response_headers`!

2. **`ProcessingResponse` Field Numbers (`request_body = 3`, `response_headers = 2`)**:
   In `envoy.service.ext_proc.v3.ProcessingResponse`, field `1` is **not** reserved, so `oneof response` uses:
   - `request_headers` = **field `1`** (`HeadersResponse`)
   - `response_headers` = **field `2`** (`HeadersResponse`)
   - `request_body` = **field `3`** (`BodyResponse`)
   - `response_body` = **field `4`** (`BodyResponse`)
   - `request_trailers` = **field `5`** (`TrailersResponse`)
   - `response_trailers` = **field `6`** (`TrailersResponse`)
   - `immediate_response` = **field `7`** (`ImmediateResponse`)

   In [`internal/aegis/ext_proc.go`](../../internal/aegis/ext_proc.go), `evaluateExtProcPhase` set `responseFieldNum = 2` (`response_headers`) for `request_body` and `3` (`request_body`) for `response_headers`. Because of Bug #1 (`field 4` misclassified as `hasResponseHeaders`), `handleProcessStream` skipped `evaluateExtProcPhase` on the request body chunk and replied on tag `3` (`BodyResponse`) containing only `header_mutation` (`field 2`) and **no `body_mutation`**.

3. **Missing `BodyMutation.streamed_response` (`field 3` `StreamedBodyResponse`) in `FullDuplexStreamed` Mode**:
   In Envoy's `ProcessorState::handleStreamedBodyCallback`, when `body_mode_ == FULL_DUPLEX_STREAMED`:
   - Envoy requires `CommonResponse.body_mutation.has_streamed_response()` (`BodyMutation` **field `3`**, `StreamedBodyResponse`) to be present on every `BodyResponse` (`ProcessingResponse` **field `3`**).
   - If `streamed_response` is absent (for example, an empty `CommonResponse` or a `CommonResponse` with only `header_mutation`), Envoy logs `FailedPreconditionError("spurious message: Normal body mutation response is received while body_mode_ is FULL_DUPLEX_STREAMED")` and injects **zero bytes** into the upstream filter chain. Because the downstream buffer was already drained upon sending `ProcessingRequest.request_body`, the upstream backend receives an empty body (`EOF`) when the stream closes.
   - Note the distinction between the enum value and the protobuf field tag: `ProcessingMode.BodySendMode.FULL_DUPLEX_STREAMED` is enum value **`4`**, whereas `BodyMutation.streamed_response` in `external_processor.proto` is **field `3`** (`StreamedBodyResponse streamed_response = 3;`).

---

## Detailed Findings

### 1. Exact Protobuf Wire Layout (`envoy.service.ext_proc.v3`)

#### 1.1 `ProcessingRequest` (`envoy.service.ext_proc.v3.ProcessingRequest`)

```protobuf
message ProcessingRequest {
  reserved 1;
  reserved "async_mode";

  oneof request {
    HttpHeaders request_headers = 2;
    HttpHeaders response_headers = 3;
    HttpBody request_body = 4;
    HttpBody response_body = 5;
    HttpTrailers request_trailers = 6;
    HttpTrailers response_trailers = 7;
  }

  envoy.config.core.v3.Metadata metadata_context = 8;
  map<string, google.protobuf.Struct> attributes = 9;
  bool observability_mode = 10;
  ProtocolConfiguration protocol_config = 11;
}
```

Sub-message wire tags inside `ProcessingRequest`:

| Parent Message | Field Name | Field Number | Wire Type (`protowire`) | Notes |
| :--- | :--- | :---: | :---: | :--- |
| `ProcessingRequest` | `request_headers` | `2` | `BytesType` (`2`) | `HttpHeaders` message |
| `ProcessingRequest` | `response_headers` | `3` | `BytesType` (`2`) | `HttpHeaders` message |
| `ProcessingRequest` | `request_body` | `4` | `BytesType` (`2`) | `HttpBody` message |
| `ProcessingRequest` | `response_body` | `5` | `BytesType` (`2`) | `HttpBody` message |
| `ProcessingRequest` | `request_trailers` | `6` | `BytesType` (`2`) | `HttpTrailers` message |
| `ProcessingRequest` | `response_trailers` | `7` | `BytesType` (`2`) | `HttpTrailers` message |
| `ProcessingRequest` | `observability_mode` | `10` | `VarintType` (`0`) | `bool` |
| `ProcessingRequest` | `protocol_config` | `11` | `BytesType` (`2`) | `ProtocolConfiguration` sent on first message of stream |
| `HttpHeaders` | `headers` | `1` | `BytesType` (`2`) | `envoy.config.core.v3.HeaderMap` |
| `HttpHeaders` | `end_of_stream` | `3` | `VarintType` (`0`) | `bool` (`true` for header-only requests like `GET`) |
| `HttpBody` | `body` | `1` | `BytesType` (`2`) | Raw HTTP body chunk `bytes` |
| `HttpBody` | `end_of_stream` | `2` | `VarintType` (`0`) | `bool` (`true` on final body chunk when no trailers follow) |
| `HttpTrailers` | `trailers` | `1` | `BytesType` (`2`) | `envoy.config.core.v3.HeaderMap` |
| `ProtocolConfiguration` | `request_body_mode` | `1` | `VarintType` (`0`) | `BodySendMode`: `NONE=0`, `STREAMED=1`, `BUFFERED=2`, `BUFFERED_PARTIAL=3`, `FULL_DUPLEX_STREAMED=4`, `GRPC=5` |
| `ProtocolConfiguration` | `response_body_mode` | `2` | `VarintType` (`0`) | `BodySendMode` enum |
| `ProtocolConfiguration` | `send_body_without_waiting_for_header_response` | `3` | `VarintType` (`0`) | `bool` |

#### 1.2 `ProcessingResponse` (`envoy.service.ext_proc.v3.ProcessingResponse`)

```protobuf
message ProcessingResponse {
  oneof response {
    HeadersResponse request_headers = 1;
    HeadersResponse response_headers = 2;
    BodyResponse request_body = 3;
    BodyResponse response_body = 4;
    TrailersResponse request_trailers = 5;
    TrailersResponse response_trailers = 6;
    ImmediateResponse immediate_response = 7;
  }

  google.protobuf.Struct dynamic_metadata = 8;
  envoy.extensions.filters.http.ext_proc.v3.ProcessingMode mode_override = 9;
  google.protobuf.Duration override_message_timeout = 10;
}
```

#### 1.3 `BodyResponse`, `CommonResponse`, `BodyMutation`, and `StreamedBodyResponse`

```protobuf
message BodyResponse {
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

message BodyMutation {
  oneof mutation {
    bytes body = 1;
    bool clear_body = 2;
    StreamedBodyResponse streamed_response = 3;
  }
}

message StreamedBodyResponse {
  bytes body = 1;
  bool end_of_stream = 2;
  bool end_of_stream_without_message = 3;
  bool grpc_message_compressed = 4;
  bool drain_complete = 5;
}
```

Wire encoding chain for a `FullDuplexStreamed` request body echo (`ProcessingResponse` for `request_body`):

```text
ProcessingResponse
└── field 3 (BytesType): BodyResponse (request_body)
    └── field 1 (BytesType): CommonResponse (response)
        ├── field 2 (BytesType, optional): HeaderMutation (header_mutation)
        └── field 3 (BytesType): BodyMutation (body_mutation)
            └── field 3 (BytesType): StreamedBodyResponse (streamed_response)
                ├── field 1 (BytesType): bytes body          (raw chunk bytes from HttpBody.body)
                └── field 2 (VarintType): bool end_of_stream (1 if HttpBody.end_of_stream == true)
```

> **Important Protobuf Note**: In proto3, scalar fields with default values (`false` / `0` / empty `bytes`) do not need to be emitted on the wire unless non-empty/true, **except** that the enclosing sub-message `BodyMutation.streamed_response` (`field 3` on `BodyMutation`) **must** be present (even if ` StreamedBodyResponse` itself is 0 bytes when `body` is empty and `end_of_stream` is `false`) so that `body_mutation().has_streamed_response()` evaluates to `true` in Envoy!

---

### 2. Envoy `FullDuplexStreamed` State Machine Contract

In Envoy's `ext_proc` filter (`source/extensions/filters/http/ext_proc/ext_proc.cc` and `processor_state.cc`):

1. **Downstream Request Headers (`decodeHeaders`)**:
   - Envoy opens the bidirectional gRPC `Process` stream and sends `ProcessingRequest` containing `protocol_config` (`field 11`, with `request_body_mode = 4` for `FULL_DUPLEX_STREAMED`) and `request_headers` (`field 2`, with `end_of_stream = false` when a request body follows).
   - Envoy sets `callback_state_ = HeadersCallback` and returns `FilterHeadersStatus::StopAllIterationAndWatermark`, holding headers until `HeadersResponse` (`ProcessingResponse` `field 1`) or `ImmediateResponse` (`ProcessingResponse` `field 7`) arrives.
   - When the `ext_proc` server responds with `ProcessingResponse{request_headers: HeadersResponse{response: CommonResponse{status: CONTINUE, header_mutation: ...}}}`, Envoy applies `header_mutation` to the request headers, switches `callback_state_` to `StreamedBodyCallback`, and calls `injectHeadersToFilterChain(false)` (`continueDecoding()`).

2. **Downstream Request Body (`decodeData` -> `handleDataStreamedModeBase`)**:
   - When `state.bodyMode() == ProcessingMode::FULL_DUPLEX_STREAMED`:
     - Envoy sends `ProcessingRequest{request_body: HttpBody{body: data, end_of_stream: end_stream}}` (`field 4`).
     - Envoy **immediately calls `data.drain(data.length())`** on the downstream buffer and increments `num_body_chunks_sent_`.
     - Envoy returns `FilterDataStatus::StopIterationNoBuffer` while waiting for the `ext_proc` server to stream back chunks.
   - When `ProcessorState::handleStreamedBodyCallback` receives `ProcessingResponse{request_body: BodyResponse{...}}` (`field 3`):
     - Because `body_mode_ == FULL_DUPLEX_STREAMED`, Envoy checks `common_response.body_mutation().has_streamed_response()` (`BodyMutation` `field 3`).
     - If `has_streamed_response()` is `false`, Envoy returns `absl::FailedPreconditionError("spurious message: Normal body mutation response is received while body_mode_ is FULL_DUPLEX_STREAMED")`, which fails the `ext_proc` processing without injecting any body bytes.
     - If `has_streamed_response()` is `true`, `handleDuplexStreamedBodyResponse` extracts `streamed_response.body()` (`field 1`) and `streamed_response.end_of_stream()` (`field 2`), calls `injectDataToFilterChain(buffer, end_of_stream)`, and when `end_of_stream == true` transitions `callback_state_` to `Idle` (or `TrailersCallback` if trailers were held) and calls `continueIfNecessary()`.

3. **Downstream Request Trailers (`decodeTrailers`)**:
   - Because `GCPTrafficExtension` requires `RequestTrailers` in `supportedEvents` whenever `requestBodySendMode: FullDuplexStreamed` is configured, if a client sends HTTP trailers, Envoy sends `ProcessingRequest{request_trailers: HttpTrailers{...}}` (`field 6`).
   - In `FULL_DUPLEX_STREAMED` mode, Envoy holds trailers until the `ext_proc` server returns a `StreamedBodyResponse` with `end_of_stream = true`, and expects `ProcessingResponse{request_trailers: TrailersResponse{}}` (`field 5`) if `request_trailers` was sent.
   - Standard HTTP/1.1 or HTTP/2 `POST /a2a` and `POST /api/sessions/{sessionId}/turns/stream` requests have no trailers, so `HttpBody.end_of_stream` is `true` on the final `request_body` message. Still, handling `request_trailers` (`ProcessingRequest` `field 6` -> `ProcessingResponse` `field 5`) ensures full protocol compliance when `RequestTrailers` is enabled in `supportedEvents`.

---

### 3. `GCPTrafficExtension` `requestBodySendMode` Options (`FullDuplexStreamed` vs `Streamed`)

Inspection of the live GKE CRD `gcptrafficextensions.networking.gke.io` (`networking.gke.io/v1`) and the GKE Gateway controller translator shows:

```yaml
requestBodySendMode:
  description: |-
    RequestBodySendModeDetermines how the proxy buffers and sends the HTTP request body to the extension.
    If not set, and RequestBody is in SupportedEvents, this defaults to "Streamed".
    Must not be set if RequestBody is not in SupportedEvents.
  enum:
    - Streamed
    - FullDuplexStreamed
  type: string
```

Comparison of the two modes supported by `GCPTrafficExtension`:

| Mode | `supportedEvents` Requirement | Envoy `BodySendMode` Enum | How Envoy Handles Request Body | Required `BodyResponse` Format to Forward Unmodified Body |
| :--- | :--- | :---: | :--- | :--- |
| `FullDuplexStreamed` | `[RequestHeaders, RequestBody, RequestTrailers]` | `FULL_DUPLEX_STREAMED` (`4`) | Drains downstream buffer immediately upon sending `request_body`; relies entirely on `StreamedBodyResponse` chunks returned by `ext_proc` | `BodyResponse` (`field 3`) -> `CommonResponse` (`field 1`) -> `BodyMutation` (`field 3`) -> `StreamedBodyResponse` (`field 3`) with `body = chunk`, `end_of_stream = eos` |
| `Streamed` | `[RequestHeaders, RequestBody]` | `STREAMED` (`1`) | Enqueues each downstream chunk into `chunk_queue_` while sending `request_body`; dequeues and injects the original chunk when `BodyResponse` arrives | `BodyResponse` (`field 3`) -> `CommonResponse` (`field 1`) with `status = CONTINUE` (`0`) and **no** `streamed_response` (or `BodyMutation.body` `field 1` to replace chunk) |

**Recommendation**:
- Keep `manifests/03-gke-diy-agent-gateway.yaml` configured with `supportedEvents: [RequestHeaders, RequestBody, RequestTrailers]` and `requestBodySendMode: FullDuplexStreamed`.
- In `internal/aegis/ext_proc.go`, parse `ProcessingRequest.protocol_config.request_body_mode` (`field 11` -> `field 1`) per gRPC stream (defaulting to `FULL_DUPLEX_STREAMED = 4` when `request_body` is received and `protocol_config` was not set or set to `4`). When `request_body_mode == 1` (`STREAMED`), omit `streamed_response`; when `request_body_mode == 4` (`FULL_DUPLEX_STREAMED`, the default), always populate `BodyMutation.streamed_response` (`field 3`) with `body = parsedReq.body` and `end_of_stream = parsedReq.endOfStream`. This makes `aegis-sre` work seamlessly with both `FullDuplexStreamed` and `Streamed` modes!

---

### 4. In-Flight `ImmediateResponse` (`field 7`, `HttpStatus: 403`) & Header Mutation Semantics

#### 4.1 In-Flight `ImmediateResponse` (`403 Forbidden`) During `request_body`
When `ext_proc` receives `ProcessingRequest.request_body` (`field 4`) containing an adversarial prompt on an edge-enforced route (`POST /a2a` or `X-Aegis-Edge-Enforce: true`, with `X-Aegis-Prompt-Screen` not `"false"`):

- The `ext_proc` server returns `ProcessingResponse{immediate_response: ImmediateResponse{status: {code: 403}, headers: ..., body: ..., details: ...}}` (`field 7`).
- In Envoy's `Filter::onReceiveMessage` -> `sendImmediateResponse`, because `processing_request_headers_` is active and **no downstream HTTP response headers have been sent yet**, Envoy calls `encoder_callbacks_->sendLocalReply(403, body, modify_headers, grpc_status, details)` and closes the `ext_proc` stream.
- Google Cloud Application Load Balancer immediately returns `HTTP 403 Forbidden` with header `x-aegis-verdict: BLOCKED_BY_GCP_AUTHZ_EXTENSION` and the JSON error payload (`{"error":"Aegis Edge Gateway: Prompt Injection Blocked at Load Balancer","verdict":"BLOCKED_BY_GCP_AUTHZ_EXTENSION",...}`), never forwarding the malicious body to the upstream agent container.

#### 4.2 Header Mutation Timing & Browser Arena Soft-Enforced Turns (`POST /api/sessions/{sessionId}/turns/stream`)
- Per `external_processor.proto` (`BodyResponse` comment) and Envoy's `ProcessorState::handleDuplexStreamedBodyResponse`, `CommonResponse.header_mutation` (`field 2`) inside a `BodyResponse` (`ProcessingResponse` `field 3`) is ignored by Envoy in `STREAMED` and `FULL_DUPLEX_STREAMED` modes once `HeadersResponse` has already been processed (because Envoy already called `injectHeadersToFilterChain(false)` upon receiving `HeadersResponse`).
- On `request_headers` (`field 2`), `ext_proc` immediately returns `HeadersResponse` (`field 1`) with `x-aegis-authz-extension: verified` and `x-aegis-ext-proc-verdict: ALLOW` (or `BYPASSED_RED`), which Envoy injects into the upstream request headers.
- On `request_body` (`field 4`) for browser Arena turns (`POST /api/sessions/{sessionId}/turns/stream`, where `edgeEnforce` is `false`):
  1. `evaluateExtProcPhase` inspects `parsedReq.body` for prompt injection patterns.
  2. It records the `request_body` phase event (`ALLOW`, `MATCH_FOUND`, or `BYPASSED_RED`) in `extProcEvents` (`GET /api/gateway/ext-proc/events`), giving the UI and verification tests live observability that the Cloud LB called out to `ext_proc` on the request body.
  3. It returns `BodyResponse` (`ProcessingResponse` `field 3`) containing:
     - `CommonResponse.header_mutation` (`field 2`) with `x-aegis-authz-extension: verified` and `x-aegis-ext-proc-verdict: MATCH_FOUND` (retained for unit-test decoding via `DecodeExtProcResponse` and ignored harmlessly by Envoy in `FULL_DUPLEX_STREAMED` mode).
     - `CommonResponse.body_mutation` (`field 3`) -> `StreamedBodyResponse` (`field 3`) with `body = parsedReq.body` and `end_of_stream = parsedReq.endOfStream`.
  4. Envoy injects `parsedReq.body` into the upstream HTTP request stream, delivering the complete JSON turn payload to `aegis-sre`, where the in-process `AegisSecurityPlugin` (`BeforeModel`) intercepts the adversarial prompt and streams the `ThreatInterceptCard` and SSE trace frames back to the browser!

---

## Code Changes Required in Ticket #65 (`internal/aegis/ext_proc.go`)

1. **Fix `decodeExtProcProcessingRequest` and `EncodeExtProcRequestBody` Field Numbers**:
   - In `decodeExtProcProcessingRequest`:
     - `case 2`: `request_headers` (`HttpHeaders`: `headers = 1`, `end_of_stream = 3`)
     - `case 3`: `response_headers` (`HttpHeaders`)
     - `case 4`: `request_body` (`HttpBody`: `body = 1`, `end_of_stream = 2`)
     - `case 5`: `response_body` (`HttpBody`: `body = 1`, `end_of_stream = 2`)
     - `case 6`: `request_trailers` (`HttpTrailers`)
     - `case 7`: `response_trailers` (`HttpTrailers`)
     - `case 11`: `protocol_config` (`ProtocolConfiguration`: `request_body_mode = 1`, `response_body_mode = 2`)
   - In `EncodeExtProcRequestBody` (and add `EncodeExtProcRequestBodyWithEOS(body string, endOfStream bool)`):
     - Encode `HttpBody` inside `ProcessingRequest` **field `4`** (`request_body`), not field `3`, and support encoding `HttpBody.end_of_stream` (`field 2`).

2. **Fix `ProcessingResponse` Field Numbers and Add `StreamedBodyResponse` Encoding**:
   - In `evaluateExtProcPhase` and `handleProcessStream`:
     - `request_headers` response -> `ProcessingResponse` **field `1`** (`HeadersResponse`)
     - `response_headers` response -> `ProcessingResponse` **field `2`** (`HeadersResponse`)
     - `request_body` response -> `ProcessingResponse` **field `3`** (`BodyResponse`)
     - `response_body` response -> `ProcessingResponse` **field `4`** (`BodyResponse`)
     - `request_trailers` response -> `ProcessingResponse` **field `5`** (`TrailersResponse`)
     - `response_trailers` response -> `ProcessingResponse` **field `6`** (`TrailersResponse`)
     - `immediate_response` -> `ProcessingResponse` **field `7`** (`ImmediateResponse`)
   - Add `encodeExtProcBodyResponse(headers map[string]string, body []byte, endOfStream bool, fullDuplexStreamed bool) []byte`:
     - When `fullDuplexStreamed` is `true` (default for `FullDuplexStreamed`), encode `CommonResponse.body_mutation` (`field 3` `BodyMutation`) -> `streamed_response` (`field 3` `StreamedBodyResponse`) containing `body` (`field 1`) and `end_of_stream` (`field 2`).
   - Update `DecodedExtProcResponse` and `DecodeExtProcResponse`:
     - Treat `num == 1 || num == 2` as `IsHeadersResponse` (`request_headers` / `response_headers`) and `num == 3 || num == 4` as `IsBodyResponse` (`request_body` / `response_body`).
     - Decode `CommonResponse.body_mutation` (`field 3`) -> `StreamedBodyResponse` (`field 3`) into `StreamedBody []byte`, `StreamedEndOfStream bool`, and `HasStreamedBodyResponse bool` so unit tests can assert the exact wire bytes.
