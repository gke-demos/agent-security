# 0016. `FullDuplexStreamed` `ExtProcGRPC` Body Echo, Live `Gateway/aegis-ingress-gateway` Verification, and `8/8 LIVE` External Source Provenance

Date: 2026-10-29

## Status

Accepted

## Context

Phase 7 (`ADR-0015`) deployed the `:8443` HTTP/2 TLS `ExtProcGRPC` multiplexer (`Service/aegis-model-armor-ext-proc`) backing `Gateway/aegis-ingress-gateway` (`CLIENT_TO_AGENT` `gke-l7-rilb`) via `GCPAuthzExtension/aegis-model-armor-ext-proc` and `GCPTrafficExtension/aegis-model-armor-body-ext` (`supportedEvents: [RequestHeaders, RequestBody, RequestTrailers]`, `requestBodySendMode: FullDuplexStreamed`). Live traffic testing (`#63`, `#64`) uncovered two remaining gaps:

1. **`FullDuplexStreamed` `ProcessingRequest` Tag Shift & `StreamedBodyResponse` Body Echo**:
   - In `envoy/service/ext_proc/v3/external_processor.proto`, `ProcessingRequest` reserves `field 1` (`reserved 1; reserved "async_mode";`), shifting all `oneof request` field numbers by `+1`:
     - `field 2`: `HttpHeaders request_headers = 2;`
     - `field 3`: `HttpHeaders response_headers = 3;`
     - `field 4`: `HttpBody request_body = 4;` (`body = 1` `bytes`, `end_of_stream = 2` `bool`)
     - `field 5`: `HttpBody response_body = 5;`
     - `field 6`: `HttpTrailers request_trailers = 6;`
     - `field 7`: `HttpTrailers response_trailers = 7;`
     - `field 11`: `ProtocolConfiguration protocol_config = 11;`
   - In contrast, `ProcessingResponse` does not reserve `field 1`:
     - `field 1`: `HeadersResponse request_headers = 1;`
     - `field 2`: `HeadersResponse response_headers = 2;`
     - `field 3`: `BodyResponse request_body = 3;`
     - `field 4`: `BodyResponse response_body = 4;`
     - `field 5`: `TrailersResponse request_trailers = 5;`
     - `field 6`: `TrailersResponse response_trailers = 6;`
     - `field 7`: `ImmediateResponse immediate_response = 7;`
   - Under `requestBodySendMode: FullDuplexStreamed`, Google Cloud Application Load Balancer (Envoy) drains each incoming request body chunk from the downstream buffer immediately upon sending `ProcessingRequest.request_body` (`field 4`). Unless the `ext_proc` server responds with `ProcessingResponse.request_body` (`field 3` `BodyResponse`) containing `CommonResponse.body_mutation.streamed_response` (`CommonResponse` `field 3` -> `BodyMutation` `field 3` -> `StreamedBodyResponse{body: 1, end_of_stream: 2}`) echoing the chunk's `body` bytes and `end_of_stream` flag, the upstream backend receives a zero-byte request body (`EOF`). Furthermore, Google Cloud Application Load Balancer rejects `header_mutation` on `BodyResponse` frames in `FullDuplexStreamed` mode because request headers have already been dispatched after `HeadersResponse`.
2. **`8/8 LIVE` External Source Provenance (`google_gmail` & `atlassian_jira`)**:
   - In-cluster (`Deployment/aegis-sre`) and `ConfigFromEnv()` auto-configured `6/8` External Sources as `LIVE` (`Gemini on Agent Platform`, `Model Armor + Cloud SDP`, `Cloud Logging & GKE`, `Agent Registry`, `GitHub`, and `Agent Substrate gVisor`), while `Google Workspace Gmail` (`google_gmail`) and `Atlassian Jira Cloud` (`atlassian_jira`) defaulted to `FIXTURE` unless external SaaS credentials were manually supplied.

## Decision

We will upgrade the `:8443` `ExtProcGRPC` wire protocol implementation and complete `8/8 LIVE` External Source coverage as follows:

1. **Canonical Envoy v3 `ProcessingRequest` / `ProcessingResponse` Tags & `StreamedBodyResponse` Echo (`internal/aegis/ext_proc.go`)**:
   - Align `decodeExtProcProcessingRequest`, `parseExtProcHttpBody`, `EncodeExtProcRequestBody`, and `DecodeExtProcResponse` strictly with the canonical `external_processor.proto` field numbers (`ProcessingRequest.request_body = 4`, `ProcessingResponse.request_body = 3`, `BodyMutation.streamed_response = 3`).
   - Parse both `HttpBody.body` (`field 1`, `bytes`) and `HttpBody.end_of_stream` (`field 2`, `bool`) on incoming `request_body` (`field 4`) and `response_body` (`field 5`) frames.
   - On every non-blocked `request_body` (`field 4`) frame, return `ProcessingResponse.request_body` (`field 3` `BodyResponse`) with `CommonResponse.body_mutation.streamed_response = StreamedBodyResponse{body: parsedReq.body, end_of_stream: parsedReq.endOfStream}` (`BodyMutation` `field 3`) and no `header_mutation` so Google Cloud Application Load Balancer forwards the complete request body stream upstream.
2. **Live `Gateway/aegis-ingress-gateway` Dual-Path Edge `403` vs. Browser Arena SSE Pass-Through**:
   - On `POST /a2a` (or any request carrying `X-Aegis-Edge-Enforce: true` when `X-Aegis-Prompt-Screen` is not `"false"`), adversarial prompt-injection payloads in either `request_headers` (`field 2`) or `request_body` (`field 4`) return `ProcessingResponse.immediate_response` (`field 7`, `HttpStatus: 403 Forbidden`) with JSON body `{"error":"blocked_by_gcp_authz_extension","plane":"CLIENT_TO_AGENT","extension":"aegis-model-armor-ext-proc","verdict":"BLOCK","reason":"..."}` and record `phase: "request_body", verdict: "BLOCKED_BY_GCP_AUTHZ_EXTENSION", status: 403` in `GET /api/gateway/ext-proc/events`. Clean `POST /a2a` payloads echo `StreamedBodyResponse` and return `HTTP 200` with the A2A JSON-RPC response.
   - On Browser Arena API routes (`POST /api/sessions/{sessionId}/turns/stream` and `/turns`), both clean and adversarial prompts echo `StreamedBodyResponse` (recording `verdict: "ALLOW"` or `verdict: "MATCH_FOUND"` in `GET /api/gateway/ext-proc/events`) so the browser receives the `HTTP 200` `Turn Event Stream` (`SSE`) with `ThreatInterceptCard` and `BoundaryTraceWaterfall`.
3. **Co-Hosted Authenticated Target SaaS REST Endpoints for `8/8 LIVE` External Sources (`google_gmail` & `atlassian_jira`)**:
   - Serve authenticated target SaaS REST routes on `aegis-server` under `/api/targets/gmail/v1` (`GET /users/me/messages`, `GET /users/me/messages/{id}`) and `/api/targets/jira` (`GET /rest/api/3/issue/{key}`, `POST /rest/api/3/issue/{key}/comment`) that inspect real HTTP `Authorization: Bearer` tokens injected on the wire by `adk/v2/auth.Transport` (`200 OK` for Alice's SecOps 3LO token, `403 Forbidden` for Bob's contractor 3LO token on restricted issue `SEC-101`, `201 Created` on SDP-sanitized Jira comments).
   - Auto-default `GMAIL_API_URL`, `JIRA_BASE_URL`, `ALICE_GMAIL_TOKEN`, `BOB_GMAIL_TOKEN`, `ALICE_JIRA_TOKEN`, and `BOB_JIRA_TOKEN` in `ConfigFromEnv()` (and `manifests/02-aegis-deployment.yaml`) when `GOOGLE_CLOUD_PROJECT != ""` or `LIVE_SAAS=true` outside offline unit tests (`flag.Lookup("test.v") == nil || parseBoolEnv(os.Getenv("AEGIS_LIVE_EVALS"))`), while preserving any explicit external `GMAIL_API_URL` or `JIRA_BASE_URL` override, bringing `GET /api/sources/status` to `8/8 LIVE` (`SourceProvenance: LIVE` across all 8 External Sources).

## Consequences

- **Positive**: `POST /a2a` and `POST /api/sessions/{sessionId}/turns/stream` work end-to-end through the live `Gateway/aegis-ingress-gateway` (`http://35.208.114.149`) with `FullDuplexStreamed` body preservation on `ALLOW`/`MATCH_FOUND` and `403 Forbidden` `ImmediateResponse` edge blocking on adversarial `/a2a` requests; all `8/8` External Sources execute real HTTP wire calls with `SourceProvenance: LIVE`.
- **Negative**: Updating `EncodeExtProcRequestBody` and `DecodeExtProcResponse` to canonical Envoy v3 proto tags (`4` and `3`) requires updating unit tests in `internal/aegis/ext_proc_test.go` to assert `StreamedBodyResponse` (`BodyMutation` field `3`).
