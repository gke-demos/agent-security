package aegis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/encoding/protowire"
)

// rawBytesCodec implements grpc/encoding.Codec for raw []byte protobuf wire frames,
// allowing Envoy ext_proc v3 bidirectional streams to be served without external .proto codegen.
type rawBytesCodec struct{}

// ExtProcRawCodec returns a gRPC codec that marshals/unmarshals raw []byte frames.
func ExtProcRawCodec() encoding.Codec {
	return rawBytesCodec{}
}

func (rawBytesCodec) Marshal(v any) ([]byte, error) {
	switch b := v.(type) {
	case []byte:
		return b, nil
	case *[]byte:
		if b == nil {
			return nil, nil
		}
		return *b, nil
	default:
		return nil, fmt.Errorf("ext_proc rawBytesCodec: unsupported Marshal type %T", v)
	}
}

func (rawBytesCodec) Unmarshal(data []byte, v any) error {
	ptr, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("ext_proc rawBytesCodec: unsupported Unmarshal target %T", v)
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	*ptr = copied
	return nil
}

func (rawBytesCodec) Name() string {
	return "proto"
}

type extProcServer struct {
	rt *Runtime
}

// NewExtProcGRPCServer returns a gRPC server registered with the Envoy
// envoy.service.ext_proc.v3.ExternalProcessor/Process bidirectional streaming callout.
func NewExtProcGRPCServer(rt *Runtime) *grpc.Server {
	srv := grpc.NewServer(grpc.ForceServerCodec(ExtProcRawCodec()))
	impl := &extProcServer{rt: rt}
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "envoy.service.ext_proc.v3.ExternalProcessor",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Process",
				Handler:       impl.handleProcessStream,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
	}, impl)
	return srv
}

// NewExtProcHandler returns an http.Handler that multiplexes HTTP/2 gRPC callouts
// (/envoy.service.ext_proc.v3.ExternalProcessor/Process) and HTTP/2 or HTTP/1.1
// health check probes (GET / or GET /healthz) on the same TLS listener.
func NewExtProcHandler(rt *Runtime) http.Handler {
	grpcSrv := NewExtProcGRPCServer(rt)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc") {
			grpcSrv.ServeHTTP(w, r)
			return
		}
		// TODO(security): Ensure rate-limiting and ingress network policies restrict health check probes in production deployments.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":     "ok",
			"component":  "aegis-model-armor-ext-proc",
			"wireFormat": "ExtProcGRPC",
		})
	})
}

// StartExtProcTLSServer starts the HTTP/2 + gRPC TLS server for the Envoy ext_proc callout
// with an ephemeral self-signed ECDSA P-256 certificate valid for in-cluster and localhost SANs.
func StartExtProcTLSServer(addr string, rt *Runtime) (net.Listener, func() error, error) {
	if strings.TrimSpace(addr) == "" {
		addr = ":8443"
	}
	cert, err := generateEphemeralExtProcTLSCert()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ext_proc TLS cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	rawLis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	tlsLis := tls.NewListener(rawLis, tlsCfg)

	srv := &http.Server{
		Handler:           NewExtProcHandler(rt),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		_ = tlsLis.Close()
		return nil, nil, fmt.Errorf("configure http2 server: %w", err)
	}

	go func() {
		_ = srv.Serve(tlsLis)
	}()

	closeFn := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
	return tlsLis, closeFn, nil
}

func generateEphemeralExtProcTLSCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().Add(-1 * time.Hour)
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "aegis-model-armor-ext-proc.aegis-system.svc.cluster.local",
			Organization: []string{"AegisSRE Zero-Trust Agent Security"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"localhost",
			"aegis-model-armor-ext-proc",
			"aegis-model-armor-ext-proc.aegis-system.svc",
			"aegis-model-armor-ext-proc.aegis-system.svc.cluster.local",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
		},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func (s *extProcServer) handleProcessStream(_ any, stream grpc.ServerStream) error {
	var guard *ContentGuard
	if s.rt != nil {
		guard = s.rt.ContentGuard()
	}
	if guard == nil {
		guard = NewContentGuard(RuntimeConfig{})
	}

	streamHeaders := make(map[string]string)
	matchedThreat := false

	for {
		var rawReq []byte
		if err := stream.RecvMsg(&rawReq); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		parsedReq := decodeExtProcProcessingRequest(rawReq)
		var respBytes []byte

		switch {
		case parsedReq.hasRequestHeaders:
			for k, v := range parsedReq.headers {
				streamHeaders[strings.ToLower(strings.TrimSpace(k))] = v
			}
			respBytes = evaluateExtProcPhase(guard, streamHeaders, parsedReq.headersConcat(), true, &matchedThreat)

		case parsedReq.hasRequestBody:
			respBytes = evaluateExtProcPhase(guard, streamHeaders, string(parsedReq.body), false, &matchedThreat)

		case parsedReq.hasResponseHeaders:
			respBytes = encodeExtProcContinueResponse(3, map[string]string{
				"x-aegis-authz-extension": "verified",
			})

		case parsedReq.hasResponseBody:
			respBytes = encodeExtProcContinueResponse(4, map[string]string{
				"x-aegis-authz-extension": "verified",
			})

		default:
			respBytes = encodeExtProcContinueResponse(1, map[string]string{
				"x-aegis-authz-extension":  "verified",
				"x-aegis-ext-proc-verdict": "ALLOW",
			})
		}

		if err := stream.SendMsg(&respBytes); err != nil {
			return err
		}
	}
}

func evaluateExtProcPhase(
	guard *ContentGuard,
	streamHeaders map[string]string,
	candidateText string,
	isHeadersPhase bool,
	matchedThreat *bool,
) []byte {
	responseFieldNum := protowire.Number(2) // request_body -> BodyResponse (field 2)
	if isHeadersPhase {
		responseFieldNum = 1 // request_headers -> HeadersResponse (field 1)
	}

	promptScreenHeader := strings.TrimSpace(streamHeaders["x-aegis-prompt-screen"])
	if strings.EqualFold(promptScreenHeader, "false") {
		return encodeExtProcContinueResponse(responseFieldNum, map[string]string{
			"x-aegis-authz-extension":  "verified",
			"x-aegis-ext-proc-verdict": "BYPASSED_RED",
		})
	}

	screenRes := guard.ScreenPrompt(candidateText, true, true)
	if screenRes.Blocked {
		*matchedThreat = true
		reason := "Prompt injection or adversarial payload blocked at Agent Gateway ext_proc boundary"
		if strings.TrimSpace(screenRes.ThreatReason) != "" {
			reason = screenRes.ThreatReason
		}
		if isExtProcEdgeEnforced(streamHeaders) {
			return encodeExtProcImmediate403(reason)
		}
		return encodeExtProcContinueResponse(responseFieldNum, map[string]string{
			"x-aegis-authz-extension":  "verified",
			"x-aegis-ext-proc-verdict": "MATCH_FOUND",
		})
	}

	verdict := "ALLOW"
	if *matchedThreat {
		verdict = "MATCH_FOUND"
	}
	return encodeExtProcContinueResponse(responseFieldNum, map[string]string{
		"x-aegis-authz-extension":  "verified",
		"x-aegis-ext-proc-verdict": verdict,
	})
}

func isExtProcEdgeEnforced(headers map[string]string) bool {
	path := strings.TrimSpace(headers[":path"])
	if strings.HasPrefix(path, "/a2a") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(headers["x-aegis-edge-enforce"]), "true") {
		return true
	}
	return false
}

type decodedProcessingRequest struct {
	hasRequestHeaders  bool
	hasRequestBody     bool
	hasResponseHeaders bool
	hasResponseBody    bool
	headers            map[string]string
	body               []byte
}

func (d decodedProcessingRequest) headersConcat() string {
	var parts []string
	for k, v := range d.headers {
		if strings.TrimSpace(v) != "" {
			parts = append(parts, k+": "+v)
		}
	}
	return strings.Join(parts, "\n")
}

func decodeExtProcProcessingRequest(b []byte) decodedProcessingRequest {
	res := decodedProcessingRequest{
		headers: make(map[string]string),
	}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch num {
		case 2: // request_headers (HttpHeaders)
			if typ == protowire.BytesType {
				val, m := protowire.ConsumeBytes(b)
				if m < 0 {
					return res
				}
				b = b[m:]
				res.hasRequestHeaders = true
				parseExtProcHttpHeaders(val, res.headers)
				continue
			}
		case 3: // request_body (HttpBody)
			if typ == protowire.BytesType {
				val, m := protowire.ConsumeBytes(b)
				if m < 0 {
					return res
				}
				b = b[m:]
				res.hasRequestBody = true
				res.body = parseExtProcHttpBody(val)
				continue
			}
		case 4: // response_headers (HttpHeaders)
			if typ == protowire.BytesType {
				val, m := protowire.ConsumeBytes(b)
				if m < 0 {
					return res
				}
				b = b[m:]
				res.hasResponseHeaders = true
				parseExtProcHttpHeaders(val, res.headers)
				continue
			}
		case 5: // response_body (HttpBody)
			if typ == protowire.BytesType {
				val, m := protowire.ConsumeBytes(b)
				if m < 0 {
					return res
				}
				b = b[m:]
				res.hasResponseBody = true
				res.body = parseExtProcHttpBody(val)
				continue
			}
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
	return res
}

func parseExtProcHttpHeaders(b []byte, out map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // HeaderMap
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			parseExtProcHeaderMap(val, out)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

func parseExtProcHeaderMap(b []byte, out map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // repeated HeaderValue
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			k, v := parseExtProcHeaderValue(val)
			if k != "" {
				out[strings.ToLower(k)] = v
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

// parseExtProcHeaderValue decodes envoy.config.core.v3.HeaderValue, preferring
// raw_value (field 3, bytes) over value (field 2, string) because Google Cloud
// Service Extensions Envoy populates raw_value on the wire.
func parseExtProcHeaderValue(b []byte) (string, string) {
	var key, strVal string
	var rawVal []byte
	var hasRaw bool
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(b)
			if m < 0 {
				return key, strVal
			}
			b = b[m:]
			key = v
			continue
		case num == 2 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(b)
			if m < 0 {
				return key, strVal
			}
			b = b[m:]
			strVal = v
			continue
		case num == 3 && typ == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return key, strVal
			}
			b = b[m:]
			rawVal = v
			hasRaw = true
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
	if hasRaw && len(rawVal) > 0 {
		return key, string(rawVal)
	}
	return key, strVal
}

func parseExtProcHttpBody(b []byte) []byte {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil
			}
			return val
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
	return nil
}

func encodeExtProcHeaderMutation(setHeaders map[string]string) []byte {
	var hm []byte
	for k, v := range setHeaders {
		// Envoy HeaderValue validation requires ONLY ONE OF value (2) or raw_value (3).
		// Set key (1) + raw_value (3) for full Envoy compatibility.
		var hv []byte
		hv = protowire.AppendTag(hv, 1, protowire.BytesType)
		hv = protowire.AppendString(hv, k)
		hv = protowire.AppendTag(hv, 3, protowire.BytesType)
		hv = protowire.AppendBytes(hv, []byte(v))

		var hvo []byte
		hvo = protowire.AppendTag(hvo, 1, protowire.BytesType)
		hvo = protowire.AppendBytes(hvo, hv)
		// append_action = OVERWRITE_IF_EXISTS_OR_ADD (1)
		hvo = protowire.AppendTag(hvo, 3, protowire.VarintType)
		hvo = protowire.AppendVarint(hvo, 1)

		hm = protowire.AppendTag(hm, 1, protowire.BytesType)
		hm = protowire.AppendBytes(hm, hvo)
	}
	return hm
}

func encodeExtProcContinueResponse(responseFieldNum protowire.Number, setHeaders map[string]string) []byte {
	var commonResp []byte
	// status = CONTINUE (0)
	commonResp = protowire.AppendTag(commonResp, 1, protowire.VarintType)
	commonResp = protowire.AppendVarint(commonResp, 0)

	if len(setHeaders) > 0 {
		hm := encodeExtProcHeaderMutation(setHeaders)
		commonResp = protowire.AppendTag(commonResp, 2, protowire.BytesType)
		commonResp = protowire.AppendBytes(commonResp, hm)
	}

	var phaseResp []byte
	phaseResp = protowire.AppendTag(phaseResp, 1, protowire.BytesType)
	phaseResp = protowire.AppendBytes(phaseResp, commonResp)

	var procResp []byte
	procResp = protowire.AppendTag(procResp, responseFieldNum, protowire.BytesType)
	procResp = protowire.AppendBytes(procResp, phaseResp)
	return procResp
}

func encodeExtProcImmediate403(reason string) []byte {
	// HttpStatus { code = 403 (Forbidden) }
	var httpStatus []byte
	httpStatus = protowire.AppendTag(httpStatus, 1, protowire.VarintType)
	httpStatus = protowire.AppendVarint(httpStatus, 403)

	hm := encodeExtProcHeaderMutation(map[string]string{
		"content-type":            "application/json",
		"x-aegis-verdict":         "BLOCKED_BY_GCP_AUTHZ_EXTENSION",
		"x-aegis-authz-extension": "aegis-model-armor-ext-proc",
	})

	bodyBytes, _ := json.Marshal(map[string]string{
		"error":     "blocked_by_gcp_authz_extension",
		"plane":     "CLIENT_TO_AGENT",
		"extension": "aegis-model-armor-ext-proc",
		"verdict":   "BLOCK",
		"reason":    reason,
	})

	var imm []byte
	imm = protowire.AppendTag(imm, 1, protowire.BytesType)
	imm = protowire.AppendBytes(imm, httpStatus)
	imm = protowire.AppendTag(imm, 2, protowire.BytesType)
	imm = protowire.AppendBytes(imm, hm)
	imm = protowire.AppendTag(imm, 3, protowire.BytesType)
	imm = protowire.AppendBytes(imm, bodyBytes)
	imm = protowire.AppendTag(imm, 5, protowire.BytesType)
	imm = protowire.AppendString(imm, "blocked_by_gcp_authz_extension")

	var procResp []byte
	procResp = protowire.AppendTag(procResp, 7, protowire.BytesType)
	procResp = protowire.AppendBytes(procResp, imm)
	return procResp
}

// EncodeExtProcRequestHeaders encodes a ProcessingRequest{request_headers: ...} frame for testing.
// When useRawValue is true, HeaderValue.raw_value (field 3) is populated like Google Cloud ALB Envoy;
// when false, HeaderValue.value (field 2) is populated.
func EncodeExtProcRequestHeaders(headers map[string]string, useRawValue bool) []byte {
	var headerMap []byte
	for k, v := range headers {
		var hv []byte
		hv = protowire.AppendTag(hv, 1, protowire.BytesType)
		hv = protowire.AppendString(hv, k)
		if useRawValue {
			hv = protowire.AppendTag(hv, 3, protowire.BytesType)
			hv = protowire.AppendBytes(hv, []byte(v))
		} else {
			hv = protowire.AppendTag(hv, 2, protowire.BytesType)
			hv = protowire.AppendString(hv, v)
		}
		headerMap = protowire.AppendTag(headerMap, 1, protowire.BytesType)
		headerMap = protowire.AppendBytes(headerMap, hv)
	}

	var httpHeaders []byte
	httpHeaders = protowire.AppendTag(httpHeaders, 1, protowire.BytesType)
	httpHeaders = protowire.AppendBytes(httpHeaders, headerMap)

	var req []byte
	req = protowire.AppendTag(req, 2, protowire.BytesType)
	req = protowire.AppendBytes(req, httpHeaders)
	return req
}

// EncodeExtProcRequestBody encodes a ProcessingRequest{request_body: ...} frame for testing.
func EncodeExtProcRequestBody(body []byte, endOfStream bool) []byte {
	var httpBody []byte
	httpBody = protowire.AppendTag(httpBody, 1, protowire.BytesType)
	httpBody = protowire.AppendBytes(httpBody, body)
	if endOfStream {
		httpBody = protowire.AppendTag(httpBody, 2, protowire.VarintType)
		httpBody = protowire.AppendVarint(httpBody, 1)
	}

	var req []byte
	req = protowire.AppendTag(req, 3, protowire.BytesType)
	req = protowire.AppendBytes(req, httpBody)
	return req
}

// ExtProcDecodedResponse summarizes a decoded Envoy ProcessingResponse for unit and integration tests.
type ExtProcDecodedResponse struct {
	IsHeadersResponse bool
	IsBodyResponse    bool
	IsImmediate       bool
	ImmediateStatus   uint32
	ImmediateBody     []byte
	ImmediateDetails  string
	Headers           map[string]string
}

// DecodeExtProcResponse decodes a wire-format ProcessingResponse frame.
func DecodeExtProcResponse(b []byte) (ExtProcDecodedResponse, error) {
	out := ExtProcDecodedResponse{
		Headers: make(map[string]string),
	}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, fmt.Errorf("invalid tag in ProcessingResponse")
		}
		b = b[n:]
		switch {
		case (num == 1 || num == 2 || num == 3 || num == 4) && typ == protowire.BytesType:
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("invalid phase response bytes")
			}
			b = b[m:]
			if num == 1 || num == 3 {
				out.IsHeadersResponse = true
			} else {
				out.IsBodyResponse = true
			}
			decodeExtProcPhaseResponse(val, out.Headers)
			continue
		case num == 7 && typ == protowire.BytesType:
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("invalid immediate_response bytes")
			}
			b = b[m:]
			out.IsImmediate = true
			decodeExtProcImmediateResponse(val, &out)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return out, fmt.Errorf("invalid field in ProcessingResponse")
		}
		b = b[m:]
	}
	return out, nil
}

func decodeExtProcPhaseResponse(b []byte, headers map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // CommonResponse
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			decodeExtProcCommonResponse(val, headers)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

func decodeExtProcCommonResponse(b []byte, headers map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 2 && typ == protowire.BytesType { // HeaderMutation
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			decodeExtProcHeaderMutation(val, headers)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

func decodeExtProcHeaderMutation(b []byte, headers map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // HeaderValueOption
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			decodeExtProcHeaderValueOption(val, headers)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

func decodeExtProcHeaderValueOption(b []byte, headers map[string]string) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType { // HeaderValue
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			k, v := parseExtProcHeaderValue(val)
			if k != "" {
				headers[strings.ToLower(k)] = v
			}
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}

func decodeExtProcImmediateResponse(b []byte, out *ExtProcDecodedResponse) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType: // HttpStatus
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			for len(val) > 0 {
				snum, styp, sn := protowire.ConsumeTag(val)
				if sn < 0 {
					break
				}
				val = val[sn:]
				if snum == 1 && styp == protowire.VarintType {
					code, sm := protowire.ConsumeVarint(val)
					if sm >= 0 {
						out.ImmediateStatus = uint32(code)
						val = val[sm:]
						continue
					}
				}
				sm := protowire.ConsumeFieldValue(snum, styp, val)
				if sm < 0 {
					break
				}
				val = val[sm:]
			}
			continue
		case num == 2 && typ == protowire.BytesType: // HeaderMutation
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			decodeExtProcHeaderMutation(val, out.Headers)
			continue
		case num == 3 && typ == protowire.BytesType: // body
			val, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return
			}
			b = b[m:]
			out.ImmediateBody = val
			continue
		case num == 5 && typ == protowire.BytesType: // details
			val, m := protowire.ConsumeString(b)
			if m < 0 {
				return
			}
			b = b[m:]
			out.ImmediateDetails = val
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			break
		}
		b = b[m:]
	}
}
