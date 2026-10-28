package aegis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

const (
	defaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'"
	allowedHTTPMethodsHeader     = "GET, HEAD, POST, OPTIONS"
)

// NewHTTPHandler is an alias for NewHandler for callers expecting the standard HTTP mux constructor name.
func NewHTTPHandler(rt *Runtime) http.Handler {
	return NewHandler(rt)
}

// NewHandler creates the HTTP ServeMux for AegisRuntime and applies all registered route extensions.
func NewHandler(rt *Runtime) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "aegis-sre"})
	})

	mux.HandleFunc("GET /api/sessions/{sessionId}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		snap := rt.GetOrCreateSession(sessionID)
		writeJSON(w, http.StatusOK, snap)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/posture", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var body struct {
			Persona PersonaID       `json:"persona"`
			Posture SecurityPosture `json:"posture"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		snap := rt.UpdateSession(sessionID, func(s *SessionSnapshot) {
			if body.Persona != "" {
				s.ActivePersona = body.Persona
			}
			s.Posture = body.Posture
		})
		writeJSON(w, http.StatusOK, snap)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/turns", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req TurnRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.SessionID = sessionID
		res, err := rt.ExecuteTurn(r.Context(), req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /api/sessions/{sessionId}/turns/stream", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionId")
		var req TurnRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.SessionID = sessionID
		sink := initSSESink(w)
		if _, err := rt.ExecuteTurnStream(r.Context(), req, sink); err != nil {
			writeSSEError(w, err)
		}
	})

	registeredHTTPRoutesMu.RLock()
	routes := append([]HTTPRouteRegistrar(nil), registeredHTTPRoutes...)
	registeredHTTPRoutesMu.RUnlock()
	for _, register := range routes {
		register(mux, rt)
	}

	return withSecurityHeaders(mux)
}

// withSecurityHeaders wraps the AegisSRE HTTP mux with defense-in-depth browser security headers,
// strict cache suppression on /api/ and /oauth/ routes, and an explicit HTTP method allow-list.
// TODO(security): AegisSRE exposes a stateless JSON/SSE API with zero auth cookies (CSRF tokens N/A),
// zero local user password accounts (Argon2id/MFA N/A — OAuth 2.0 + S256 PKCE delegates to upstream IdPs),
// zero file-upload endpoints (AV/CDR scanning N/A), and zero SQL databases (SQL parameterization N/A).
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		hdr.Set("Content-Security-Policy", defaultContentSecurityPolicy)

		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/oauth/") {
			hdr.Set("Cache-Control", "no-store")
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost:
			next.ServeHTTP(w, r)
		case http.MethodOptions:
			hdr.Set("Allow", allowedHTTPMethodsHeader)
			w.WriteHeader(http.StatusNoContent)
		default:
			hdr.Set("Allow", allowedHTTPMethodsHeader)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})
}

func initSSESink(w http.ResponseWriter) TurnEventSink {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	var mu sync.Mutex
	return func(ev TurnStreamEvent) {
		mu.Lock()
		defer mu.Unlock()
		payload, err := json.Marshal(ev)
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func writeSSEError(w http.ResponseWriter, err error) {
	payload, _ := json.Marshal(map[string]string{"error": err.Error()})
	_, _ = fmt.Fprintf(w, "event: turn.error\ndata: %s\n\n", payload)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
