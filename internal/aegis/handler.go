package aegis

import (
	"encoding/json"
	"net/http"
)

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

	registeredScenarioHandlersMu.RLock()
	routes := append([]HTTPRouteRegistrar(nil), registeredHTTPRoutes...)
	registeredScenarioHandlersMu.RUnlock()
	for _, register := range routes {
		register(mux, rt)
	}

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
