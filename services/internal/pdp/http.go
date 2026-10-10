// The HTTP API of the PDP: decisions for PEPs, signals from PEPs and the IDS,
// and the administration of policy and emergency mode.

package pdp

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// TrustResponse is the body of GET /v1/trust.
type TrustResponse struct {
	Subject string      `json:"subject"`
	Score   float64     `json:"score"`
	Level   trust.Level `json:"level"`
}

// EmergencyState is the body of GET and PUT /v1/emergency.
type EmergencyState struct {
	On bool `json:"on"`
}

// NewHandler returns the HTTP API of p:
//
//	POST /v1/decide              model.AccessRequest → model.Decision
//	POST /v1/signals             trust.Signal → 204                 (token)
//	GET  /v1/trust?subject=<id>  → TrustResponse
//	GET  /v1/policy              → policy.Policy
//	PUT  /v1/policy              policy.Policy → 204                (token)
//	GET  /v1/emergency           → EmergencyState
//	PUT  /v1/emergency           EmergencyState → 204               (token)
//
// Requests marked (token) change the PDP and need the header
// "Authorization: Bearer <token>". An empty token disables them. Decisions are
// counted in reg as ztc_pdp_decisions_total{effect}.
func NewHandler(p *PDP, token string, reg *observability.Registry) http.Handler {
	h := &handler{
		pdp:       p,
		token:     token,
		decisions: reg.Counter("ztc_pdp_decisions_total", "Access decisions by effect."),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/decide", h.decide)
	mux.HandleFunc("POST /v1/signals", h.authorized(h.signal))
	mux.HandleFunc("GET /v1/trust", h.trust)
	mux.HandleFunc("GET /v1/policy", h.getPolicy)
	mux.HandleFunc("PUT /v1/policy", h.authorized(h.putPolicy))
	mux.HandleFunc("GET /v1/emergency", h.getEmergency)
	mux.HandleFunc("PUT /v1/emergency", h.authorized(h.putEmergency))
	return mux
}

// handler holds what the endpoints share.
type handler struct {
	pdp       *PDP
	token     string
	decisions *observability.Counter
}

// authorized wraps next so it runs only with the right bearer token. The
// comparison takes the same time however much of the token is right, so the
// token cannot be guessed one character at a time.
func (h *handler) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.token == "" {
			httpx.Error(w, http.StatusForbidden, "writes are disabled on this PDP")
			return
		}
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(h.token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			httpx.Error(w, http.StatusUnauthorized, "missing or wrong bearer token")
			return
		}
		next(w, r)
	}
}

func (h *handler) decide(w http.ResponseWriter, r *http.Request) {
	var req model.AccessRequest
	if err := httpx.ReadJSON(w, r, &req); err != nil {
		badRequest(w, err)
		return
	}
	d, err := h.pdp.Decide(r.Context(), req)
	h.decisions.Inc("effect", string(d.Effect))
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (h *handler) signal(w http.ResponseWriter, r *http.Request) {
	var sig trust.Signal
	if err := httpx.ReadJSON(w, r, &sig); err != nil {
		badRequest(w, err)
		return
	}
	if _, err := h.pdp.RecordSignal(sig); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) trust(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	if subject == "" {
		httpx.Error(w, http.StatusBadRequest, "missing query parameter subject")
		return
	}
	score := h.pdp.Trust.Score(subject)
	httpx.WriteJSON(w, http.StatusOK, TrustResponse{Subject: subject, Score: score, Level: trust.LevelOf(score)})
}

func (h *handler) getPolicy(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.pdp.Engine.Policy())
}

func (h *handler) putPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := policy.Load(http.MaxBytesReader(w, r.Body, httpx.MaxBody))
	if err != nil {
		badRequest(w, err)
		return
	}
	if err := h.pdp.Engine.Install(p); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, policy.ErrStalePolicy) {
			status = http.StatusConflict
		}
		httpx.Error(w, status, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) getEmergency(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, EmergencyState{On: h.pdp.Emergency()})
}

func (h *handler) putEmergency(w http.ResponseWriter, r *http.Request) {
	var s EmergencyState
	if err := httpx.ReadJSON(w, r, &s); err != nil {
		badRequest(w, err)
		return
	}
	h.pdp.SetEmergency(s.On)
	w.WriteHeader(http.StatusNoContent)
}

// badRequest answers a body that could not be read: 413 if it was too large,
// 400 otherwise.
func badRequest(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	httpx.Error(w, status, err.Error())
}
