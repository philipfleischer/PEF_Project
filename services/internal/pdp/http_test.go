// Tests for the PDP's HTTP API, through httptest without a real server.

package pdp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

const token = "test-token"

// api is a PDP behind its HTTP handler.
type api struct {
	t       *testing.T
	pdp     *PDP
	handler http.Handler
	metrics *observability.Registry
}

func newAPI(t *testing.T) *api {
	t.Helper()
	now := t0
	reg := observability.NewRegistry()
	p := newPDP(t, &now)
	return &api{t: t, pdp: p, handler: NewHandler(p, token, reg), metrics: reg}
}

// do sends a request with body (a string is sent as is, anything else as
// JSON) and the given bearer token, and returns the response.
func (a *api) do(method, target string, body any, bearer string) *httptest.ResponseRecorder {
	a.t.Helper()
	var s string
	switch b := body.(type) {
	case nil:
	case string:
		s = b
	default:
		data, err := json.Marshal(b)
		if err != nil {
			a.t.Fatal(err)
		}
		s = string(data)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(s))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

// decision decodes a 200 response from POST /v1/decide.
func (a *api) decision(req model.AccessRequest) model.Decision {
	a.t.Helper()
	rec := a.do(http.MethodPost, "/v1/decide", req, "")
	if rec.Code != http.StatusOK {
		a.t.Fatalf("POST /v1/decide = %d %s", rec.Code, rec.Body)
	}
	var d model.Decision
	if err := json.NewDecoder(rec.Body).Decode(&d); err != nil {
		a.t.Fatal(err)
	}
	return d
}

func TestHTTPDecide(t *testing.T) {
	a := newAPI(t)
	if d := a.decision(writeTelemetry("bay-1")); d.Allowed() {
		t.Fatalf("unknown PMU allowed: %+v", d)
	}
	for _, sig := range []string{
		`{"subject":"` + pmu + `","kind":"authentication","value":0.8}`,
		`{"subject":"` + pmu + `","kind":"posture","value":1}`,
	} {
		if rec := a.do(http.MethodPost, "/v1/signals", sig, token); rec.Code != http.StatusNoContent {
			t.Fatalf("POST /v1/signals = %d %s", rec.Code, rec.Body)
		}
	}
	if d := a.decision(writeTelemetry("bay-1")); !d.Allowed() || d.DecidedBy != "cloud-pdp" {
		t.Errorf("authenticated PMU: %+v", d)
	}
	deny := a.metrics.Counter("ztc_pdp_decisions_total", "").Value("effect", "deny")
	allow := a.metrics.Counter("ztc_pdp_decisions_total", "").Value("effect", "allow")
	if deny != 1 || allow != 1 {
		t.Errorf("decisions metric: deny %v, allow %v, want 1 and 1", deny, allow)
	}
}

func TestHTTPStatusCodes(t *testing.T) {
	a := newAPI(t)
	tooLarge := `{"subject":{"id":"` + strings.Repeat("x", 2<<20) + `"}}`
	tests := []struct {
		name, method, target string
		body                 any
		bearer               string
		want                 int
	}{
		{"decide: not JSON", "POST", "/v1/decide", `{`, "", 400},
		{"decide: unknown field", "POST", "/v1/decide", `{"subjekt":{}}`, "", 400},
		{"decide: body too large", "POST", "/v1/decide", tooLarge, "", 413},
		{"decide: wrong method", "GET", "/v1/decide", nil, "", 405},
		{"signal: no token", "POST", "/v1/signals", `{"subject":"a","kind":"posture","value":1}`, "", 401},
		{"signal: wrong token", "POST", "/v1/signals", `{"subject":"a","kind":"posture","value":1}`, "guess", 401},
		{"signal: unknown kind", "POST", "/v1/signals", `{"subject":"a","kind":"reset"}`, token, 400},
		{"signal: no subject", "POST", "/v1/signals", `{"kind":"posture","value":1}`, token, 400},
		{"trust: no subject", "GET", "/v1/trust", nil, "", 400},
		{"policy: no token", "PUT", "/v1/policy", `{"version":2,"rules":[]}`, "", 401},
		{"policy: misspelt field", "PUT", "/v1/policy", `{"version":2,"rulez":[]}`, token, 400},
		{"policy: not newer", "PUT", "/v1/policy", `{"version":1,"rules":[]}`, token, 409},
		{"emergency: no token", "PUT", "/v1/emergency", `{"on":true}`, "", 401},
		{"unknown path", "GET", "/v1/nothing", nil, "", 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if rec := a.do(tc.method, tc.target, tc.body, tc.bearer); rec.Code != tc.want {
				t.Errorf("%s %s = %d %s, want %d", tc.method, tc.target, rec.Code, rec.Body, tc.want)
			}
		})
	}
	if a.pdp.Engine.Policy().Version != 1 || a.pdp.Emergency() {
		t.Error("a rejected request changed the PDP")
	}
}

func TestHTTPWritesDisabledWithoutToken(t *testing.T) {
	now := t0
	h := NewHandler(newPDP(t, &now), "", observability.NewRegistry())
	req := httptest.NewRequest(http.MethodPut, "/v1/emergency", strings.NewReader(`{"on":true}`))
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT /v1/emergency with no token configured = %d, want 403", rec.Code)
	}
}

func TestHTTPTrust(t *testing.T) {
	a := newAPI(t)
	authenticate(t, a.pdp, pmu)
	rec := a.do(http.MethodGet, "/v1/trust?subject="+url.QueryEscape(pmu), nil, "")
	var got TrustResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/trust = %d, %v", rec.Code, err)
	}
	if got.Subject != pmu || got.Level != "high" {
		t.Errorf("GET /v1/trust = %+v", got)
	}
}

func TestHTTPPolicy(t *testing.T) {
	a := newAPI(t)
	next := `{"version":2,"rules":[{"id":"allow-all","effect":"allow"}]}`
	if rec := a.do(http.MethodPut, "/v1/policy", next, token); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/policy = %d %s", rec.Code, rec.Body)
	}
	rec := a.do(http.MethodGet, "/v1/policy", nil, "")
	var got struct{ Version uint64 }
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil || got.Version != 2 {
		t.Errorf("GET /v1/policy after PUT: version %d, %v", got.Version, err)
	}
	authenticate(t, a.pdp, pmu)
	if d := a.decision(writeTelemetry("bay-2")); !d.Allowed() || d.RuleID != "allow-all" {
		t.Errorf("the new policy is not used: %+v", d)
	}
}

func TestHTTPEmergency(t *testing.T) {
	a := newAPI(t)
	if rec := a.do(http.MethodPut, "/v1/emergency", EmergencyState{On: true}, token); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/emergency = %d %s", rec.Code, rec.Body)
	}
	rec := a.do(http.MethodGet, "/v1/emergency", nil, "")
	var got EmergencyState
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil || !got.On {
		t.Errorf("GET /v1/emergency = %+v, %v", got, err)
	}
	authenticate(t, a.pdp, operator)
	if d := a.decision(operateBreaker()); d.RuleID != "break-glass-breaker" {
		t.Errorf("operator in emergency mode: %+v", d)
	}
}
