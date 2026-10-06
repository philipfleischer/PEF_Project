package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestHealthMux(t *testing.T) {
	pdpErr := error(nil)
	checks := map[string]Check{
		"pdp":   func(context.Context) error { return pdpErr },
		"audit": func(context.Context) error { return nil },
	}
	var logs bytes.Buffer
	mux := HealthMux(NewRegistry(), slog.New(slog.NewTextHandler(&logs, nil)), checks)

	if code, _ := get(t, mux, "/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, mux, "/readyz"); code != http.StatusOK {
		t.Errorf("/readyz with healthy checks = %d, want 200", code)
	}

	pdpErr = errors.New("dial tcp 10.0.3.7:8181: connection refused")
	code, body := get(t, mux, "/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "pdp") {
		t.Errorf("/readyz with failing check = %d %q, want 503 naming pdp", code, body)
	}
	if strings.Contains(body, "10.0.3.7") {
		t.Errorf("/readyz leaks the internal error to the client: %q", body)
	}
	if !strings.Contains(logs.String(), "10.0.3.7") {
		t.Errorf("the check error was not logged; logs = %q", logs.String())
	}

	if code, _ := get(t, mux, "/metrics"); code != http.StatusOK {
		t.Errorf("/metrics = %d, want 200", code)
	}
}

func TestReadyzGivesChecksADeadline(t *testing.T) {
	var hadDeadline bool
	checks := map[string]Check{"slow": func(ctx context.Context) error {
		_, hadDeadline = ctx.Deadline()
		return nil
	}}
	mux := HealthMux(NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)), checks)
	get(t, mux, "/readyz")
	if !hadDeadline {
		t.Error("checks were called without a deadline")
	}
}

func TestInstrument(t *testing.T) {
	reg := NewRegistry()
	h := Instrument(reg, "ztc-pdp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deny" {
			w.WriteHeader(http.StatusForbidden)
			w.WriteHeader(http.StatusInternalServerError) // ignored by net/http; the first code counts
			return
		}
		_, _ = w.Write([]byte("ok")) // implicit 200
	}))

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/allow", nil),
		httptest.NewRequest(http.MethodPost, "/deny", nil),
		httptest.NewRequest("EVIL-METHOD", "/allow", nil),
	} {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	requests := reg.Counter("ztc_http_requests_total", "")
	tests := []struct {
		method, code string
		want         float64
	}{
		{"GET", "200", 1},
		{"POST", "403", 1},
		{"OTHER", "200", 1},
		{"EVIL-METHOD", "200", 0},
	}
	for _, tc := range tests {
		if got := requests.Value("service", "ztc-pdp", "method", tc.method, "code", tc.code); got != tc.want {
			t.Errorf("requests{method=%s,code=%s} = %v, want %v", tc.method, tc.code, got, tc.want)
		}
	}

	var b strings.Builder
	if err := reg.Write(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `ztc_http_request_seconds_count{service="ztc-pdp"} 3`) {
		t.Errorf("latency histogram did not record 3 requests:\n%s", b.String())
	}
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	log, err := NewLogger(&buf, "ztc-pdp", "warn")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown", "subject", "pmu-7")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1 (info is below warn):\n%s", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	if rec["service"] != "ztc-pdp" || rec["msg"] != "shown" || rec["subject"] != "pmu-7" {
		t.Errorf("log record = %v, want service, msg and subject fields", rec)
	}

	if _, err := NewLogger(&buf, "ztc-pdp", "verbose"); err == nil {
		t.Error("NewLogger accepted the unknown level \"verbose\"")
	}
}
