package observability

import (
	"net/http"
	"strconv"
	"time"
)

// Instrument wraps h and records the RED metrics (rate, errors, duration) of
// every request in reg:
//
//	ztc_http_requests_total{service, method, code}
//	ztc_http_request_seconds{service}
//
// The URL path is deliberately not a label, and unknown methods are recorded
// as "OTHER": label values chosen by clients would let anyone create
// unlimited time series and exhaust the service's memory (denial of service).
func Instrument(reg *Registry, service string, h http.Handler) http.Handler {
	requests := reg.Counter("ztc_http_requests_total", "HTTP requests by service, method and status code.")
	latency := reg.Histogram("ztc_http_request_seconds", "HTTP request latency in seconds.", DefBuckets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rec, r)
		requests.Inc("service", service, "method", methodLabel(r.Method), "code", strconv.Itoa(rec.status))
		latency.Observe(time.Since(start).Seconds(), "service", service)
	})
}

// methodLabel maps the HTTP request method to a bounded set of label values.
func methodLabel(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return m
	}
	return "OTHER"
}

// statusRecorder remembers the status code a handler writes. A handler that
// never calls WriteHeader implicitly answers 200.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status code and passes every call on.
func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying ResponseWriter,
// for example to flush or to set per-request deadlines.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
