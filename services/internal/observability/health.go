package observability

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Check reports whether one dependency of the service is usable.
// nil means ready. It must return promptly once ctx is cancelled.
type Check func(ctx context.Context) error

// CheckTimeout bounds how long /readyz waits for all checks together.
const CheckTimeout = 2 * time.Second

// HealthMux returns a mux that serves the operational endpoints:
//
//	GET /healthz   liveness: 200 while the process can serve HTTP at all
//	GET /readyz    readiness: 200 if every check passes, else 503
//	GET /metrics   the Prometheus scrape endpoint of reg
//
// /readyz names the failing checks but not their errors, because these
// endpoints are unauthenticated. The errors go to log instead.
func HealthMux(reg *Registry, log *slog.Logger, checks map[string]Check) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), CheckTimeout)
		defer cancel()
		var failed []string
		for _, name := range slices.Sorted(maps.Keys(checks)) {
			if err := checks[name](ctx); err != nil {
				log.Warn("readiness check failed", "check", name, "err", err)
				failed = append(failed, name)
			}
		}
		if len(failed) > 0 {
			http.Error(w, "not ready: "+strings.Join(failed, ", "), http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.Handle("GET /metrics", reg.Handler())
	return mux
}
