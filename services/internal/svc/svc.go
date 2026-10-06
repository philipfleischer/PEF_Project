// Package svc is the start-up scaffolding shared by every ZTC service: it
// reads the configuration, creates the logger and the metrics registry, and
// serves the application next to the operational endpoints /healthz, /readyz
// and /metrics until the service is told to stop.
package svc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
)

// Service holds what every service's main function needs.
type Service struct {
	Name    string
	Env     config.Env
	Log     *slog.Logger
	Metrics *observability.Registry
}

// New creates a Service called name that reads its configuration from env and
// writes JSON logs to logOut. ZTC_LOG_LEVEL sets the log level (default info);
// an unknown level is an error.
func New(name string, env config.Env, logOut io.Writer) (*Service, error) {
	log, err := observability.NewLogger(logOut, name, env.String("log_level", "info"))
	if err != nil {
		return nil, err
	}
	return &Service{Name: name, Env: env, Log: log, Metrics: observability.NewRegistry()}, nil
}

// Handler returns the complete HTTP handler of the service: the operational
// endpoints, and app instrumented with request metrics for every other path.
// checks are the readiness checks behind /readyz.
func (s *Service) Handler(app http.Handler, checks map[string]observability.Check) http.Handler {
	mux := observability.HealthMux(s.Metrics, s.Log, checks)
	mux.Handle("/", observability.Instrument(s.Metrics, s.Name, app))
	return mux
}

// Serve listens on ZTC_LISTEN (default defaultAddr) and serves Handler(app,
// checks) until ctx is cancelled, then shuts down gracefully. It refuses to
// start if any configuration value read so far was invalid, so every service
// fails fast on a typo in its environment.
func (s *Service) Serve(ctx context.Context, defaultAddr string, app http.Handler, checks map[string]observability.Check) error {
	addr := s.Env.String("listen", defaultAddr)
	if err := s.Env.Err(); err != nil {
		return fmt.Errorf("svc: invalid configuration: %w", err)
	}
	srv := httpx.NewServer(addr, s.Handler(app, checks))
	s.Log.Info("listening", "addr", addr)
	err := httpx.Run(ctx, srv)
	s.Log.Info("stopped", "err", err)
	return err
}
