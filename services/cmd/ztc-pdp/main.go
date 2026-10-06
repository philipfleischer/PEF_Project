// Command ztc-pdp is the Policy Decision Point of ZTC: the service a Policy
// Enforcement Point asks whether a request may go ahead (NIST SP 800-207).
//
// This first version only serves the operational endpoints /healthz, /readyz
// and /metrics. The decision API will be added in milestone M1.
//
// Environment:
//
//	ZTC_LISTEN      address to listen on (default :8181)
//	ZTC_LOG_LEVEL   debug, info, warn or error (default info)
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/httpx"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/svc"
)

func main() {
	// Cancel the context on Ctrl+C (SIGINT) or when Docker or Kubernetes
	// stops the container (SIGTERM), so the server shuts down gracefully.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, config.New(), os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ztc-pdp:", err)
		os.Exit(1)
	}
}

// run starts the PDP and blocks until ctx is cancelled or the server fails.
// It takes its dependencies as parameters so tests can call it directly.
func run(ctx context.Context, env config.Env, logOut io.Writer) error {
	s, err := svc.New("ztc-pdp", env, logOut)
	if err != nil {
		return err
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.Error(w, http.StatusNotFound, "not found")
	})
	return s.Serve(ctx, ":8181", app, nil)
}
