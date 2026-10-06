// Package httpx holds small HTTP helpers shared by all ZTC services:
// JSON responses, strict JSON request decoding with a size limit,
// and an http.Server with defensive timeouts and graceful shutdown.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// MaxBody is the largest request body ReadJSON accepts (1 MiB). It protects
// services from memory exhaustion by oversized requests.
const MaxBody = 1 << 20

// WriteJSON writes v as JSON with the given status code. nosniff stops
// browsers from guessing a different content type for the response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes {"error": msg} with the given status code.
func Error(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// ReadJSON decodes the request body into v. It rejects unknown fields,
// trailing data after the JSON value, and bodies larger than MaxBody; for an
// oversized body the error is an *http.MaxBytesError, which callers can map
// to 413 Request Entity Too Large.
func ReadJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("httpx: trailing data after JSON body")
	}
	return nil
}

// NewServer returns an http.Server for addr with timeouts that stop slow
// clients (slowloris) from holding connections open forever.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

// ShutdownTimeout is how long Run waits for in-flight requests to finish.
const ShutdownTimeout = 10 * time.Second

// Run serves srv (over TLS if srv.TLSConfig is set) until ctx is cancelled,
// then shuts it down gracefully: no new connections are accepted and
// in-flight requests get ShutdownTimeout to finish. It returns early with an
// error if the server cannot start, for example because the port is in use.
func Run(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		var err error
		if srv.TLSConfig != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
