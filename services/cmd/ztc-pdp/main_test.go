package main

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
)

func envFrom(vars map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	})
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, envFrom(map[string]string{"ZTC_LISTEN": "127.0.0.1:0"}), io.Discard) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the context was cancelled")
	}
}

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	err := run(context.Background(), envFrom(map[string]string{"ZTC_LOG_LEVEL": "verbose"}), io.Discard)
	if err == nil {
		t.Fatal("run accepted ZTC_LOG_LEVEL=verbose")
	}
}
