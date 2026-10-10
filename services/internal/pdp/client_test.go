// Tests for the remote client against a real HTTP server, the decider chain
// and placement parsing.

package pdp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

func TestParsePlacement(t *testing.T) {
	for _, s := range []string{"cloud", "fog", "hierarchical"} {
		if p, err := ParsePlacement(s); err != nil || string(p) != s {
			t.Errorf("ParsePlacement(%q) = %q, %v", s, p, err)
		}
	}
	for _, s := range []string{"", "Cloud", "edge"} {
		if _, err := ParsePlacement(s); err == nil {
			t.Errorf("ParsePlacement(%q) = nil error", s)
		}
	}
}

// TestRemoteClient runs a real PDP behind a real HTTP server on localhost.
func TestRemoteClient(t *testing.T) {
	now := t0
	srv := httptest.NewServer(NewHandler(newPDP(t, &now), token, observability.NewRegistry()))
	defer srv.Close()
	c := &RemoteClient{BaseURL: srv.URL, Token: token}
	ctx := context.Background()

	if d, err := c.Decide(ctx, writeTelemetry("bay-1")); err != nil || d.Allowed() {
		t.Fatalf("unknown PMU: %+v, %v", d, err)
	}
	for _, sig := range []trust.Signal{
		{Subject: pmu, Kind: trust.Authentication, Value: 0.8},
		{Subject: pmu, Kind: trust.Posture, Value: 1},
	} {
		if err := c.RecordSignal(ctx, sig); err != nil {
			t.Fatalf("RecordSignal() = %v", err)
		}
	}
	d, err := c.Decide(ctx, writeTelemetry("bay-1"))
	if err != nil || !d.Allowed() || d.DecidedBy != "cloud-pdp" {
		t.Errorf("authenticated PMU: %+v, %v", d, err)
	}

	wrong := &RemoteClient{BaseURL: srv.URL, Token: "guess"}
	if err := wrong.RecordSignal(ctx, trust.Signal{Subject: pmu, Kind: trust.Authentication, Value: 1}); err == nil {
		t.Error("RecordSignal() with a wrong token = nil error")
	}
}

// TestRemoteClientFailsClosed checks that every way the remote PDP can fail
// gives a deny and an error.
func TestRemoteClientFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}, 0},
		{"not JSON", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("allow")) }, 0},
		{"unknown effect", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"effect":"maybe"}`))
		}, 0},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://attacker.example/v1/decide", http.StatusTemporaryRedirect)
		}, 0},
		{"too slow", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(300 * time.Millisecond):
				_, _ = w.Write([]byte(`{"effect":"allow"}`))
			}
		}, 50 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			c := &RemoteClient{BaseURL: srv.URL, Timeout: tc.timeout}
			start := time.Now()
			d, err := c.Decide(context.Background(), writeTelemetry("bay-1"))
			if err == nil || d.Allowed() {
				t.Errorf("Decide() = %+v, %v, want a deny and an error", d, err)
			}
			// The slow server answers "allow" after 300 ms; the client must
			// have given up long before.
			if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
				t.Errorf("Decide() took %v", elapsed)
			}
		})
	}
}

func TestRemoteClientUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens on this address any more
	d, err := (&RemoteClient{BaseURL: srv.URL}).Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || d.Allowed() {
		t.Errorf("Decide() = %+v, %v, want a deny and an error", d, err)
	}
}

func TestChain(t *testing.T) {
	down := DeciderFunc(func(context.Context, model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Deny}, errors.New("down")
	})
	answer := func(effect model.Effect, by string, calls *int) Decider {
		return DeciderFunc(func(context.Context, model.AccessRequest) (model.Decision, error) {
			*calls++
			return model.Decision{Effect: effect, DecidedBy: by}, nil
		})
	}
	var first, second int
	tests := []struct {
		name    string
		chain   Chain
		want    model.Effect
		wantBy  string
		wantErr bool
	}{
		{"first answers", Chain{answer(model.Allow, "fog", &first), answer(model.Allow, "cloud", &second)}, model.Allow, "fog", false},
		{"falls back on error", Chain{down, answer(model.Allow, "cloud", &second)}, model.Allow, "cloud", false},
		{"a deny is an answer", Chain{answer(model.Deny, "fog", &first), answer(model.Allow, "cloud", &second)}, model.Deny, "fog", false},
		{"all fail", Chain{down, down}, model.Deny, "", true},
		{"empty", Chain{}, model.Deny, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := tc.chain.Decide(context.Background(), writeTelemetry("bay-1"))
			if d.Effect != tc.want || d.DecidedBy != tc.wantBy || (err != nil) != tc.wantErr {
				t.Errorf("Decide() = %+v, %v", d, err)
			}
		})
	}
	if second != 1 {
		t.Errorf("the second decider was asked %d times, want 1 (only after an error)", second)
	}
	_, err := Chain{down, down}.Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || strings.Count(err.Error(), "down") != 2 {
		t.Errorf("all errors should be joined: %v", err)
	}
}
