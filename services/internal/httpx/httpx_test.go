package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]int{"answer": 42})

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got, want := rec.Body.String(), "{\"answer\":42}\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestError(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, http.StatusForbidden, "denied")

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got, want := rec.Body.String(), "{\"error\":\"denied\"}\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestReadJSON(t *testing.T) {
	type request struct {
		Subject string `json:"subject"`
	}
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid", `{"subject":"pmu-7"}`, false},
		{"unknown field", `{"subject":"pmu-7","admin":true}`, true},
		{"trailing data", `{"subject":"pmu-7"}{"subject":"evil"}`, true},
		{"malformed", `{"subject":`, true},
		{"empty", ``, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			var got request
			err := ReadJSON(httptest.NewRecorder(), r, &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ReadJSON error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got.Subject != "pmu-7" {
				t.Errorf("Subject = %q, want pmu-7", got.Subject)
			}
		})
	}
}

func TestReadJSONRejectsOversizedBody(t *testing.T) {
	body := `{"subject":"` + strings.Repeat("a", MaxBody) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	var v struct {
		Subject string `json:"subject"`
	}
	err := ReadJSON(httptest.NewRecorder(), r, &v)

	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("ReadJSON error = %v, want *http.MaxBytesError", err)
	}
}

func TestRunShutsDownWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer("127.0.0.1:0", http.NotFoundHandler())

	done := make(chan error, 1)
	go func() { done <- Run(ctx, srv) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

func TestRunFailsWhenPortIsInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := NewServer(ln.Addr().String(), http.NotFoundHandler())
	if err := Run(context.Background(), srv); err == nil {
		t.Fatal("Run returned nil on a port that is in use, want an error")
	}
}
