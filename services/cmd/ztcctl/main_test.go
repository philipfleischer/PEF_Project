package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/observability"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
)

func envFrom(vars map[string]string) config.Env {
	return config.NewWithLookup(func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	})
}

// ztcctl runs one command and returns its exit status, stdout and stderr.
func ztcctl(t *testing.T, vars map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, envFrom(vars), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestPolicyDefault(t *testing.T) {
	code, out, _ := ztcctl(t, nil, "policy", "default")
	want, err := policy.Marshal(policy.DefaultSubstationPolicy())
	if code != exitOK || err != nil || out != string(want) {
		t.Errorf("policy default: exit %d, output differs from policy.Marshal: %v", code, err)
	}
}

func TestPolicyValidate(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.json"), filepath.Join(dir, "bad.json")
	for path, body := range map[string]string{
		good: `{"version":4,"rules":[{"id":"a","effect":"allow"}]}`,
		bad:  `{"version":4,"rules":[{"id":"a","effect":"allow","sujbects":["x"]}]}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, out, _ := ztcctl(t, nil, "policy", "validate", good); code != exitOK || !strings.Contains(out, "version 4 with 1 rules") {
		t.Errorf("validate good: exit %d, %q", code, out)
	}
	if code, _, errOut := ztcctl(t, nil, "policy", "validate", bad); code != exitError || !strings.Contains(errOut, "sujbects") {
		t.Errorf("validate bad: exit %d, %q", code, errOut)
	}
}

// TestDecideAndSignal runs ztcctl against a real PDP over HTTP.
func TestDecideAndSignal(t *testing.T) {
	p := pdp.New("cloud-pdp", policy.NewEngine(policy.DefaultSubstationPolicy()))
	srv := httptest.NewServer(pdp.NewHandler(p, "secret", observability.NewRegistry()))
	defer srv.Close()
	vars := map[string]string{"ZTC_PDP_URL": srv.URL, "ZTC_PDP_TOKEN": "secret"}
	pmu := "spiffe://grid.example/edge/pmu/1"
	write := func(rzone string) []string {
		return []string{"decide", "-subject", pmu, "-action", "write", "-resource", rzone + "/telemetry/pmu-1",
			"-type", "telemetry", "-zone", "bay-1", "-resource-zone", rzone}
	}

	if code, out, _ := ztcctl(t, vars, write("bay-1")...); code != exitDeny || !strings.HasPrefix(out, "deny: denied by rule deny-untrusted") {
		t.Errorf("unknown PMU: exit %d, %q", code, out)
	}
	for _, kv := range [][2]string{{"authentication", "0.8"}, {"posture", "1"}} {
		if code, _, errOut := ztcctl(t, vars, "signal", "-subject", pmu, "-kind", kv[0], "-value", kv[1]); code != exitOK {
			t.Fatalf("signal %s: exit %d, %s", kv[0], code, errOut)
		}
	}
	if code, out, _ := ztcctl(t, vars, write("bay-1")...); code != exitOK || !strings.HasPrefix(out, "allow: allowed by rule edge-write-telemetry") {
		t.Errorf("own bay: exit %d, %q", code, out)
	}
	if code, out, _ := ztcctl(t, vars, write("bay-2")...); code != exitDeny || !strings.Contains(out, "default deny") {
		t.Errorf("other bay: exit %d, %q", code, out)
	}
}

func TestErrors(t *testing.T) {
	unreachable := map[string]string{"ZTC_PDP_URL": "http://127.0.0.1:1", "ZTC_PDP_TOKEN": "x"}
	decide := []string{"decide", "-subject", "spiffe://grid.example/edge/pmu/1", "-resource", "r", "-type", "telemetry"}
	tests := []struct {
		name string
		vars map[string]string
		args []string
		want int
	}{
		{"no command", nil, nil, exitUsage},
		{"unknown command", nil, []string{"reboot"}, exitUsage},
		{"help", nil, []string{"decide", "-h"}, exitOK},
		{"unknown flag", nil, []string{"decide", "-subjct", "x"}, exitUsage},
		{"missing flags", nil, []string{"decide", "-subject", "spiffe://grid.example/edge/pmu/1"}, exitUsage},
		{"not a SPIFFE ID", nil, []string{"decide", "-subject", "pmu-1", "-resource", "r", "-type", "t"}, exitUsage},
		{"unknown layer", nil, []string{"decide", "-subject", "spiffe://grid.example/moon/pmu/1", "-resource", "r", "-type", "t"}, exitUsage},
		{"PDP unreachable", unreachable, decide, exitError},
		{"signal without token", nil, []string{"signal", "-subject", "s", "-kind", "posture"}, exitError},
		{"signal with unknown kind", unreachable, []string{"signal", "-subject", "s", "-kind", "reset"}, exitUsage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, errOut := ztcctl(t, tc.vars, tc.args...); code != tc.want {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tc.want, errOut)
			}
		})
	}
}
