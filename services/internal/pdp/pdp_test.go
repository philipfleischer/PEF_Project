// Tests for the PDP: trust in decisions, facts the PDP will not take from the
// request, denials as trust signals, and compromise escalation.

package pdp

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

const (
	pmu      = "spiffe://grid.example/edge/pmu/1"
	operator = "spiffe://grid.example/cloud/operator/alice"
)

// t0 is 14:00, inside working hours.
var t0 = time.Date(2026, 10, 9, 14, 0, 0, 0, time.UTC)

// newPDP returns a PDP with the default substation policy whose clock reads *now.
func newPDP(t *testing.T, now *time.Time) *PDP {
	t.Helper()
	p := New("cloud-pdp", policy.NewEngine(policy.DefaultSubstationPolicy()))
	p.Trust.SetClock(func() time.Time { return *now })
	return p
}

// authenticate gives subject mTLS authentication, good posture and one
// location signal: 0.35·0.8 + 0.25 + 0.30 + 0.10·0.5 = 0.88.
func authenticate(t *testing.T, p *PDP, subject string) {
	t.Helper()
	for _, sig := range []trust.Signal{
		{Subject: subject, Kind: trust.Authentication, Value: 0.8},
		{Subject: subject, Kind: trust.Posture, Value: 1},
		{Subject: subject, Kind: trust.Location, Value: 1},
	} {
		if _, err := p.RecordSignal(sig); err != nil {
			t.Fatal(err)
		}
	}
}

// writeTelemetry is the PMU sending a measurement to a bay.
func writeTelemetry(bay string) model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: pmu, Layer: model.LayerEdge, Zone: "bay-1"},
		Action:   "write",
		Resource: model.Resource{ID: bay + "/telemetry/pmu-1", Type: "telemetry", Zone: bay},
	}
}

// operateBreaker is the operator switching a breaker from the enterprise zone.
func operateBreaker() model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: operator, Layer: model.LayerCloud, Zone: "enterprise", Roles: []string{"operator"}},
		Action:   "operate",
		Resource: model.Resource{ID: "bay-1/breaker/Q1", Type: "breaker", Zone: "bay-1"},
		Context:  model.Context{SourceZone: "enterprise"},
	}
}

// decide fails the test if the PDP returns an error.
func decide(t *testing.T, p *PDP, req model.AccessRequest) model.Decision {
	t.Helper()
	d, err := p.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	return d
}

func TestDecideUnknownSubject(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	d := decide(t, p, writeTelemetry("bay-1"))
	if d.Allowed() || d.RuleID != "deny-untrusted" || d.TrustScore != 0 || d.DecidedBy != "cloud-pdp" {
		t.Errorf("unknown PMU: %+v", d)
	}
}

func TestDecideAuthenticated(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	authenticate(t, p, pmu)
	d := decide(t, p, writeTelemetry("bay-1"))
	if !d.Allowed() || d.RuleID != "edge-write-telemetry" || math.Abs(d.TrustScore-0.88) > 1e-9 {
		t.Errorf("authenticated PMU: %+v", d)
	}
}

func TestDecideIgnoresClaimedTrust(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	req := writeTelemetry("bay-1")
	req.Context.TrustScore = 1 // a PEP must not be able to raise trust
	if d := decide(t, p, req); d.Allowed() || d.TrustScore != 0 {
		t.Errorf("claimed trust was used: %+v", d)
	}
}

func TestDecideIgnoresClaimedEmergency(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	authenticate(t, p, operator)
	req := operateBreaker()
	req.Context.Emergency = true
	if d := decide(t, p, req); d.Allowed() {
		t.Errorf("claimed emergency was used: %+v", d)
	}
	p.SetEmergency(true)
	if d := decide(t, p, operateBreaker()); !d.Allowed() || d.RuleID != "break-glass-breaker" {
		t.Errorf("emergency declared by the PDP: %+v", d)
	}
}

func TestDecideIgnoresClaimedTime(t *testing.T) {
	now := t0
	p := New("cloud-pdp", policy.NewEngine(&policy.Policy{Version: 1, Rules: []policy.Rule{
		{ID: "allow-all", Effect: model.Allow},
		{ID: "deny-night", Effect: model.Deny, Conditions: []policy.Condition{{Attribute: "context.hour", Op: "lt", Value: "6"}}},
	}}))
	p.Trust.SetClock(func() time.Time { return now })
	authenticate(t, p, pmu)

	req := writeTelemetry("bay-1")
	req.Context.Time = time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC) // claims night
	if d := decide(t, p, req); !d.Allowed() {
		t.Errorf("claimed time was used: %+v", d)
	}
	now = time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC) // it really is night
	if d := decide(t, p, writeTelemetry("bay-1")); d.RuleID != "deny-night" {
		t.Errorf("PDP clock at night: %+v", d)
	}
}

func TestDenialLowersTrust(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	authenticate(t, p, pmu)
	if d := decide(t, p, writeTelemetry("bay-2")); d.Allowed() {
		t.Fatalf("PMU wrote to another bay: %+v", d)
	}
	// 0.88 − 0.1 for one fresh denial
	if got := p.Trust.Score(pmu); math.Abs(got-0.78) > 1e-9 {
		t.Errorf("score after a denial = %v, want 0.78", got)
	}
}

func TestDecideCancelled(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	authenticate(t, p, pmu)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d, err := p.Decide(ctx, writeTelemetry("bay-1"))
	if err == nil || d.Allowed() {
		t.Errorf("cancelled request: %+v, %v", d, err)
	}
}

func TestRecordSignalEscalation(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	authenticate(t, p, pmu)
	tests := []struct {
		name  string
		value float64
		want  bool
	}{
		{"weak alert", 0.5, false},
		{"NaN is not an alert", math.NaN(), false},
		{"strong alert", 0.95, true},
		{"already compromised", 0.99, false},
	}
	for _, tc := range tests {
		got, err := p.RecordSignal(trust.Signal{Subject: pmu, Kind: trust.Behaviour, Value: tc.value, Source: "ztc-ids"})
		if err != nil || got != tc.want {
			t.Errorf("%s: RecordSignal() = %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}
	if d := decide(t, p, writeTelemetry("bay-1")); d.Allowed() || d.TrustScore != 0 {
		t.Errorf("compromised PMU: %+v", d)
	}
}

func TestRecordSignalRejectsInvalid(t *testing.T) {
	now := t0
	p := newPDP(t, &now)
	if _, err := p.RecordSignal(trust.Signal{Subject: pmu, Kind: "reset"}); err == nil {
		t.Error("RecordSignal() of an unknown kind = nil error")
	}
}
