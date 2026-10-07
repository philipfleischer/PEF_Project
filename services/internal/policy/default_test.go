// Tests for the default substation policy: one row per kind of subject and
// the boundaries that matter in the substation.

package policy

import (
	"slices"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// actor is a subject in the substation scenario.
type actor struct {
	id    string
	layer model.Layer
	zone  string
	roles []string
}

var (
	pmu       = actor{"spiffe://grid.example/edge/pmu/1", model.LayerEdge, "bay-1", nil}
	fogNode   = actor{"spiffe://grid.example/fog/gateway/1", model.LayerFog, "bay-1", nil}
	operator  = actor{"spiffe://grid.example/cloud/operator/alice", model.LayerCloud, "control-centre", []string{"operator"}}
	engineer  = actor{"spiffe://grid.example/cloud/engineer/bob", model.LayerCloud, "control-centre", []string{"engineer"}}
	auditor   = actor{"spiffe://grid.example/cloud/auditor/eve", model.LayerCloud, "control-centre", []string{"auditor"}}
	admin     = actor{"spiffe://grid.example/cloud/admin/root", model.LayerCloud, "control-centre", nil}
	analytics = actor{"spiffe://grid.example/cloud/analytics/1", model.LayerCloud, "cloud", nil}
)

// wants builds a request from a to perform action on a resource of type
// rtype in zone rzone, sent from a's own zone with the given trust score.
func (a actor) wants(action, rtype, rzone string, trust float64) model.AccessRequest {
	return model.AccessRequest{
		Subject:  model.Subject{ID: a.id, Layer: a.layer, Zone: a.zone, Roles: a.roles},
		Action:   action,
		Resource: model.Resource{ID: rzone + "/" + rtype + "/1", Type: rtype, Zone: rzone},
		Context: model.Context{Time: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), TrustScore: trust,
			SourceZone: a.zone, SourceLayer: a.layer},
	}
}

func TestDefaultSubstationPolicyIsValid(t *testing.T) {
	p := DefaultSubstationPolicy()
	if err := Validate(p); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if p.Version != 1 {
		t.Errorf("version = %d, want 1", p.Version)
	}
}

func TestDefaultSubstationPolicy(t *testing.T) {
	fromEnterprise := func(r *model.AccessRequest) { r.Context.SourceZone = "enterprise" }
	emergency := func(r *model.AccessRequest) { r.Context.SourceZone, r.Context.Emergency = "enterprise", true }
	alsoOperator := func(r *model.AccessRequest) { r.Subject.Roles = []string{"auditor", "operator"} }
	adminIsAuditor := func(r *model.AccessRequest) { r.Subject.Roles = []string{"auditor"} }

	tests := []struct {
		name     string
		req      model.AccessRequest
		mutate   func(r *model.AccessRequest)
		want     model.Effect
		wantRule string
	}{
		// Edge devices.
		{"PMU writes telemetry to its own bay", pmu.wants("write", "telemetry", "bay-1", 0.6), nil, model.Allow, "edge-write-telemetry"},
		{"PMU writes telemetry to another bay", pmu.wants("write", "telemetry", "bay-2", 0.6), nil, model.Deny, ""},
		{"untrusted PMU", pmu.wants("write", "telemetry", "bay-1", 0.2), nil, model.Deny, "deny-untrusted"},
		{"PMU operates a breaker", pmu.wants("operate", "breaker", "bay-1", 0.99), nil, model.Deny, ""},
		{"PMU runs a task in its own bay", pmu.wants("execute", "task", "bay-1", 0.6), nil, model.Allow, "edge-offload-task"},

		// Fog and cloud services.
		{"fog reads telemetry of its own bay", fogNode.wants("read", "telemetry", "bay-1", 0.6), nil, model.Allow, "fog-read-telemetry"},
		{"fog reads telemetry of another bay", fogNode.wants("read", "telemetry", "bay-2", 0.6), nil, model.Deny, ""},
		{"fog executes a task", fogNode.wants("execute", "task", "bay-1", 0.6), nil, model.Allow, "execute-task"},
		{"fog migrates a service", fogNode.wants("migrate", "service", "bay-1", 0.7), nil, model.Allow, "migrate-service"},
		{"analytics reads aggregates", analytics.wants("read", "telemetry-aggregate", "bay-1", 0.6), nil, model.Allow, "cloud-read-aggregates"},
		{"analytics reads raw telemetry", analytics.wants("read", "telemetry", "bay-1", 0.9), nil, model.Deny, ""},

		// Operators and engineers.
		{"operator at the trust threshold", operator.wants("operate", "breaker", "bay-1", 0.8), nil, model.Allow, "operate-breaker"},
		{"operator just below the threshold", operator.wants("operate", "breaker", "bay-1", 0.79), nil, model.Deny, ""},
		{"operator from the enterprise zone", operator.wants("operate", "breaker", "bay-1", 0.95), fromEnterprise, model.Deny, ""},
		{"operator in emergency mode", operator.wants("operate", "breaker", "bay-1", 0.6), emergency, model.Allow, "break-glass-breaker"},
		{"emergency does not lift the trust floor", operator.wants("operate", "breaker", "bay-1", 0.4), emergency, model.Deny, ""},
		{"engineer writes a setpoint", engineer.wants("write", "setpoint", "bay-1", 0.7), nil, model.Allow, "write-setpoint"},
		{"operator writes a setpoint", operator.wants("write", "setpoint", "bay-1", 0.95), nil, model.Deny, ""},

		// Auditors (TEK5520 exercise: read, never write).
		{"auditor reads telemetry", auditor.wants("read", "telemetry", "bay-1", 0.6), nil, model.Allow, "auditor-read"},
		{"auditor reads the audit log", auditor.wants("read", "audit-log", "cloud", 0.6), nil, model.Allow, "auditor-read"},
		{"auditor reads the policy", auditor.wants("read", "policy", "cloud", 0.6), nil, model.Allow, "auditor-read"},
		{"auditor writes telemetry", auditor.wants("write", "telemetry", "bay-1", 0.9), nil, model.Deny, "auditor-read-only"},
		{"auditor who is also operator", auditor.wants("operate", "breaker", "bay-1", 0.9), alsoOperator, model.Deny, "auditor-read-only"},
		{"admin with the auditor role", admin.wants("write", "policy", "cloud", 0.9), adminIsAuditor, model.Deny, "auditor-read-only"},

		// Policy administration.
		{"admin changes the policy", admin.wants("write", "policy", "cloud", 0.8), nil, model.Allow, "policy-admin"},
		{"admin with low trust", admin.wants("write", "policy", "cloud", 0.7), nil, model.Deny, ""},
		{"operator changes the policy", operator.wants("write", "policy", "cloud", 0.95), nil, model.Deny, ""},

		// Anything not listed.
		{"unknown action", operator.wants("delete", "breaker", "bay-1", 0.95), nil, model.Deny, ""},
	}
	e := NewEngine(DefaultSubstationPolicy())
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			d := e.Evaluate(req)
			if d.Effect != tc.want || d.RuleID != tc.wantRule {
				t.Errorf("Evaluate() = %s by %q (%s), want %s by %q", d.Effect, d.RuleID, d.Reason, tc.want, tc.wantRule)
			}
		})
	}
}

func TestDefaultSubstationPolicyBreakerDecision(t *testing.T) {
	d := NewEngine(DefaultSubstationPolicy()).Evaluate(operator.wants("operate", "breaker", "bay-1", 0.9))
	if d.TTL != 10*time.Second || !slices.Equal(d.Obligations, []string{"log", "reverify:10s"}) {
		t.Errorf("breaker decision = %+v, want TTL 10s and obligations log, reverify:10s", d)
	}
}

func TestDefaultSubstationPolicyIsFresh(t *testing.T) {
	p := DefaultSubstationPolicy()
	p.Rules[0].ID = "changed"
	if got := DefaultSubstationPolicy().Rules[0].ID; got != "deny-untrusted" {
		t.Errorf("a change to one copy leaked into the next: %q", got)
	}
}
