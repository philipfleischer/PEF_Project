// Tests for the evaluation engine: rule matching, every condition operator,
// deny-overrides, decision fields, Install and concurrent use. Written before
// the engine, so they fail until it is implemented.

package policy

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// cond is shorthand for a Condition in the test tables.
func cond(attr, op, value string) Condition {
	return Condition{Attribute: attr, Op: op, Value: value}
}

func TestEvaluate(t *testing.T) {
	allowAll := Rule{ID: "allow-all", Effect: model.Allow}
	tests := []struct {
		name     string
		rules    []Rule
		mutate   func(r *model.AccessRequest) // nil means sampleRequest() as is
		want     model.Effect
		wantRule string
	}{
		// Combining algorithm.
		{"no rules: default deny", nil, nil, model.Deny, ""},
		{"matching allow", []Rule{allowAll}, nil, model.Allow, "allow-all"},
		{"deny before allow wins", []Rule{{ID: "d", Effect: model.Deny}, allowAll}, nil, model.Deny, "d"},
		{"deny after allow wins", []Rule{allowAll, {ID: "d", Effect: model.Deny}}, nil, model.Deny, "d"},
		{"non-matching deny is ignored", []Rule{allowAll, {ID: "d", Effect: model.Deny, Actions: []string{"write"}}}, nil, model.Allow, "allow-all"},
		{"first matching allow is reported", []Rule{{ID: "a1", Effect: model.Allow}, {ID: "a2", Effect: model.Allow}}, nil, model.Allow, "a1"},

		// Subjects, resources and actions.
		{"action matches", []Rule{{ID: "a", Effect: model.Allow, Actions: []string{"read"}}}, nil, model.Allow, "a"},
		{"action differs", []Rule{{ID: "a", Effect: model.Allow, Actions: []string{"write"}}}, nil, model.Deny, ""},
		{"role pattern", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"role:operator"}}}, nil, model.Allow, "a"},
		{"role pattern, role missing", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"role:auditor"}}}, nil, model.Deny, ""},
		{"SPIFFE pattern", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"spiffe://*/fog/*"}}}, nil, model.Allow, "a"},
		{"SPIFFE pattern, other layer", []Rule{{ID: "a", Effect: model.Allow, Subjects: []string{"spiffe://*/edge/*"}}}, nil, model.Deny, ""},
		{"resource type pattern", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"type:breaker"}}}, nil, model.Allow, "a"},
		{"resource type differs", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"type:telemetry"}}}, nil, model.Deny, ""},
		{"resource ID pattern", []Rule{{ID: "a", Effect: model.Allow, Resources: []string{"substation-1/*"}}}, nil, model.Allow, "a"},

		// Condition operators.
		{"eq", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "eq", "substation-1")}}}, nil, model.Allow, "a"},
		{"neq", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "neq", "substation-1")}}}, nil, model.Deny, ""},
		{"in", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.sourceZone", "in", "control-centre, substation-hmi")}}}, nil, model.Allow, "a"},
		{"nin", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.sourceZone", "nin", "control-centre,substation-hmi")}}}, nil, model.Deny, ""},
		{"in on multi-valued role", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.role", "in", "engineer")}}}, nil, model.Allow, "a"},
		{"glob", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("resource.id", "glob", "*/breaker/*")}}}, nil, model.Allow, "a"},
		{"gte at the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.trustScore", "gte", "0.8")}}},
			func(r *model.AccessRequest) { r.Context.TrustScore = 0.8 }, model.Allow, "a"},
		{"gte just below the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.trustScore", "gte", "0.8")}}},
			func(r *model.AccessRequest) { r.Context.TrustScore = 0.79 }, model.Deny, ""},
		{"gt at the threshold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.trustScore", "gt", "0.85")}}}, nil, model.Deny, ""},
		{"lt", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("resource.sensitivity", "lt", "5")}}}, nil, model.Allow, "a"},
		{"lte", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("resource.sensitivity", "lte", "3")}}}, nil, model.Deny, ""},
		{"numeric op on text never matches", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "gt", "1")}}}, nil, model.Deny, ""},
		{"sameAs", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "sameAs", "resource.zone")}}}, nil, model.Allow, "a"},
		{"sameAs, other zone", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "sameAs", "resource.zone")}}},
			func(r *model.AccessRequest) { r.Resource.Zone = "substation-2" }, model.Deny, ""},
		{"sameAs, both empty", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.zone", "sameAs", "resource.zone")}}},
			func(r *model.AccessRequest) { r.Subject.Zone, r.Resource.Zone = "", "" }, model.Deny, ""},
		{"missing attribute never matches", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("subject.attr.clearance", "eq", "")}}}, nil, model.Deny, ""},
		{"all conditions must hold", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{
			cond("subject.zone", "eq", "substation-1"), cond("action", "eq", "write")}}}, nil, model.Deny, ""},

		// Time.
		{"night deny, daytime request", []Rule{allowAll, {ID: "deny-night", Effect: model.Deny, Conditions: []Condition{cond("context.hour", "lt", "6")}}}, nil, model.Allow, "allow-all"},
		{"night deny, night request", []Rule{allowAll, {ID: "deny-night", Effect: model.Deny, Conditions: []Condition{cond("context.hour", "lt", "6")}}},
			func(r *model.AccessRequest) { r.Context.Time = time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC) }, model.Deny, "deny-night"},
		{"time condition without time", []Rule{{ID: "a", Effect: model.Allow, Conditions: []Condition{cond("context.hour", "gte", "0")}}},
			func(r *model.AccessRequest) { r.Context.Time = time.Time{} }, model.Deny, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := sampleRequest()
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			d := NewEngine(&Policy{Version: 1, Rules: tc.rules}).Evaluate(req)
			if d.Effect != tc.want || d.RuleID != tc.wantRule {
				t.Errorf("Evaluate() = %s by %q (%s), want %s by %q", d.Effect, d.RuleID, d.Reason, tc.want, tc.wantRule)
			}
		})
	}
}

func TestEvaluateDecisionFields(t *testing.T) {
	e := NewEngine(&Policy{Version: 7, Rules: []Rule{
		{ID: "read", Effect: model.Allow, Actions: []string{"read"}, Obligations: []string{"log", "reverify:10s"}, TTLSeconds: 10},
		{ID: "write", Effect: model.Allow, Actions: []string{"write"}},
	}})

	d := e.Evaluate(sampleRequest())
	if d.RuleID != "read" || d.PolicyVersion != 7 || d.TTL != 10*time.Second || d.Reason == "" {
		t.Errorf("allow decision = %+v", d)
	}
	if !slices.Equal(d.Obligations, []string{"log", "reverify:10s"}) {
		t.Fatalf("obligations = %v", d.Obligations)
	}
	d.Obligations[0] = "changed" // the caller owns its copy
	if got := installed(t, e).Rules[0].Obligations[0]; got != "log" {
		t.Errorf("changing the decision changed the policy: %q", got)
	}

	write := sampleRequest()
	write.Action = "write"
	if d := e.Evaluate(write); d.TTL != e.DefaultTTL || d.TTL != 30*time.Second {
		t.Errorf("rule without TTL: TTL = %v, want DefaultTTL 30s", d.TTL)
	}

	execute := sampleRequest()
	execute.Action = "execute"
	d = e.Evaluate(execute)
	if d.Allowed() || d.PolicyVersion != 7 || d.Reason == "" || len(d.Obligations) != 0 {
		t.Errorf("default deny decision = %+v", d)
	}
}

// installed returns the engine's policy and stops the test if there is none,
// so a missing policy is reported as a failure instead of a nil-pointer panic.
func installed(t *testing.T, e *Engine) *Policy {
	t.Helper()
	p := e.Policy()
	if p == nil {
		t.Fatal("Policy() = nil, want the installed policy")
	}
	return p
}

func TestNewEngineNil(t *testing.T) {
	e := NewEngine(nil)
	installed(t, e)
	if d := e.Evaluate(sampleRequest()); d.Allowed() {
		t.Errorf("empty engine allowed: %+v", d)
	}
}

func TestInstall(t *testing.T) {
	e := NewEngine(&Policy{Version: 1})
	allowAll := []Rule{{ID: "allow-all", Effect: model.Allow}}

	if err := e.Install(nil); err == nil {
		t.Error("Install(nil) = nil, want error")
	}
	invalid := &Policy{Version: 2, Rules: []Rule{{ID: "x", Effect: "maybe"}}}
	if err := e.Install(invalid); err == nil {
		t.Error("invalid policy installed")
	}
	if err := e.Install(&Policy{Version: 1, Rules: allowAll}); !errors.Is(err, ErrStalePolicy) {
		t.Errorf("same version: err = %v, want ErrStalePolicy", err)
	}
	if v := installed(t, e).Version; v != 1 {
		t.Fatalf("a rejected Install changed the policy: version %d", v)
	}

	if err := e.Install(&Policy{Version: 2, Rules: allowAll}); err != nil {
		t.Fatalf("Install(v2) = %v", err)
	}
	if v := installed(t, e).Version; v != 2 {
		t.Errorf("version = %d, want 2", v)
	}
	if !e.Evaluate(sampleRequest()).Allowed() {
		t.Error("the new policy is not used")
	}
	if err := e.Install(&Policy{Version: 1}); !errors.Is(err, ErrStalePolicy) {
		t.Errorf("older version: err = %v, want ErrStalePolicy", err)
	}
}

// TestConcurrentEvaluateAndInstall is for the race detector (make test runs
// with -race): readers must never see a half-installed policy.
func TestConcurrentEvaluateAndInstall(t *testing.T) {
	e := NewEngine(&Policy{Version: 1})
	req := sampleRequest()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				e.Evaluate(req)
			}
		})
	}
	for v := uint64(2); v <= 100; v++ {
		if err := e.Install(&Policy{Version: v, Rules: []Rule{{ID: "allow-all", Effect: model.Allow}}}); err != nil {
			t.Errorf("Install(v%d) = %v", v, err)
		}
	}
	wg.Wait()
	if v := installed(t, e).Version; v != 100 {
		t.Errorf("version = %d, want 100", v)
	}
}
