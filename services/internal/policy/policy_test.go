// Tests for the policy types and Validate.
package policy

import (
	"strings"
	"testing"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// validPolicy returns a small policy that passes Validate; each test case
// breaks one thing in its own copy.
func validPolicy() *Policy {
	return &Policy{
		Version: 1,
		Rules: []Rule{
			{ID: "deny-untrusted", Effect: model.Deny,
				Conditions: []Condition{{Attribute: "context.trustScore", Op: "lt", Value: "0.3"}}},
			{ID: "edge-write-telemetry", Effect: model.Allow, Actions: []string{"write"},
				Resources:  []string{"type:telemetry"},
				Conditions: []Condition{{Attribute: "subject.zone", Op: "sameAs", Value: "resource.zone"}},
				TTLSeconds: 60},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *Policy)
		wantErr string // "" means the policy must be valid
	}{
		{"valid", func(*Policy) {}, ""},
		{"no rules is valid (engine denies everything)", func(p *Policy) { p.Rules = nil }, ""},
		{"empty id", func(p *Policy) { p.Rules[0].ID = "" }, "empty id"},
		{"duplicate id", func(p *Policy) { p.Rules[1].ID = p.Rules[0].ID }, "duplicate id"},
		{"unknown effect", func(p *Policy) { p.Rules[0].Effect = "maybe" }, "unknown effect"},
		{"empty effect", func(p *Policy) { p.Rules[0].Effect = "" }, "unknown effect"},
		{"negative ttl", func(p *Policy) { p.Rules[1].TTLSeconds = -1 }, "negative ttlSeconds"},
		{"unknown op", func(p *Policy) { p.Rules[0].Conditions[0].Op = "approx" }, "unknown op"},
		{"unknown attribute", func(p *Policy) { p.Rules[0].Conditions[0].Attribute = "context.trustscore" }, "unknown attribute"},
		{"sameAs unknown attribute", func(p *Policy) { p.Rules[1].Conditions[0].Value = "resource.zon" }, "unknown attribute"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(p)
			err := Validate(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateNil(t *testing.T) {
	if Validate(nil) == nil {
		t.Fatal("Validate(nil) = nil, want error")
	}
}
