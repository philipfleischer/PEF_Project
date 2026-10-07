// The evaluation engine: holds the installed policy and turns an access
// request into a decision with deny-overrides and default deny.

package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// ErrStalePolicy is returned by Install for a policy whose version is not
// newer than the installed one, so an old policy can never replace a newer.
var ErrStalePolicy = errors.New("policy: version is not newer than the installed policy")

// Engine evaluates access requests against the installed policy. Evaluate may
// be called from many goroutines while Install replaces the policy.
type Engine struct {
	current    atomic.Pointer[Policy] // never nil after NewEngine; readers never lock
	DefaultTTL time.Duration          // cache lifetime of a decision when the rule sets none
}

// NewEngine returns an engine with p installed and DefaultTTL 30 s. A nil p
// installs an empty policy, which denies everything.
func NewEngine(p *Policy) *Engine {
	if p == nil {
		p = &Policy{}
	}
	e := &Engine{DefaultTTL: 30 * time.Second}
	e.current.Store(p)
	return e
}

// Policy returns the installed policy. Callers must not modify it.
func (e *Engine) Policy() *Policy { return e.current.Load() }

// Install validates p and installs it if p.Version is newer than the
// installed version. On any error the installed policy is kept.
func (e *Engine) Install(p *Policy) error {
	if err := Validate(p); err != nil {
		return err
	}
	for {
		old := e.current.Load()
		if p.Version <= old.Version {
			return fmt.Errorf("%w (have %d, got %d)", ErrStalePolicy, old.Version, p.Version)
		}
		if e.current.CompareAndSwap(old, p) {
			return nil
		}
		// Another Install won the race; compare against its version and retry.
	}
}

// Evaluate returns the decision for req with deny-overrides and default deny:
// the first matching deny rule decides; otherwise the first matching allow
// rule decides; otherwise the request is denied. The decision carries RuleID,
// Reason, TTL and PolicyVersion, and an allow also carries a copy of the
// rule's obligations. Evaluate never fails: every problem becomes a deny.
func (e *Engine) Evaluate(req model.AccessRequest) model.Decision {
	p := e.current.Load() // one snapshot for the whole evaluation
	var allow *Rule
	for i := range p.Rules {
		r := &p.Rules[i]
		if !matches(r, req) {
			continue
		}
		if r.Effect == model.Deny {
			return model.Decision{
				Effect: model.Deny, Reason: "denied by rule " + r.ID, RuleID: r.ID,
				TTL: e.ttl(r), PolicyVersion: p.Version,
			}
		}
		if allow == nil {
			allow = r
		}
	}
	if allow == nil {
		return model.Decision{
			Effect: model.Deny, Reason: "no rule matched (default deny)",
			TTL: e.DefaultTTL, PolicyVersion: p.Version,
		}
	}
	return model.Decision{
		Effect: model.Allow, Reason: "allowed by rule " + allow.ID, RuleID: allow.ID,
		TTL: e.ttl(allow), PolicyVersion: p.Version,
		Obligations: append([]string(nil), allow.Obligations...),
	}
}

// ttl returns how long a decision made by r may be cached.
func (e *Engine) ttl(r *Rule) time.Duration {
	if r.TTLSeconds > 0 {
		return time.Duration(r.TTLSeconds) * time.Second
	}
	return e.DefaultTTL
}

// matches reports whether r applies to req: every non-empty pattern list has
// a match and every condition holds.
func matches(r *Rule, req model.AccessRequest) bool {
	if len(r.Subjects) > 0 && !matchSubject(r.Subjects, req.Subject) {
		return false
	}
	if len(r.Resources) > 0 && !matchResource(r.Resources, req.Resource) {
		return false
	}
	if len(r.Actions) > 0 && !matchAny(r.Actions, req.Action) {
		return false
	}
	for _, c := range r.Conditions {
		if !evalCondition(c, req) {
			return false
		}
	}
	return true
}

// matchAny reports whether s matches at least one of the glob patterns.
func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if Glob(p, s) {
			return true
		}
	}
	return false
}

// matchSubject matches "role:<glob>" against each of the subject's roles and
// any other pattern against its SPIFFE ID.
func matchSubject(patterns []string, s model.Subject) bool {
	for _, p := range patterns {
		if role, ok := strings.CutPrefix(p, "role:"); ok {
			for _, have := range s.Roles {
				if Glob(role, have) {
					return true
				}
			}
			continue
		}
		if Glob(p, s.ID) {
			return true
		}
	}
	return false
}

// matchResource matches "type:<glob>" against the resource type and any other
// pattern against the resource ID.
func matchResource(patterns []string, r model.Resource) bool {
	for _, p := range patterns {
		if typ, ok := strings.CutPrefix(p, "type:"); ok {
			if Glob(typ, r.Type) {
				return true
			}
			continue
		}
		if Glob(p, r.ID) {
			return true
		}
	}
	return false
}

// evalCondition reports whether c holds for req. A missing attribute, an
// unknown operator or a value that is not a number for a numeric operator
// all give false (fail closed).
func evalCondition(c Condition, req model.AccessRequest) bool {
	v, ok := Resolve(c.Attribute, req)
	if !ok {
		return false
	}
	switch c.Op {
	case "eq":
		return v == c.Value
	case "neq":
		return v != c.Value
	case "in":
		return overlaps(splitList(v), splitList(c.Value))
	case "nin":
		return !overlaps(splitList(v), splitList(c.Value))
	case "glob":
		return Glob(c.Value, v)
	case "sameAs":
		other, ok := Resolve(c.Value, req)
		return ok && v != "" && v == other
	case "gt", "gte", "lt", "lte":
		a, errA := parseNumber(v)
		b, errB := parseNumber(c.Value)
		if errA != nil || errB != nil {
			return false
		}
		switch c.Op {
		case "gt":
			return a > b
		case "gte":
			return a >= b
		case "lt":
			return a < b
		default:
			return a <= b
		}
	}
	return false
}

// isNumericOp reports whether op compares numbers.
func isNumericOp(op string) bool { return op == "gt" || op == "gte" || op == "lt" || op == "lte" }

// parseNumber parses a decimal number such as "0.8", ignoring surrounding spaces.
func parseNumber(s string) (float64, error) { return strconv.ParseFloat(strings.TrimSpace(s), 64) }

// splitList splits a comma-separated list and drops spaces and empty items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// overlaps reports whether a and b have at least one item in common.
func overlaps(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}
