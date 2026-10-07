// The evaluation engine: holds the installed policy and turns an access
// request into a decision with deny-overrides and default deny.

package policy

import (
	"errors"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// ErrStalePolicy is returned by Install for a policy whose version is not
// newer than the installed one, so an old policy can never replace a newer.
var ErrStalePolicy = errors.New("policy: version is not newer than the installed policy")

// Engine evaluates access requests against the installed policy. Evaluate may
// be called from many goroutines while Install replaces the policy.
type Engine struct {
	// TODO(ztc): hold the installed policy in an atomic.Pointer.
	DefaultTTL time.Duration // cache lifetime of a decision when the rule sets none
}

// NewEngine returns an engine with p installed and DefaultTTL 30 s. A nil p
// installs an empty policy, which denies everything.
func NewEngine(p *Policy) *Engine {
	// TODO(ztc): store p (or an empty policy) and set DefaultTTL.
	return &Engine{}
}

// Policy returns the installed policy. Callers must not modify it.
func (e *Engine) Policy() *Policy {
	// TODO(ztc): load the installed policy.
	return nil
}

// Install validates p and installs it if p.Version is newer than the
// installed version. On any error the installed policy is kept.
func (e *Engine) Install(p *Policy) error {
	// TODO(ztc): validate, compare versions, swap atomically.
	return nil
}

// Evaluate returns the decision for req with deny-overrides and default deny:
// the first matching deny rule decides; otherwise the first matching allow
// rule decides; otherwise the request is denied. The decision carries RuleID,
// Reason, TTL and PolicyVersion, and an allow also carries a copy of the
// rule's obligations. Evaluate never fails: every problem becomes a deny.
func (e *Engine) Evaluate(req model.AccessRequest) model.Decision {
	// TODO(ztc): match rules against req and combine with deny-overrides.
	return model.Decision{}
}
