// Tests for the decision cache: what it remembers, every way it forgets, and
// that it never hides a failing upstream.

package pdp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// fakeUpstream answers with whatever answer returns and counts the calls.
type fakeUpstream struct {
	mu     sync.Mutex
	calls  int
	answer func(req model.AccessRequest) (model.Decision, error)
}

func (f *fakeUpstream) Decide(_ context.Context, req model.AccessRequest) (model.Decision, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.answer(req)
}

func (f *fakeUpstream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// allowFor returns an upstream that allows everything with the given TTL and
// versions, as a cloud PDP would.
func allowFor(ttl time.Duration, policyVersion, epoch uint64) *fakeUpstream {
	return &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		return model.Decision{Effect: model.Allow, TTL: ttl, PolicyVersion: policyVersion, RevocationEpoch: epoch, DecidedBy: "cloud-pdp"}, nil
	}}
}

// newCache returns a cache in front of up whose clock reads *now.
func newCache(up Decider, now *time.Time) *Cache {
	c := NewCache("fog-cache", up, 100)
	c.SetClock(func() time.Time { return *now })
	return c
}

// ask fails the test on an error and returns the decision.
func ask(t *testing.T, c *Cache, req model.AccessRequest) model.Decision {
	t.Helper()
	d, err := c.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	return d
}

func TestCacheHitWithinTTL(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := newCache(up, &now)
	if d := ask(t, c, writeTelemetry("bay-1")); d.DecidedBy != "cloud-pdp" {
		t.Errorf("first answer from %q, want cloud-pdp", d.DecidedBy)
	}
	now = now.Add(59 * time.Second)
	if d := ask(t, c, writeTelemetry("bay-1")); !d.Allowed() || d.DecidedBy != "fog-cache" {
		t.Errorf("second answer: %+v", d)
	}
	if hits, misses, size := c.Stats(); up.count() != 1 || hits != 1 || misses != 1 || size != 1 {
		t.Errorf("upstream calls %d, stats %d/%d/%d, want 1, 1/1/1", up.count(), hits, misses, size)
	}
}

func TestCacheExpires(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	now = now.Add(time.Minute)
	ask(t, c, writeTelemetry("bay-1"))
	if up.count() != 2 {
		t.Errorf("upstream calls = %d, want 2 after the TTL ran out", up.count())
	}
}

func TestCacheDoesNotCache(t *testing.T) {
	tests := []struct {
		name string
		up   *fakeUpstream
	}{
		{"deny", &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
			return model.Decision{Effect: model.Deny, TTL: time.Minute}, nil
		}}},
		{"allow without TTL", allowFor(0, 1, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := t0
			c := newCache(tc.up, &now)
			ask(t, c, writeTelemetry("bay-1"))
			ask(t, c, writeTelemetry("bay-1"))
			if tc.up.count() != 2 {
				t.Errorf("upstream calls = %d, want 2", tc.up.count())
			}
		})
	}
}

// TestCacheKeyCoversTheRequest is a flaw of the original, which keyed entries
// by subject, action and resource ID only: an allow from the control centre
// was reused for the same request from the enterprise network.
func TestCacheKeyCoversTheRequest(t *testing.T) {
	now := t0
	up := &fakeUpstream{answer: func(req model.AccessRequest) (model.Decision, error) {
		if req.Context.SourceZone != "control-centre" {
			return model.Decision{Effect: model.Deny}, nil
		}
		return model.Decision{Effect: model.Allow, TTL: 10 * time.Second}, nil
	}}
	c := newCache(up, &now)
	fromControl := operateBreaker()
	fromControl.Context.SourceZone = "control-centre"
	if d := ask(t, c, fromControl); !d.Allowed() {
		t.Fatalf("from the control centre: %+v", d)
	}
	if d := ask(t, c, operateBreaker()); d.Allowed() {
		t.Errorf("an allow from the control centre was reused for the enterprise network: %+v", d)
	}
}

// TestCacheKeysDoNotCollide is another flaw of the original: keys were
// "subject|action|resource", so subject "a|b" with action "c" and subject "a"
// with action "b|c" shared an entry.
func TestCacheKeysDoNotCollide(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := newCache(up, &now)
	first := model.AccessRequest{Subject: model.Subject{ID: "a|b"}, Action: "c", Resource: model.Resource{ID: "r"}}
	second := model.AccessRequest{Subject: model.Subject{ID: "a"}, Action: "b|c", Resource: model.Resource{ID: "r"}}
	ask(t, c, first)
	if d := ask(t, c, second); d.DecidedBy == "fog-cache" {
		t.Errorf("another subject's allow was served from the cache: %+v", d)
	}
}

func TestCacheIgnoresFieldsThePDPSets(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	req := writeTelemetry("bay-1")
	req.Context.Time, req.Context.TrustScore = t0.Add(time.Second), 0.9
	if d := ask(t, c, req); d.DecidedBy != "fog-cache" {
		t.Errorf("time and trust score in the request split the entry: %+v", d)
	}
}

// TestCacheInvalidatesOnDeny is the RQ4 finding of the original: without it a
// subject whose trust had just dropped kept using its cached allows.
func TestCacheInvalidatesOnDeny(t *testing.T) {
	now := t0
	compromised := false
	up := &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		if compromised {
			return model.Decision{Effect: model.Deny}, nil
		}
		return model.Decision{Effect: model.Allow, TTL: time.Minute}, nil
	}}
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	compromised = true
	ask(t, c, writeTelemetry("bay-2")) // a miss, and upstream denies the subject
	if d := ask(t, c, writeTelemetry("bay-1")); d.Allowed() {
		t.Errorf("a cached allow outlived a deny for the same subject: %+v", d)
	}
}

func TestCacheInvalidateSubject(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	ask(t, c, operateBreaker())
	c.InvalidateSubject(pmu)
	if _, _, size := c.Stats(); size != 1 {
		t.Errorf("size after InvalidateSubject = %d, want 1 (the operator's entry)", size)
	}
}

// TestCacheVersions checks that a newer policy version or revocation epoch
// drops every entry, tracked as two separate counters, and that an answer
// from an older policy is not cached.
func TestCacheVersions(t *testing.T) {
	tests := []struct {
		name             string
		policy, epoch    uint64
		wantKeptOldEntry bool
	}{
		{"same versions", 5, 1, true},
		{"newer policy", 6, 1, false},
		{"newer revocation epoch below the policy version", 5, 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := t0
			up := allowFor(time.Minute, 5, 1)
			c := newCache(up, &now)
			ask(t, c, writeTelemetry("bay-1"))
			up.answer = allowFor(time.Minute, tc.policy, tc.epoch).answer
			ask(t, c, operateBreaker())
			if d := ask(t, c, writeTelemetry("bay-1")); (d.DecidedBy == "fog-cache") != tc.wantKeptOldEntry {
				t.Errorf("old entry kept = %v, want %v", d.DecidedBy == "fog-cache", tc.wantKeptOldEntry)
			}
		})
	}

	now := t0
	up := allowFor(time.Minute, 5, 1)
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	up.answer = allowFor(time.Minute, 4, 1).answer // a replica that is behind
	ask(t, c, operateBreaker())
	if _, _, size := c.Stats(); size != 1 {
		t.Errorf("an answer from an older policy was cached: size %d, want 1", size)
	}
}

func TestCacheUpstreamFailure(t *testing.T) {
	now := t0
	fail := false
	up := &fakeUpstream{answer: func(model.AccessRequest) (model.Decision, error) {
		if fail {
			return model.Decision{Effect: model.Deny}, errors.New("WAN down")
		}
		return model.Decision{Effect: model.Allow, TTL: time.Minute}, nil
	}}
	c := newCache(up, &now)
	ask(t, c, writeTelemetry("bay-1"))
	fail = true
	if d := ask(t, c, writeTelemetry("bay-1")); !d.Allowed() {
		t.Errorf("a live entry should still be served while upstream is down: %+v", d)
	}
	now = now.Add(time.Minute)
	d, err := c.Decide(context.Background(), writeTelemetry("bay-1"))
	if err == nil || d.Allowed() {
		t.Errorf("expired entry with upstream down: %+v, %v, want a deny and an error", d, err)
	}
}

func TestCacheMaxSize(t *testing.T) {
	now := t0
	up := &fakeUpstream{answer: func(req model.AccessRequest) (model.Decision, error) {
		ttl := time.Minute
		if req.Resource.ID == "short" {
			ttl = time.Second
		}
		return model.Decision{Effect: model.Allow, TTL: ttl}, nil
	}}
	c := NewCache("fog-cache", up, 2)
	c.SetClock(func() time.Time { return now })
	for _, id := range []string{"short", "a", "b"} {
		ask(t, c, model.AccessRequest{Subject: model.Subject{ID: "s"}, Resource: model.Resource{ID: id}})
	}
	if _, _, size := c.Stats(); size != 2 {
		t.Errorf("size = %d, want 2", size)
	}
	before := up.count()
	ask(t, c, model.AccessRequest{Subject: model.Subject{ID: "s"}, Resource: model.Resource{ID: "a"}})
	if up.count() != before {
		t.Error("the entry that expires first should have been evicted, not a")
	}
}

// TestCacheConcurrentUse is for the race detector.
func TestCacheConcurrentUse(t *testing.T) {
	now := t0
	up := allowFor(time.Minute, 1, 0)
	c := NewCache("fog-cache", up, 4)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 100 {
				req := writeTelemetry("bay-1")
				req.Resource.ID = string(rune('a' + (i+j)%6))
				if _, err := c.Decide(context.Background(), req); err != nil {
					t.Error(err)
				}
				if j%10 == 0 {
					c.InvalidateSubject(pmu)
				}
			}
		})
	}
	wg.Go(func() { c.SetClock(func() time.Time { return now }) })
	wg.Wait()
	if _, _, size := c.Stats(); size > 4 {
		t.Errorf("size = %d, above the maximum of 4", size)
	}
}
