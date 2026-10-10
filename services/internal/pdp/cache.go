// The decision cache: a Decider that remembers allows from the Decider behind
// it, for the hierarchical placement of RQ1.

package pdp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// Cache sits on a fog node in front of a slower Decider, usually a
// RemoteClient to the cloud PDP, and answers repeated requests from memory.
//
// Only allows are cached. A cached allow is forgotten when:
//   - its TTL (Decision.TTL, set by the policy rule) runs out;
//   - an answer from upstream carries a newer policy version or a newer
//     revocation epoch, which drops every entry;
//   - upstream denies the subject anything, which drops the subject's entries;
//   - InvalidateSubject is called, for example on an IDS alert.
//
// When upstream fails, an expired entry is never used: the answer is a deny.
type Cache struct {
	name     string
	upstream Decider
	maxSize  int

	mu              sync.Mutex
	now             func() time.Time
	entries         map[cacheKey]cacheEntry
	policyVersion   uint64 // newest policy version seen
	revocationEpoch uint64 // newest revocation epoch seen, a separate sequence
	hits, misses    uint64
}

// cacheKey identifies a request by a hash of everything a decision can depend
// on, so two requests share an entry only if the policy cannot tell them apart.
type cacheKey [sha256.Size]byte

type cacheEntry struct {
	subject string
	d       model.Decision
	expires time.Time
}

// NewCache returns a cache called name in front of upstream that holds at
// most maxSize decisions (at least 1).
func NewCache(name string, upstream Decider, maxSize int) *Cache {
	return &Cache{
		name:     name,
		upstream: upstream,
		maxSize:  max(maxSize, 1),
		now:      time.Now,
		entries:  make(map[cacheKey]cacheEntry),
	}
}

// SetClock replaces the clock used for TTLs, for tests.
func (c *Cache) SetClock(now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// Decide answers req from the cache if a live allow is stored for it, and
// asks upstream otherwise. A cached answer has DecidedBy set to the cache's
// name. If upstream fails, the answer is a deny and the error.
func (c *Cache) Decide(ctx context.Context, req model.AccessRequest) (model.Decision, error) {
	key, cacheable := keyOf(req)
	if cacheable {
		c.mu.Lock()
		e, ok := c.entries[key]
		if ok && c.now().Before(e.expires) {
			c.hits++
			c.mu.Unlock()
			e.d.DecidedBy = c.name
			return e.d, nil
		}
		c.misses++
		c.mu.Unlock()
	}

	d, err := c.upstream.Decide(ctx, req)
	if err != nil {
		return model.Decision{Effect: model.Deny, Reason: "no decision: " + err.Error(), DecidedBy: c.name}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.observe(d.PolicyVersion, d.RevocationEpoch)
	if !d.Allowed() {
		c.dropSubject(req.Subject.ID)
		return d, nil
	}
	stale := d.PolicyVersion < c.policyVersion || d.RevocationEpoch < c.revocationEpoch
	if cacheable && d.TTL > 0 && !stale {
		c.store(key, cacheEntry{subject: req.Subject.ID, d: d, expires: c.now().Add(d.TTL)})
	}
	return d, nil
}

// InvalidateSubject drops every cached decision for subject.
func (c *Cache) InvalidateSubject(subject string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropSubject(subject)
}

// Stats returns the number of hits and misses so far and the number of
// cached decisions.
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, len(c.entries)
}

// observe records the versions of an upstream answer and drops every entry if
// either is newer than seen before. The two are separate sequences: policy
// version 3 says nothing about revocation epoch 3. c.mu must be held.
func (c *Cache) observe(policyVersion, revocationEpoch uint64) {
	if policyVersion <= c.policyVersion && revocationEpoch <= c.revocationEpoch {
		return
	}
	c.policyVersion = max(c.policyVersion, policyVersion)
	c.revocationEpoch = max(c.revocationEpoch, revocationEpoch)
	clear(c.entries)
}

// dropSubject removes the entries of subject. c.mu must be held.
func (c *Cache) dropSubject(subject string) {
	for k, e := range c.entries {
		if e.subject == subject {
			delete(c.entries, k)
		}
	}
}

// store adds e, first removing expired entries and, if the cache is still
// full, the entry that would expire first. c.mu must be held.
func (c *Cache) store(key cacheKey, e cacheEntry) {
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxSize {
		now := c.now()
		var oldest cacheKey
		var oldestExpiry time.Time
		for k, old := range c.entries {
			if !now.Before(old.expires) {
				delete(c.entries, k)
				continue
			}
			if oldestExpiry.IsZero() || old.expires.Before(oldestExpiry) {
				oldest, oldestExpiry = k, old.expires
			}
		}
		if len(c.entries) >= c.maxSize {
			delete(c.entries, oldest)
		}
	}
	c.entries[key] = e
}

// keyOf hashes req without the fields the PDP sets itself (time, trust score,
// emergency). It reports false if req cannot be encoded; such a request is
// never cached.
func keyOf(req model.AccessRequest) (cacheKey, bool) {
	req.Context.Time = time.Time{}
	req.Context.TrustScore = 0
	req.Context.Emergency = false
	data, err := json.Marshal(req)
	if err != nil {
		return cacheKey{}, false
	}
	return sha256.Sum256(data), true
}

// Check at compile time that *Cache satisfies Decider.
var _ Decider = (*Cache)(nil)
