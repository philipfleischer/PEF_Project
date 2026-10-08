// The trust store: the State of every subject, shared by the goroutines that
// record signals and the ones that ask for scores.

package trust

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Store keeps the trust State of every subject. It is safe for concurrent
// use: PEPs, the IDS and the PDP record signals while the PDP reads scores.
type Store struct {
	mu    sync.RWMutex
	eval  *Evaluator
	state map[string]State
	now   func() time.Time
}

// NewStore returns an empty store that scores with eval, or with
// NewEvaluator() if eval is nil, and reads time from the system clock.
func NewStore(eval *Evaluator) *Store {
	if eval == nil {
		eval = NewEvaluator()
	}
	return &Store{eval: eval, state: make(map[string]State), now: time.Now}
}

// SetClock replaces the clock the store reads "now" from, for tests and for
// replaying recorded signals. It is safe to call while the store is in use.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Record applies sig to the state of its subject. A signal without a time is
// stamped with the store's clock. A signal without a subject or with an
// unknown kind is rejected and changes nothing.
func (s *Store) Record(sig Signal) error {
	if sig.Subject == "" {
		return errors.New("trust: signal without subject")
	}
	if !sig.Kind.Valid() {
		return fmt.Errorf("trust: unknown signal kind %q", sig.Kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sig.Time.IsZero() {
		sig.Time = s.now()
	}
	s.state[sig.Subject] = s.eval.Apply(s.state[sig.Subject], sig)
	return nil
}

// Score returns the current trust score of subject. An unknown subject
// scores 0: zero trust until proven otherwise.
func (s *Store) Score(subject string) float64 {
	s.mu.RLock()
	st := s.state[subject]
	now := s.now()
	s.mu.RUnlock()
	return s.eval.Score(st, now)
}

// State returns a copy of the state of subject and whether it is known.
func (s *Store) State(subject string) (State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.state[subject]
	return st, ok
}

// Subjects returns the IDs of all known subjects in sorted order.
func (s *Store) Subjects() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.state))
	for id := range s.state {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
