// Tests for the trust store: unknown subjects, the injectable clock, input
// checks and concurrent use under the race detector.

package trust

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// fixedClock returns a store whose clock reads *now, so a test can move time.
func fixedClock(now *time.Time) *Store {
	s := NewStore(nil)
	s.SetClock(func() time.Time { return *now })
	return s
}

// record fails the test if the store rejects sig.
func record(t *testing.T, s *Store, sig Signal) {
	t.Helper()
	if err := s.Record(sig); err != nil {
		t.Fatalf("Record(%+v) = %v", sig, err)
	}
}

func TestStoreUnknownSubject(t *testing.T) {
	s := NewStore(nil)
	if got := s.Score("spiffe://grid.example/edge/pmu/9"); got != 0 {
		t.Errorf("Score(unknown) = %v, want 0", got)
	}
	if _, ok := s.State("spiffe://grid.example/edge/pmu/9"); ok {
		t.Error("State(unknown) reported a known subject")
	}
}

func TestStoreScoreFollowsTheClock(t *testing.T) {
	now := t0
	s := fixedClock(&now)
	pmu := "spiffe://grid.example/edge/pmu/1"
	record(t, s, Signal{Subject: pmu, Kind: Authentication, Value: 1})
	record(t, s, Signal{Subject: pmu, Kind: Posture, Value: 1})
	record(t, s, Signal{Subject: pmu, Kind: Location, Value: 1})

	st, _ := s.State(pmu)
	if !st.LastAuth.Equal(t0) {
		t.Errorf("signal without time: LastAuth = %v, want the store clock %v", st.LastAuth, t0)
	}
	// 0.35 + 0.25 + 0.30 + 0.10·0.5 (one location signal from 0)
	if got := s.Score(pmu); !near(got, 0.95) || LevelOf(got) != High {
		t.Errorf("Score() = %v (%s), want 0.95 (high)", got, LevelOf(got))
	}
	now = t0.Add(time.Hour) // twelve half-lives without a new authentication
	// 0.35/4096 + 0.25 + 0.30 + 0.05
	if got := s.Score(pmu); !near(got, 0.6+0.35/4096) || LevelOf(got) != Medium {
		t.Errorf("Score() after an hour = %v (%s), want 0.600085 (medium)", got, LevelOf(got))
	}
}

func TestStoreNow(t *testing.T) {
	now := t0
	s := fixedClock(&now)
	if got := s.Now(); !got.Equal(t0) {
		t.Errorf("Now() = %v, want %v", got, t0)
	}
}

func TestStoreDenialOfUnknownSubject(t *testing.T) {
	s := NewStore(nil)
	record(t, s, Signal{Subject: "spiffe://grid.example/edge/attacker", Kind: Denial})
	if got := s.Score("spiffe://grid.example/edge/attacker"); got != 0 {
		t.Errorf("Score() after a denial = %v, want 0", got)
	}
}

func TestStoreCompromise(t *testing.T) {
	s := NewStore(nil)
	record(t, s, Signal{Subject: "a", Kind: Authentication, Value: 1})
	record(t, s, Signal{Subject: "a", Kind: Compromise})
	if got := s.Score("a"); got != 0 {
		t.Errorf("Score() of a compromised subject = %v, want 0", got)
	}
}

func TestStoreRejects(t *testing.T) {
	s := NewStore(nil)
	for _, sig := range []Signal{
		{Kind: Authentication, Value: 1},
		{Subject: "a", Kind: "reset"},
		{Subject: "a"},
	} {
		if err := s.Record(sig); err == nil {
			t.Errorf("Record(%+v) = nil, want error", sig)
		}
	}
	if ids := s.Subjects(); len(ids) != 0 {
		t.Errorf("a rejected signal created subjects %v", ids)
	}
}

func TestStoreSubjectsSorted(t *testing.T) {
	s := NewStore(nil)
	for _, id := range []string{"c", "a", "b"} {
		record(t, s, Signal{Subject: id, Kind: Posture, Value: 1})
	}
	if got := s.Subjects(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("Subjects() = %v", got)
	}
}

// TestStoreConcurrentUse is for the race detector (make test runs with
// -race): writers, readers and a clock change at the same time.
func TestStoreConcurrentUse(t *testing.T) {
	s := NewStore(nil)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for i := range 200 {
				subject := fmt.Sprintf("spiffe://grid.example/edge/pmu/%d", i%10)
				if err := s.Record(Signal{Subject: subject, Kind: Authentication, Value: float64(w+1) / 4}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for i := range 200 {
				s.Score(fmt.Sprintf("spiffe://grid.example/edge/pmu/%d", i%10))
				s.Subjects()
			}
		})
	}
	wg.Go(func() { s.SetClock(time.Now) })
	wg.Wait()
	if got := len(s.Subjects()); got != 10 {
		t.Errorf("len(Subjects()) = %d, want 10", got)
	}
}
