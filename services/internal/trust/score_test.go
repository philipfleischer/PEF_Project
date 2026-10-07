// Test vectors for the trust score, computed by hand before the code existed.
// The C++ core in sim/core (M6) must produce the same numbers.

package trust

import (
	"math"
	"testing"
	"time"
)

// t0 is the reference time of every vector.
var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// near reports whether a and b are equal within 1e-9, enough for float64
// arithmetic and strict enough to catch any wrong term in the formula.
func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// verified is a subject that authenticated with full strength at t0 and is
// perfect in every other component.
func verified() State {
	return State{AuthStrength: 1, LastAuth: t0, Posture: 1, Anomaly: 0, Location: 1, LastUpdate: t0}
}

func TestNewEvaluatorDefaults(t *testing.T) {
	e := NewEvaluator()
	w := e.Weights
	if !near(w.Authentication+w.Posture+w.Behaviour+w.Location, 1) {
		t.Errorf("weights %+v do not sum to 1", w)
	}
	if e.AuthHalfLife != 5*time.Minute || e.DenialHalfLife != 10*time.Minute || e.DenialPenalty != 0.1 || e.Alpha != 0.5 {
		t.Errorf("NewEvaluator() = %+v", e)
	}
}

// TestScoreVectors checks the formula on fixed states. Each row shows the
// arithmetic, with weights 0.35 / 0.25 / 0.30 / 0.10.
func TestScoreVectors(t *testing.T) {
	tests := []struct {
		name  string
		state func() State
		now   time.Time
		want  float64
	}{
		// 0.35·1 + 0.25·1 + 0.30·(1−0) + 0.10·1
		{"verified, just authenticated", verified, t0, 1.0},
		// auth = 1·0.5¹ = 0.5 → 0.175 + 0.25 + 0.30 + 0.10
		{"one half-life later", verified, t0.Add(5 * time.Minute), 0.825},
		// auth = 1·0.5² = 0.25 → 0.0875 + 0.65
		{"two half-lives later", verified, t0.Add(10 * time.Minute), 0.7375},
		// auth = 1·0.5¹² → 0.35/4096 + 0.65
		{"one hour later", verified, t0.Add(time.Hour), 0.65 + 0.35/4096},
		// a clock behind LastAuth gives no extra credit: age counts as 0
		{"clock skew", verified, t0.Add(-time.Minute), 1.0},
		// bearer token: 0.35·0.5 + 0.65
		{"token, just authenticated", func() State { s := verified(); s.AuthStrength = 0.5; return s }, t0, 0.825},
		// 0.35·0.5·0.5 + 0.65: below 0.8, so a breaker needs a fresh, stronger login (step-up)
		{"token, one half-life later", func() State { s := verified(); s.AuthStrength = 0.5; return s }, t0.Add(5 * time.Minute), 0.7375},
		// 0.35 + 0.25 + 0.30·(1−0.5) + 0.10
		{"anomaly 0.5", func() State { s := verified(); s.Anomaly = 0.5; return s }, t0, 0.85},
		// 1.0 − 0.1·1·0.5⁰
		{"one denial just now", func() State { s := verified(); s.Denials, s.LastDenial = 1, t0; return s }, t0, 0.9},
		// 1.0 − 0.1·3
		{"three denials just now", func() State { s := verified(); s.Denials, s.LastDenial = 3, t0; return s }, t0, 0.7},
		// fresh login at t0+10m, denial at t0: 1.0 − 0.1·1·0.5¹
		{"denial ten minutes old", func() State {
			s := verified()
			s.LastAuth, s.Denials, s.LastDenial = t0.Add(10*time.Minute), 1, t0
			return s
		}, t0.Add(10 * time.Minute), 0.95},
		// 0.175 + 0 + 0 + 0 − 0.5 = −0.325, clamped
		{"clamped at 0", func() State {
			return State{AuthStrength: 0.5, LastAuth: t0, Anomaly: 1, Denials: 5, LastDenial: t0}
		}, t0, 0},
		{"compromised", func() State { s := verified(); s.Compromised = true; return s }, t0, 0},
		// perfect in everything but authentication: no proof, no trust
		{"never authenticated", func() State { s := verified(); s.AuthStrength, s.LastAuth = 0, time.Time{}; return s }, t0, 0},
		{"zero state", func() State { return State{} }, t0, 0},
	}
	e := NewEvaluator()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.Score(tc.state(), tc.now); !near(got, tc.want) {
				t.Errorf("Score() = %.12f, want %.12f", got, tc.want)
			}
		})
	}
}

func TestScoreNaNWeights(t *testing.T) {
	e := NewEvaluator()
	e.Weights.Posture = math.NaN()
	if got := e.Score(verified(), t0); got != 0 {
		t.Errorf("Score() with a NaN weight = %v, want 0", got)
	}
}

// TestApply checks how each kind of signal changes the state.
func TestApply(t *testing.T) {
	later := t0.Add(10 * time.Minute)
	tests := []struct {
		name    string
		start   State
		signals []Signal
		check   func(st State) bool
	}{
		{"authentication sets strength and time", State{}, []Signal{{Kind: Authentication, Value: 0.8, Time: t0}},
			func(st State) bool { return st.AuthStrength == 0.8 && st.LastAuth.Equal(t0) && st.LastUpdate.Equal(t0) }},
		{"authentication above 1 is clamped", State{}, []Signal{{Kind: Authentication, Value: 7, Time: t0}},
			func(st State) bool { return st.AuthStrength == 1 }},
		{"authentication with strength 0 is ignored", State{}, []Signal{{Kind: Authentication, Value: 0, Time: t0}},
			func(st State) bool { return st.LastAuth.IsZero() }},
		{"authentication with NaN is ignored", State{}, []Signal{{Kind: Authentication, Value: math.NaN(), Time: t0}},
			func(st State) bool { return st.LastAuth.IsZero() }},
		{"older authentication is ignored", State{}, []Signal{
			{Kind: Authentication, Value: 0.5, Time: later}, {Kind: Authentication, Value: 1, Time: t0}},
			func(st State) bool {
				return st.AuthStrength == 0.5 && st.LastAuth.Equal(later) && st.LastUpdate.Equal(later)
			}},
		{"posture NaN counts as 0", State{Posture: 1}, []Signal{{Kind: Posture, Value: math.NaN(), Time: t0}},
			func(st State) bool { return st.Posture == 0 }},
		// 0.5·1 + 0.5·0 = 0.5, then 0.5·1 + 0.5·0.5 = 0.75
		{"behaviour is smoothed", State{}, []Signal{{Kind: Behaviour, Value: 1, Time: t0}, {Kind: Behaviour, Value: 1, Time: t0}},
			func(st State) bool { return near(st.Anomaly, 0.75) }},
		// 0.5·0 + 0.5·1
		{"one unexpected location halves it", State{Location: 1}, []Signal{{Kind: Location, Value: 0, Time: t0}},
			func(st State) bool { return near(st.Location, 0.5) }},
		// 1·0.5¹ + 1
		{"denials decay from the last denial", State{}, []Signal{{Kind: Denial, Time: t0}, {Kind: Denial, Time: later}},
			func(st State) bool { return near(st.Denials, 1.5) && st.LastDenial.Equal(later) }},
		{"other signals leave the denial clock alone", State{}, []Signal{{Kind: Denial, Time: t0}, {Kind: Posture, Value: 1, Time: later}},
			func(st State) bool { return st.Denials == 1 && st.LastDenial.Equal(t0) && st.LastUpdate.Equal(later) }},
		{"compromise", State{}, []Signal{{Kind: Compromise, Time: t0}},
			func(st State) bool { return st.Compromised }},
		{"signal without time uses LastUpdate", State{LastUpdate: t0}, []Signal{{Kind: Authentication, Value: 1}},
			func(st State) bool { return st.LastAuth.Equal(t0) }},
		{"unknown kind changes nothing", State{Posture: 1, LastUpdate: t0}, []Signal{{Kind: "reset", Value: 1, Time: later}},
			func(st State) bool { return st == State{Posture: 1, LastUpdate: t0} }},
	}
	e := NewEvaluator()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.start
			for _, s := range tc.signals {
				st = e.Apply(st, s)
			}
			if !tc.check(st) {
				t.Errorf("state = %+v", st)
			}
		})
	}
}

// TestDenialDoesNotCreateTrust is the first flaw of the original algorithm:
// a subject that never authenticated reached 0.3 by being denied once.
func TestDenialDoesNotCreateTrust(t *testing.T) {
	e := NewEvaluator()
	st := e.Apply(State{}, Signal{Kind: Denial, Time: t0})
	for _, now := range []time.Time{t0, t0.Add(time.Hour)} {
		if got := e.Score(st, now); got != 0 {
			t.Errorf("Score(%v) = %v, want 0", now.Sub(t0), got)
		}
	}
}

// TestGoodSignalNeverLowersScore is the second flaw of the original: a posture
// signal after a denial reset the denial penalty to full strength.
func TestGoodSignalNeverLowersScore(t *testing.T) {
	e := NewEvaluator()
	st := e.Apply(verified(), Signal{Kind: Denial, Time: t0})
	later := t0.Add(10 * time.Minute)
	without := e.Score(st, later)
	with := e.Score(e.Apply(st, Signal{Kind: Posture, Value: 1, Time: later}), later)
	if with < without {
		t.Errorf("a good posture signal lowered the score from %v to %v", without, with)
	}
}
