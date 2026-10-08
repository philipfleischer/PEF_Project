// The trust score: how signals change a subject's State, and how a State
// becomes a number in [0, 1] at a given time.

package trust

import (
	"math"
	"time"
)

// Weights are the shares of the four components of the score. They sum to 1,
// so a subject that is perfect in every component scores 1.
type Weights struct {
	Authentication float64 `json:"authentication"`
	Posture        float64 `json:"posture"`
	Behaviour      float64 `json:"behaviour"`
	Location       float64 `json:"location"`
}

// DefaultWeights favour the signals that change within seconds
// (authentication and behaviour) over posture, which changes slowly, and
// location, which is weak evidence where devices never move.
var DefaultWeights = Weights{Authentication: 0.35, Posture: 0.25, Behaviour: 0.30, Location: 0.10}

// Evaluator holds the parameters of the trust algorithm. RQ4 varies them.
type Evaluator struct {
	Weights Weights
	// AuthHalfLife is how fast authentication fades: after one half-life
	// without a new authentication it counts half.
	AuthHalfLife time.Duration
	// DenialPenalty is subtracted from the score per recent denial.
	DenialPenalty float64
	// DenialHalfLife is how fast the denial penalty fades.
	DenialHalfLife time.Duration
	// Alpha is the smoothing factor for behaviour and location (0..1): the
	// weight of the newest signal against the history.
	Alpha float64
}

// NewEvaluator returns an evaluator with DefaultWeights, a 5 min
// authentication half-life, a 0.1 penalty per denial with a 10 min half-life,
// and Alpha 0.5.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		Weights:        DefaultWeights,
		AuthHalfLife:   5 * time.Minute,
		DenialPenalty:  0.1,
		DenialHalfLife: 10 * time.Minute,
		Alpha:          0.5,
	}
}

// Apply returns st updated with signal s; st itself is not changed. Values
// are clamped to [0, 1] and NaN counts as 0. A signal without a time is
// applied at st.LastUpdate. An authentication with strength 0, or older than
// the last one, is ignored, and an unknown kind changes nothing.
func (e *Evaluator) Apply(st State, s Signal) State {
	t := s.Time
	if t.IsZero() {
		t = st.LastUpdate
	}
	v := clamp01(s.Value)
	switch s.Kind {
	case Authentication:
		if v == 0 || t.IsZero() || t.Before(st.LastAuth) {
			return st // no proof, or older than the proof we have
		}
		st.AuthStrength, st.LastAuth = v, t
	case Posture:
		st.Posture = v
	case Behaviour:
		st.Anomaly = e.Alpha*v + (1-e.Alpha)*st.Anomaly
	case Location:
		st.Location = e.Alpha*v + (1-e.Alpha)*st.Location
	case Denial:
		// Decay the old count to t, then add this denial.
		st.Denials = st.Denials*halfLife(t.Sub(st.LastDenial), e.DenialHalfLife) + 1
		if t.After(st.LastDenial) {
			st.LastDenial = t
		}
	case Compromise:
		st.Compromised = true
	default:
		return st
	}
	if t.After(st.LastUpdate) {
		st.LastUpdate = t
	}
	return st
}

// Score returns the trust score of st at time now, in [0, 1]:
//
//	auth  = AuthStrength · 0.5^((now − LastAuth) / AuthHalfLife)
//	score = wA·auth + wP·Posture + wB·(1 − Anomaly) + wL·Location
//	        − DenialPenalty · Denials · 0.5^((now − LastDenial) / DenialHalfLife)
//
// A compromised subject, and a subject that has never authenticated, scores 0.
func (e *Evaluator) Score(st State, now time.Time) float64 {
	if st.Compromised || st.LastAuth.IsZero() {
		return 0
	}
	w := e.Weights
	auth := st.AuthStrength * halfLife(now.Sub(st.LastAuth), e.AuthHalfLife)
	score := w.Authentication*auth + w.Posture*st.Posture + w.Behaviour*(1-st.Anomaly) + w.Location*st.Location
	score -= e.DenialPenalty * st.Denials * halfLife(now.Sub(st.LastDenial), e.DenialHalfLife)
	return clamp01(score)
}

// halfLife returns 0.5^(age/hl): 1 for a fresh event, 0.5 after one
// half-life. A negative age (clock skew) counts as 0, and a half-life of 0 or
// less makes everything older than now worthless.
func halfLife(age, hl time.Duration) float64 {
	if age <= 0 {
		return 1
	}
	if hl <= 0 {
		return 0
	}
	return math.Pow(0.5, float64(age)/float64(hl))
}

// clamp01 limits x to [0, 1] and turns NaN into 0, the least trusted value.
func clamp01(x float64) float64 {
	switch {
	case math.IsNaN(x) || x < 0:
		return 0
	case x > 1:
		return 1
	}
	return x
}
