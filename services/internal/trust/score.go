// The trust score: how signals change a subject's State, and how a State
// becomes a number in [0, 1] at a given time.

package trust

import "time"

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
	// TODO(ztc): set the default parameters.
	return &Evaluator{}
}

// Apply returns st updated with signal s; st itself is not changed. Values
// are clamped to [0, 1] and NaN counts as 0. A signal without a time is
// applied at st.LastUpdate. An authentication with strength 0, or older than
// the last one, is ignored, and an unknown kind changes nothing.
func (e *Evaluator) Apply(st State, s Signal) State {
	// TODO(ztc): update the state for each kind of signal.
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
	// TODO(ztc): implement the formula.
	return 0
}
