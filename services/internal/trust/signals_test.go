// Tests for signal kinds and trust levels.

package trust

import (
	"math"
	"testing"
)

func TestKindValid(t *testing.T) {
	for _, k := range []Kind{Authentication, Posture, Behaviour, Location, Denial, Compromise} {
		if !k.Valid() {
			t.Errorf("%q.Valid() = false, want true", k)
		}
	}
	for _, k := range []Kind{"", "Authentication", "auth", "reset"} {
		if k.Valid() {
			t.Errorf("%q.Valid() = true, want false", k)
		}
	}
}

func TestLevelOf(t *testing.T) {
	tests := []struct {
		score float64
		want  Level
	}{
		{1, High},
		{0.8, High},
		{0.79, Medium},
		{0.5, Medium},
		{0.49, Low},
		{0.3, Low},
		{0.29, Untrusted},
		{0, Untrusted},
		{-1, Untrusted},
		{math.NaN(), Untrusted},
	}
	for _, tc := range tests {
		if got := LevelOf(tc.score); got != tc.want {
			t.Errorf("LevelOf(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}
