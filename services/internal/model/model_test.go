package model

import "testing"

func TestParseLayer(t *testing.T) {
	tests := []struct {
		in      string
		want    Layer
		wantErr bool
	}{
		{"edge", LayerEdge, false},
		{"FOG", LayerFog, false},
		{"  cloud ", LayerCloud, false},
		{"datacenter", LayerUnknown, true},
		{"", LayerUnknown, true},
	}
	for _, tc := range tests {
		got, err := ParseLayer(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseLayer(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("ParseLayer(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLayerStringRoundTrip(t *testing.T) {
	for _, l := range []Layer{LayerEdge, LayerFog, LayerCloud} {
		got, err := ParseLayer(l.String())
		if err != nil || got != l {
			t.Errorf("ParseLayer(%v.String()) = %v, %v; want %v, nil", l, got, err, l)
		}
	}
	if s := LayerUnknown.String(); s != "unknown" {
		t.Errorf("LayerUnknown.String() = %q, want %q", s, "unknown")
	}
}

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b Layer
		want int
	}{
		{LayerEdge, LayerEdge, 0},
		{LayerEdge, LayerFog, 1},
		{LayerFog, LayerEdge, 1},
		{LayerCloud, LayerEdge, 2},
	}
	for _, tc := range tests {
		if got := Distance(tc.a, tc.b); got != tc.want {
			t.Errorf("Distance(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TEST

func TestDecisionAllowedFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		d    Decision
		want bool
	}{
		{"explicit allow", Decision{Effect: Allow}, true},
		{"explicit deny", Decision{Effect: Deny}, false},
		{"zero value", Decision{}, false},
		{"unknown effect", Decision{Effect: "maybe"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.d.Allowed(); got != tc.want {
				t.Errorf("Allowed() = %v, want %v", got, tc.want)
			}
		})
	}
}
