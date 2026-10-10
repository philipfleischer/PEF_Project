package token

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// t0 is the reference time of the tests.
var t0 = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

// newSigner returns a signer with a fresh key and a verifier for "ztc-pep"
// that trusts it and whose clock stands at t0.
func newSigner(t *testing.T) (Signer, Verifier) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Signer{KeyID: "k1", Key: key},
		Verifier{Keys: map[string]ed25519.PublicKey{"k1": pub}, Audience: "ztc-pep", Now: func() time.Time { return t0 }}
}

// pmuClaims are valid at t0 for one minute.
func pmuClaims() Claims {
	return Claims{
		Issuer:    "ztc-ca",
		Subject:   "spiffe://grid.example/edge/pmu/1",
		Audience:  []string{"ztc-pep"},
		ExpiresAt: t0.Add(time.Minute).Unix(),
		NotBefore: t0.Unix(),
		IssuedAt:  t0.Unix(),
		ID:        "jti-1",
		Scope:     []string{"telemetry:write"},
	}
}

func TestSignVerify(t *testing.T) {
	s, v := newSigner(t)
	tok, err := s.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "spiffe://grid.example/edge/pmu/1" || got.ID != "jti-1" || !got.HasScope("telemetry:write") {
		t.Errorf("Verify returned %+v", got)
	}
}

func TestSignRequiresClaims(t *testing.T) {
	s, _ := newSigner(t)
	for name, change := range map[string]func(*Claims){
		"no subject":  func(c *Claims) { c.Subject = "" },
		"no audience": func(c *Claims) { c.Audience = nil },
		"no expiry":   func(c *Claims) { c.ExpiresAt = 0 },
		"no ID":       func(c *Claims) { c.ID = "" },
	} {
		c := pmuClaims()
		change(&c)
		if _, err := s.Sign(c); !errors.Is(err, ErrMissingClaim) {
			t.Errorf("%s: Sign error %v, want ErrMissingClaim", name, err)
		}
	}
	if _, err := (Signer{KeyID: "k1"}).Sign(pmuClaims()); err == nil {
		t.Error("Sign without a key succeeded")
	}
}

func TestHasScope(t *testing.T) {
	c := Claims{Scope: []string{"telemetry:*", "breaker:read"}}
	tests := []struct {
		scope string
		want  bool
	}{
		{"telemetry:read", true},
		{"telemetry:write", true},
		{"breaker:read", true},
		{"breaker:operate", false},
		{"telemetryx:read", false}, // the wildcard ends at the colon
		{"", false},
	}
	for _, tc := range tests {
		if got := c.HasScope(tc.scope); got != tc.want {
			t.Errorf("HasScope(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
	if (Claims{Scope: []string{"*"}}).HasScope("breaker:operate") {
		t.Error(`a bare "*" must not grant everything`)
	}
}

func TestKeyThumbprint(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	// SHA-256 is 32 bytes, which is 43 characters of base64url without padding.
	if got := KeyThumbprint(pub); len(got) != 43 || got != KeyThumbprint(pub) {
		t.Errorf("KeyThumbprint = %q", got)
	}
	other := make(ed25519.PublicKey, ed25519.PublicKeySize)
	other[0] = 1
	if KeyThumbprint(pub) == KeyThumbprint(other) {
		t.Error("two keys have the same thumbprint")
	}
}
