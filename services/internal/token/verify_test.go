// Negative tests for Verify: every way an attacker or a broken issuer can get
// a token wrong, each rejected with its own error.

package token

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// forge signs any header and payload JSON with key, so a test can build a
// token with a valid signature that Sign would never produce.
func forge(key ed25519.PrivateKey, header, payload string) string {
	in := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in)))
}

func TestVerifyRejects(t *testing.T) {
	s, v := newSigner(t)
	good, err := s.Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")

	// An attacker with their own key, using our kid.
	_, evilKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	evil, err := (Signer{KeyID: "k1", Key: evilKey}).Sign(pmuClaims())
	if err != nil {
		t.Fatal(err)
	}
	admin := pmuClaims()
	admin.Subject = "spiffe://grid.example/cloud/admin/mallory"
	adminTok, err := (Signer{KeyID: "k1", Key: evilKey}).Sign(admin)
	if err != nil {
		t.Fatal(err)
	}

	payload := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":["ztc-pep"],"exp":1791806460,"jti":"jti-1"}`
	emptyAud := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":[""],"exp":1791806460,"jti":"jti-1"}`
	noExp := `{"sub":"spiffe://grid.example/edge/pmu/1","aud":["ztc-pep"],"jti":"jti-1"}`
	at := func(d time.Duration) func(*Verifier) {
		return func(v *Verifier) { v.Now = func() time.Time { return t0.Add(d) } }
	}

	tests := []struct {
		name   string
		tok    string
		change func(*Verifier) // nil keeps the verifier from newSigner
		want   error
	}{
		// The header: the token must not choose how it is checked.
		{"alg none without signature", b64.EncodeToString([]byte(`{"alg":"none","typ":"ZTC","kid":"k1"}`)) + "." + parts[1] + ".", nil, ErrAlgorithm},
		{"alg none with valid signature", forge(s.Key, `{"alg":"none","typ":"ZTC","kid":"k1"}`, payload), nil, ErrAlgorithm},
		{"alg HS256", forge(s.Key, `{"alg":"HS256","typ":"ZTC","kid":"k1"}`, payload), nil, ErrAlgorithm},
		{"typ JWT", forge(s.Key, `{"alg":"EdDSA","typ":"JWT","kid":"k1"}`, payload), nil, ErrAlgorithm},
		{"unknown kid", forge(s.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k2"}`, payload), nil, ErrUnknownKey},
		{"public key of wrong length", good, func(v *Verifier) { v.Keys = map[string]ed25519.PublicKey{"k1": make([]byte, 5)} }, ErrUnknownKey},

		// The signature: nobody without the private key can make or change a token.
		{"signed with another key", evil, nil, ErrSignature},
		{"payload swapped", parts[0] + "." + strings.Split(adminTok, ".")[1] + "." + parts[2], nil, ErrSignature},
		{"signature truncated", good[:len(good)-4], nil, ErrSignature},
		{"signature removed", parts[0] + "." + parts[1] + ".", nil, ErrSignature},

		// The format.
		{"empty", "", nil, ErrMalformed},
		{"two parts", parts[0] + "." + parts[1], nil, ErrMalformed},
		{"four parts", good + ".x", nil, ErrMalformed},
		{"header not base64url", "!!!." + parts[1] + "." + parts[2], nil, ErrMalformed},
		{"header not JSON", b64.EncodeToString([]byte("EdDSA")) + "." + parts[1] + "." + parts[2], nil, ErrMalformed},
		{"payload not JSON", forge(s.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, "sub=x"), nil, ErrMalformed},
		{"too long", good + strings.Repeat("A", MaxTokenSize), nil, ErrMalformed},

		// The claims and the time window.
		{"no expiry", forge(s.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, noExp), nil, ErrMissingClaim},
		{"at expiry", good, at(time.Minute), ErrExpired},
		{"long after expiry", good, at(time.Hour), ErrExpired},
		{"before not-before", good, at(-time.Second), ErrNotYetValid},
		{"wrong audience", good, func(v *Verifier) { v.Audience = "ztc-historian" }, ErrAudience},
		{"verifier without audience", good, func(v *Verifier) { v.Audience = "" }, ErrAudience},
		{"verifier without audience, token for empty audience", forge(s.Key, `{"alg":"EdDSA","typ":"ZTC","kid":"k1"}`, emptyAud), func(v *Verifier) { v.Audience = "" }, ErrAudience},

		// What must still pass.
		{"one second before expiry", good, at(time.Minute - time.Second), nil},
		{"after expiry within leeway", good, func(v *Verifier) { at(time.Minute)(v); v.Leeway = 5 * time.Second }, nil},
		{"before not-before within leeway", good, func(v *Verifier) { at(-time.Second)(v); v.Leeway = 5 * time.Second }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ver := v
			if tc.change != nil {
				tc.change(&ver)
			}
			got, err := ver.Verify(tc.tok)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify error %v, want %v", err, tc.want)
			}
			if err != nil && got.Subject != "" {
				t.Errorf("Verify returned claims %+v together with an error", got)
			}
		})
	}
}
