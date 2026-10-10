// Package token implements the credentials of research question RQ2:
//
//   - signed tokens (signed.go): JWT-like bearer tokens signed with Ed25519.
//     A verifier needs only the issuer's public key, so a fog node can check a
//     token while the link to the cloud is down. The price is that a token is
//     valid until it expires unless the verifier keeps a revocation list.
//   - capabilities (capability.go): macaroon-style HMAC chains. The holder
//     can narrow one without asking the issuer, which suits offloading:
//     edge -> fog -> cloud, each hop with fewer rights.
//   - certificates come with mutual TLS in M5.
//
// Industry equivalents: JWT (RFC 7519) with go-jose or golang-jwt, Google's
// macaroons, Biscuit tokens.
package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// MaxTokenSize is the longest token Verify accepts, in bytes. Tokens travel in
// HTTP headers; a longer one is an attack on the verifier's memory and CPU.
const MaxTokenSize = 4096

// Claims is the payload of a signed token. The names follow RFC 7519.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`             // SPIFFE ID of the holder
	Audience  []string `json:"aud"`             // services that may accept the token
	ExpiresAt int64    `json:"exp"`             // Unix seconds
	NotBefore int64    `json:"nbf,omitempty"`   // Unix seconds; 0 means no lower bound
	IssuedAt  int64    `json:"iat,omitempty"`   // Unix seconds
	ID        string   `json:"jti"`             // unique ID, used for revocation
	Scope     []string `json:"scope,omitempty"` // e.g. "telemetry:read", "breaker:*"
	// Confirmation binds the token to the holder's key (RFC 7800): the
	// KeyThumbprint of its public key. Verify does not check it; a PEP that
	// asks the client to prove it holds the key does.
	Confirmation string `json:"cnf,omitempty"`
}

// Errors returned by Sign and Verify. Every way a token can fail has its own
// error, so tests and the audit log can tell why a token was rejected.
var (
	ErrMalformed    = errors.New("token: malformed")
	ErrAlgorithm    = errors.New("token: algorithm or type not accepted")
	ErrUnknownKey   = errors.New("token: unknown key id")
	ErrSignature    = errors.New("token: bad signature")
	ErrMissingClaim = errors.New("token: missing required claim")
	ErrExpired      = errors.New("token: expired")
	ErrNotYetValid  = errors.New("token: not yet valid")
	ErrAudience     = errors.New("token: audience mismatch")
)

// The only header values this package writes and accepts.
const (
	algorithm = "EdDSA"
	tokenType = "ZTC"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// b64 is base64url without padding, the encoding of JWT (RFC 7515).
var b64 = base64.RawURLEncoding

// Signer creates signed tokens with one Ed25519 key.
type Signer struct {
	KeyID string             // written as "kid", so verifiers can pick the key during rotation
	Key   ed25519.PrivateKey // the signing key
}

// Sign returns c as header.payload.signature, each part base64url without
// padding, with the header {"alg":"EdDSA","typ":"ZTC","kid":KeyID}. It refuses
// claims a verifier would reject for missing a required claim.
func (s Signer) Sign(c Claims) (string, error) {
	if len(s.Key) != ed25519.PrivateKeySize {
		return "", errors.New("token: signer has no Ed25519 key")
	}
	if err := c.checkRequired(); err != nil {
		return "", err
	}
	h, err := json.Marshal(header{Alg: algorithm, Typ: tokenType, Kid: s.KeyID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(s.Key, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// Verifier checks signed tokens for one service.
type Verifier struct {
	Keys     map[string]ed25519.PublicKey // kid -> public key of the issuer
	Audience string                       // this service; must be in the token's aud
	Leeway   time.Duration                // allowed clock difference, fog nodes drift
	Now      func() time.Time             // nil means time.Now
}

// Verify checks the format, algorithm, signature, required claims, time
// window and audience of tok, in that order, and returns its claims. On any
// failure it returns empty claims and one of the errors above, so a caller
// cannot use the claims of a rejected token by mistake.
//
// A verifier without an Audience rejects every token: a configuration
// mistake must not turn into "any audience will do".
func (v Verifier) Verify(tok string) (Claims, error) {
	if len(tok) > MaxTokenSize {
		return Claims{}, ErrMalformed
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformed
	}
	var h header
	if err := decodePart(parts[0], &h); err != nil {
		return Claims{}, err
	}
	// The algorithm is fixed by the verifier, never chosen by the token.
	if h.Alg != algorithm || h.Typ != tokenType {
		return Claims{}, ErrAlgorithm
	}
	key, ok := v.Keys[h.Kid]
	if !ok || len(key) != ed25519.PublicKeySize {
		return Claims{}, ErrUnknownKey
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrSignature
	}
	var c Claims
	if err := decodePart(parts[1], &c); err != nil {
		return Claims{}, err
	}
	if err := c.checkRequired(); err != nil {
		return Claims{}, err
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now()
	if !t.Before(time.Unix(c.ExpiresAt, 0).Add(v.Leeway)) {
		return Claims{}, ErrExpired
	}
	if c.NotBefore != 0 && t.Before(time.Unix(c.NotBefore, 0).Add(-v.Leeway)) {
		return Claims{}, ErrNotYetValid
	}
	if v.Audience == "" || !slices.Contains(c.Audience, v.Audience) {
		return Claims{}, ErrAudience
	}
	return c, nil
}

// decodePart decodes one base64url JSON part of a token into dst.
func decodePart(part string, dst any) error {
	b, err := b64.DecodeString(part)
	if err != nil {
		return ErrMalformed
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return ErrMalformed
	}
	return nil
}

// checkRequired returns ErrMissingClaim unless c has a subject, an audience,
// an expiry and an ID. Without an expiry a token is valid forever, and without
// an ID it cannot be revoked.
func (c Claims) checkRequired() error {
	if c.Subject == "" || len(c.Audience) == 0 || c.ExpiresAt == 0 || c.ID == "" {
		return ErrMissingClaim
	}
	return nil
}

// HasScope reports whether c grants scope s, for example "telemetry:read".
// A granted scope "telemetry:*" covers every scope that starts with
// "telemetry:".
func (c Claims) HasScope(s string) bool {
	for _, g := range c.Scope {
		if g == s {
			return true
		}
		if prefix, ok := strings.CutSuffix(g, "*"); ok && strings.HasSuffix(prefix, ":") && strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// KeyThumbprint returns the value of Claims.Confirmation for a public key:
// base64url of its SHA-256 hash.
func KeyThumbprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:])
}
