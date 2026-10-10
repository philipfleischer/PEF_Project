// Capabilities: macaroon-style bearer credentials that any holder can narrow
// but nobody can widen.

package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// MinRootKeySize is the shortest root key accepted, in bytes. HMAC-SHA256 is
// only as strong as its key; 32 random bytes match the size of the hash.
const MinRootKeySize = 32

// MaxCaveats is the most caveats a capability may carry. Verify computes one
// HMAC per caveat, so without a limit a long chain costs the verifier CPU.
const MaxCaveats = 32

// Capability is a macaroon-style credential (Birgisson et al., NDSS 2014):
//
//	sig_0 = HMAC(rootKey, ID)
//	sig_i = HMAC(sig_{i-1}, caveat_i)
//
// A holder can add a caveat by computing the next HMAC from Sig, but cannot
// remove one, because that would mean finding sig_{i-1} from sig_i. Only the
// issuer, who knows the root key, can verify. In ZTC the PDP gives a
// capability to an edge device, and when the device offloads a task to a fog
// node it hands over a narrower copy: "only task t-7", "for 30 seconds",
// "only on the fog layer".
type Capability struct {
	Location string   `json:"loc"` // which service verifies it; a hint, not covered by Sig
	ID       string   `json:"id"`  // names the grant and the root key
	Caveats  []string `json:"cav"` // restrictions, e.g. "action = read"
	Sig      []byte   `json:"sig"` // the last HMAC-SHA256 of the chain
}

// Errors returned by the capability functions.
var (
	ErrRootKey      = errors.New("capability: root key too short")
	ErrCapSignature = errors.New("capability: bad signature")
	ErrCaveat       = errors.New("capability: caveat not satisfied")
)

func mac(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// NewCapability mints a capability without caveats for the grant id. The
// root key must be at least MinRootKeySize bytes.
func NewCapability(rootKey []byte, id, location string) (Capability, error) {
	if len(rootKey) < MinRootKeySize {
		return Capability{}, ErrRootKey
	}
	return Capability{Location: location, ID: id, Sig: mac(rootKey, id)}, nil
}

// Attenuate returns a copy of c with one more caveat. It does not change c,
// so one capability can be narrowed in different ways for different holders.
func (c Capability) Attenuate(caveat string) Capability {
	return Capability{
		Location: c.Location,
		ID:       c.ID,
		Caveats:  append(slices.Clone(c.Caveats), caveat),
		Sig:      mac(c.Sig, caveat),
	}
}

// CaveatChecker decides whether one caveat holds for the current request. It
// must return an error wrapping ErrCaveat for a caveat it does not understand.
type CaveatChecker func(caveat string) error

// Verify recomputes the HMAC chain from rootKey, compares it with c.Sig in
// constant time, and then asks check about every caveat. All caveats must
// hold. A nil check accepts only a capability without caveats.
func (c Capability) Verify(rootKey []byte, check CaveatChecker) error {
	if len(rootKey) < MinRootKeySize {
		return ErrRootKey
	}
	if len(c.Caveats) > MaxCaveats {
		return ErrMalformed
	}
	sig := mac(rootKey, c.ID)
	for _, cav := range c.Caveats {
		sig = mac(sig, cav)
	}
	if !hmac.Equal(sig, c.Sig) {
		return ErrCapSignature
	}
	for _, cav := range c.Caveats {
		if check == nil {
			return fmt.Errorf("%w: no checker for %q", ErrCaveat, cav)
		}
		if err := check(cav); err != nil {
			return err
		}
	}
	return nil
}

// Encode returns c as base64url JSON, for an HTTP header.
func (c Capability) Encode() string {
	b, _ := json.Marshal(c) // cannot fail: c holds only strings and bytes
	return b64.EncodeToString(b)
}

// DecodeCapability is the inverse of Encode. It rejects input longer than
// MaxTokenSize, more than MaxCaveats caveats, an empty ID and a signature that
// is not one HMAC-SHA256 long.
func DecodeCapability(s string) (Capability, error) {
	if len(s) > MaxTokenSize {
		return Capability{}, ErrMalformed
	}
	var c Capability
	if err := decodePart(s, &c); err != nil {
		return Capability{}, err
	}
	if c.ID == "" || len(c.Sig) != sha256.Size || len(c.Caveats) > MaxCaveats {
		return Capability{}, ErrMalformed
	}
	return c, nil
}

// Request is what StandardChecker compares the caveats with.
type Request struct {
	Action   string      // e.g. "execute"
	Resource string      // e.g. "substation-1/task/t-7"
	Task     string      // ID of the offloaded task, if any
	Layer    model.Layer // the layer of the node that verifies
	Now      time.Time
}

// StandardChecker returns a CaveatChecker for the caveats used in ZTC, each
// of the form "<key> <op> <value>":
//
//	action = <a>          the request's action is a
//	resource ^= <prefix>  the resource ID starts with prefix
//	task = <id>           the request is for this offloaded task
//	layer <= <layer>      the verifying node is on this layer or nearer the edge
//	expires < <unix>      the time is before this Unix second
//
// Anything else, including an unknown key, is not satisfied: fail closed.
func StandardChecker(r Request) CaveatChecker {
	return func(caveat string) error {
		key, op, val, ok := splitCaveat(caveat)
		if !ok {
			return fmt.Errorf("%w: malformed %q", ErrCaveat, caveat)
		}
		var holds bool
		switch key + " " + op {
		case "action =":
			holds = r.Action == val
		case "resource ^=":
			holds = strings.HasPrefix(r.Resource, val)
		case "task =":
			holds = r.Task == val
		case "layer <=":
			limit, err := model.ParseLayer(val)
			holds = err == nil && r.Layer != model.LayerUnknown && r.Layer <= limit
		case "expires <":
			exp, err := strconv.ParseInt(val, 10, 64)
			holds = err == nil && r.Now.Before(time.Unix(exp, 0))
		default:
			return fmt.Errorf("%w: unknown caveat %q", ErrCaveat, caveat)
		}
		if !holds {
			return fmt.Errorf("%w: %q", ErrCaveat, caveat)
		}
		return nil
	}
}

// splitCaveat splits "key op value" at the first two spaces.
func splitCaveat(caveat string) (key, op, val string, ok bool) {
	key, rest, ok1 := strings.Cut(caveat, " ")
	op, val, ok2 := strings.Cut(rest, " ")
	return key, op, val, ok1 && ok2
}
