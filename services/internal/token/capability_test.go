package token

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// rootKey is a fixed 32-byte test key.
var rootKey = []byte("root-key-of-the-pdp-0123456789ab")

// offload is the capability an edge device hands a fog node for task t-7:
// execute, under substation-1/, task t-7, on fog or edge, before t0 + 30 s.
func offload(t *testing.T) Capability {
	t.Helper()
	c, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	return c.Attenuate("action = execute").
		Attenuate("resource ^= substation-1/").
		Attenuate("task = t-7").
		Attenuate("layer <= fog").
		Attenuate("expires < " + strconv.FormatInt(t0.Add(30*time.Second).Unix(), 10))
}

// fogRequest satisfies every caveat of offload.
func fogRequest() Request {
	return Request{Action: "execute", Resource: "substation-1/task/t-7", Task: "t-7", Layer: model.LayerFog, Now: t0}
}

func TestCapabilityVerify(t *testing.T) {
	c := offload(t)
	if err := c.Verify(rootKey, StandardChecker(fogRequest())); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	tests := []struct {
		name   string
		change func(*Request)
	}{
		{"other action", func(r *Request) { r.Action = "write" }},
		{"other substation", func(r *Request) { r.Resource = "substation-2/task/t-7" }},
		{"other task", func(r *Request) { r.Task = "t-8" }},
		{"cloud layer", func(r *Request) { r.Layer = model.LayerCloud }},
		{"unknown layer", func(r *Request) { r.Layer = model.LayerUnknown }},
		{"at expiry", func(r *Request) { r.Now = t0.Add(30 * time.Second) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := fogRequest()
			tc.change(&r)
			if err := c.Verify(rootKey, StandardChecker(r)); !errors.Is(err, ErrCaveat) {
				t.Errorf("Verify error %v, want ErrCaveat", err)
			}
		})
	}
	edge := fogRequest()
	edge.Layer = model.LayerEdge
	if err := c.Verify(rootKey, StandardChecker(edge)); err != nil {
		t.Errorf("layer <= fog must hold on the edge: %v", err)
	}
}

// TestCapabilityCannotBeWidened is the acceptance criterion of issue #15: a
// holder who changes the chain in any way breaks the signature.
func TestCapabilityCannotBeWidened(t *testing.T) {
	c := offload(t)
	ok := StandardChecker(fogRequest())
	tests := []struct {
		name   string
		change func(*Capability)
	}{
		{"last caveat removed", func(c *Capability) { c.Caveats = c.Caveats[:len(c.Caveats)-1] }},
		{"first caveat removed", func(c *Capability) { c.Caveats = c.Caveats[1:] }},
		{"caveat changed", func(c *Capability) { c.Caveats[0] = "action = operate" }},
		{"caveats reordered", func(c *Capability) { c.Caveats[0], c.Caveats[1] = c.Caveats[1], c.Caveats[0] }},
		{"all caveats removed", func(c *Capability) { c.Caveats = nil }},
		{"other grant", func(c *Capability) { c.ID = "grant-1" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := c
			w.Caveats = append([]string(nil), c.Caveats...)
			tc.change(&w)
			if err := w.Verify(rootKey, ok); !errors.Is(err, ErrCapSignature) {
				t.Errorf("Verify error %v, want ErrCapSignature", err)
			}
		})
	}
	if err := c.Verify([]byte("another-root-key-0123456789abcde"), ok); !errors.Is(err, ErrCapSignature) {
		t.Errorf("wrong root key: %v", err)
	}
}

func TestAttenuateCopies(t *testing.T) {
	c, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	// Three caveats: a slice grown by append now has room for a fourth, so a
	// shared backing array would let b overwrite a's last caveat.
	parent := c.Attenuate("action = execute").Attenuate("resource ^= substation-1/").Attenuate("layer <= fog")
	a := parent.Attenuate("task = t-1")
	b := parent.Attenuate("task = t-2")
	if len(parent.Caveats) != 3 || a.Caveats[3] != "task = t-1" || b.Caveats[3] != "task = t-2" {
		t.Errorf("Attenuate shares caveats: parent %q, a %q, b %q", parent.Caveats, a.Caveats, b.Caveats)
	}
}

func TestCapabilityFailsClosed(t *testing.T) {
	c, err := NewCapability(rootKey, "grant-42", "ztc-fog")
	if err != nil {
		t.Fatal(err)
	}
	ok := StandardChecker(fogRequest())
	if err := c.Verify(rootKey, nil); err != nil {
		t.Errorf("no caveats, no checker: %v", err)
	}
	tests := []struct {
		name  string
		cap   Capability
		check CaveatChecker
	}{
		{"caveat without checker", c.Attenuate("action = execute"), nil},
		{"unknown caveat", c.Attenuate("colour = blue"), ok},
		{"no spaces", c.Attenuate("action=execute"), ok},
		{"unknown operator", c.Attenuate("action != write"), ok},
		{"expiry not a number", c.Attenuate("expires < soon"), ok},
		{"layer not a layer", c.Attenuate("layer <= moon"), ok},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cap.Verify(rootKey, tc.check); !errors.Is(err, ErrCaveat) {
				t.Errorf("Verify error %v, want ErrCaveat", err)
			}
		})
	}
	if _, err := NewCapability([]byte("short"), "grant-42", "ztc-fog"); !errors.Is(err, ErrRootKey) {
		t.Errorf("NewCapability with a short key: %v", err)
	}
	if err := c.Verify([]byte("short"), ok); !errors.Is(err, ErrRootKey) {
		t.Errorf("Verify with a short key: %v", err)
	}
	long := c
	for range MaxCaveats + 1 {
		long = long.Attenuate("action = execute")
	}
	if err := long.Verify(rootKey, ok); !errors.Is(err, ErrMalformed) {
		t.Errorf("%d caveats: %v", len(long.Caveats), err)
	}
}

func TestCapabilityEncoding(t *testing.T) {
	c := offload(t)
	got, err := DecodeCapability(c.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(rootKey, StandardChecker(fogRequest())); err != nil {
		t.Errorf("decoded capability rejected: %v", err)
	}
	enc := func(s string) string { return b64.EncodeToString([]byte(s)) }
	for name, s := range map[string]string{
		"not base64url": "!!!",
		"not JSON":      enc("grant-42"),
		"no ID":         enc(`{"sig":"` + strings.Repeat("A", 43) + `="}`),
		"short sig":     enc(`{"id":"grant-42","sig":"AAAA"}`),
		"too long":      strings.Repeat("A", MaxTokenSize+1),
	} {
		if _, err := DecodeCapability(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: error %v, want ErrMalformed", name, err)
		}
	}
}
