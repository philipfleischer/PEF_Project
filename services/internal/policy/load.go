// Reading and writing policies as JSON, the format of deploy/policies/*.json
// and of the PDP's PUT /v1/policy.

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Load reads exactly one JSON policy from r and validates it. Unknown fields
// and data after the policy are errors, so a misspelt field such as
// "sujbects" is reported instead of silently dropped.
func Load(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("policy: unexpected data after the policy")
	}
	if err := Validate(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadFile reads and validates the JSON policy in the file at path.
func LoadFile(path string) (*Policy, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only, so a close error cannot lose data
	p, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Marshal returns p as JSON indented by two spaces with a trailing newline.
// It is the canonical form of the policy files, so the same policy always
// gives the same bytes and a diff shows only real changes.
func Marshal(p *Policy) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "<" and ">" readable in descriptions
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("policy: encode: %w", err)
	}
	return buf.Bytes(), nil
}
