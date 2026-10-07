// Attribute names that policy conditions can use: which names exist, how each
// one is read from an access request, and the glob matching used by patterns.

package policy

import (
	"strconv"
	"strings"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
)

// plainAttributes are the names that map to one fixed field of a request.
var plainAttributes = map[string]bool{
	"subject.id": true, "subject.layer": true, "subject.class": true, "subject.owner": true,
	"subject.zone": true, "subject.role": true, "subject.authMethod": true,
	"resource.id": true, "resource.type": true, "resource.zone": true, "resource.layer": true,
	"resource.sensitivity": true, "action": true,
	"context.trustScore": true, "context.sourceZone": true, "context.sourceLayer": true,
	"context.emergency": true, "context.hour": true,
}

// mapPrefixes name the free-form attribute maps: "subject.attr.site" reads the
// key "site" from Subject.Attributes.
var mapPrefixes = []string{"subject.attr.", "resource.attr.", "context.attr."}

// KnownAttribute reports whether name is an attribute that Resolve can read:
// one of the fixed names, or a map prefix followed by a non-empty key.
func KnownAttribute(name string) bool {
	if plainAttributes[name] {
		return true
	}
	for _, prefix := range mapPrefixes {
		if key, ok := strings.CutPrefix(name, prefix); ok && key != "" {
			return true
		}
	}
	return false
}

// Resolve returns the value of the attribute name in req as a string, and
// whether the attribute exists. Numbers are formatted with strconv so the
// numeric operators can parse them back, and subject.role is the roles joined
// by commas. A missing map key or an unset time reports false, so a condition
// on it can never match (fail closed).
func Resolve(name string, req model.AccessRequest) (string, bool) {
	switch name {
	case "subject.id":
		return req.Subject.ID, true
	case "subject.layer":
		return req.Subject.Layer.String(), true
	case "subject.class":
		return string(req.Subject.Class), true
	case "subject.owner":
		return req.Subject.Owner, true
	case "subject.zone":
		return req.Subject.Zone, true
	case "subject.role":
		return strings.Join(req.Subject.Roles, ","), true
	case "subject.authMethod":
		return req.Subject.AuthMethod, true
	case "resource.id":
		return req.Resource.ID, true
	case "resource.type":
		return req.Resource.Type, true
	case "resource.zone":
		return req.Resource.Zone, true
	case "resource.layer":
		return req.Resource.Layer.String(), true
	case "resource.sensitivity":
		return strconv.Itoa(req.Resource.Sensitivity), true
	case "action":
		return req.Action, true
	case "context.trustScore":
		return strconv.FormatFloat(req.Context.TrustScore, 'f', -1, 64), true
	case "context.sourceZone":
		return req.Context.SourceZone, true
	case "context.sourceLayer":
		return req.Context.SourceLayer.String(), true
	case "context.emergency":
		return strconv.FormatBool(req.Context.Emergency), true
	case "context.hour":
		if req.Context.Time.IsZero() {
			return "", false
		}
		return strconv.Itoa(req.Context.Time.UTC().Hour()), true
	}
	if key, ok := strings.CutPrefix(name, "subject.attr."); ok {
		v, found := req.Subject.Attributes[key]
		return v, found
	}
	if key, ok := strings.CutPrefix(name, "resource.attr."); ok {
		v, found := req.Resource.Attributes[key]
		return v, found
	}
	if key, ok := strings.CutPrefix(name, "context.attr."); ok {
		v, found := req.Context.Attributes[key]
		return v, found
	}
	return "", false
}

// Glob reports whether s matches pattern, where "*" matches any sequence of
// characters (also empty, also across "/") and every other character,
// including "[", "]" and "?", matches only itself. It runs in linear time:
// on a mismatch it backtracks to the last star instead of trying every split.
func Glob(pattern, s string) bool {
	p, i := 0, 0 // positions in pattern and s
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i // remember the star; first try matching nothing
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			p = star + 1 // let the last star swallow one more character
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++ // trailing stars match the empty rest
	}
	return p == len(pattern)
}
