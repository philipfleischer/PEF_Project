// Package config reads service configuration from environment variables
// (twelve-factor style), which is how Docker Compose, Kubernetes ConfigMaps
// and Helm values reach a process. Every variable is prefixed "ZTC_".
//
// A variable that is set but cannot be parsed falls back to its default and is
// recorded, so main() can refuse to start (see Env.Err) instead of silently
// running with a value the operator did not ask for.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads variables that share a prefix. Create it with New or NewWithLookup.
// It is meant to be used during start-up from one goroutine.
type Env struct {
	Prefix string
	lookup func(string) (string, bool)
	errs   *[]error
}

// New returns an Env that reads the process environment with the "ZTC_" prefix.
func New() Env { return NewWithLookup(os.LookupEnv) }

// NewWithLookup returns an Env with the "ZTC_" prefix that reads variables
// through lookup instead of the process environment, so tests can inject values.
func NewWithLookup(lookup func(string) (string, bool)) Env {
	return Env{Prefix: "ZTC_", lookup: lookup, errs: new([]error)}
}

// name returns the full variable name: "listen" becomes "ZTC_LISTEN".
func (e Env) name(key string) string { return e.Prefix + strings.ToUpper(key) }

// Err returns every parse error seen so far joined into one error, or nil.
func (e Env) Err() error { return errors.Join(*e.errs...) }

// String returns the variable, or def if it is unset or empty.
func (e Env) String(key, def string) string {
	if v, ok := e.lookup(e.name(key)); ok && v != "" {
		return v
	}
	return def
}

// Int returns the variable parsed as an int, or def if it is unset, empty or invalid.
func (e Env) Int(key string, def int) int {
	return parse(e, key, def, strconv.Atoi)
}

// Float returns the variable parsed as a float64, or def if it is unset, empty or invalid.
func (e Env) Float(key string, def float64) float64 {
	return parse(e, key, def, func(s string) (float64, error) { return strconv.ParseFloat(s, 64) })
}

// Bool returns the variable parsed by strconv.ParseBool
// ("true", "1", "false", "0", ...), or def if it is unset, empty or invalid.
func (e Env) Bool(key string, def bool) bool {
	return parse(e, key, def, strconv.ParseBool)
}

// Duration returns the variable parsed by time.ParseDuration ("250ms", "5s", "1m"),
// or def if it is unset, empty or invalid. A number without a unit is invalid.
func (e Env) Duration(key string, def time.Duration) time.Duration {
	return parse(e, key, def, time.ParseDuration)
}

// List returns a comma-separated variable as a slice with surrounding spaces
// trimmed and empty items dropped, or def if it is unset or empty.
func (e Env) List(key string, def []string) []string {
	v, ok := e.lookup(e.name(key))
	if !ok || v == "" {
		return def
	}

	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parse is shared by the typed getters. An unset or empty variable returns
// def; a value that conv rejects is recorded in e and also returns def.
func parse[T any](e Env, key string, def T, conv func(string) (T, error)) T {
	v, ok := e.lookup(e.name(key))
	if !ok || v == "" {
		return def
	}
	x, err := conv(v)
	if err != nil {
		*e.errs = append(*e.errs, fmt.Errorf("config: %s: %w", e.name(key), err))
		return def
	}
	return x
}
