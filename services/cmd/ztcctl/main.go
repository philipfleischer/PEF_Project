// Command ztcctl is the operator's command line tool for ZTC.
//
// Usage:
//
//	ztcctl policy default              print the built-in substation policy as JSON
//	ztcctl policy validate <file>      check a policy file the way ztc-pdp loads it
//	ztcctl decide [flags]              ask a PDP for a decision
//	ztcctl signal [flags]              send a trust signal to a PDP
//
// Run "ztcctl decide -h" or "ztcctl signal -h" for the flags.
//
// Exit status: 0 success (for decide: allow), 3 deny, 1 error, 2 wrong usage.
//
// Environment:
//
//	ZTC_PDP_URL     PDP base URL (default http://localhost:8181)
//	ZTC_PDP_TOKEN   bearer token for signal; read from the environment, not a
//	                flag, so it does not show up in the process list
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/config"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/pdp"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/policy"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitDeny  = 3
)

const usage = `usage: ztcctl <command>

  policy default              print the built-in substation policy as JSON
  policy validate <file>      check a policy file the way ztc-pdp loads it
  decide [flags]              ask a PDP for a decision (ztcctl decide -h)
  signal [flags]              send a trust signal to a PDP (ztcctl signal -h)
`

var (
	// errUsage marks an error in how ztcctl was called.
	errUsage = errors.New("wrong usage")
	// errDenied is returned by decide when the PDP denies the request.
	errDenied = errors.New("denied")
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], config.New(), os.Stdout, os.Stderr))
}

// run executes one ztcctl command and returns the exit status. It takes its
// dependencies as parameters so tests can call it directly.
func run(ctx context.Context, args []string, env config.Env, stdout, stderr io.Writer) int {
	err := dispatch(ctx, args, env, stdout, stderr)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errDenied):
		return exitDeny
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintf(stderr, "ztcctl: %v\n\n%s", err, usage)
		return exitUsage
	default:
		_, _ = fmt.Fprintln(stderr, "ztcctl:", err)
		return exitError
	}
}

func dispatch(ctx context.Context, args []string, env config.Env, stdout, stderr io.Writer) error {
	pdpURL := env.String("pdp_url", "http://localhost:8181")
	switch {
	case len(args) == 2 && args[0] == "policy" && args[1] == "default":
		return printPolicy(stdout)
	case len(args) == 3 && args[0] == "policy" && args[1] == "validate":
		return validate(args[2], stdout)
	case len(args) >= 1 && args[0] == "decide":
		return decide(ctx, args[1:], pdpURL, stdout, stderr)
	case len(args) >= 1 && args[0] == "signal":
		return signal(ctx, args[1:], pdpURL, env.String("pdp_token", ""), stderr)
	}
	if len(args) == 0 {
		return fmt.Errorf("%w: no command", errUsage)
	}
	return fmt.Errorf("%w: unknown command %q", errUsage, strings.Join(args, " "))
}

// printPolicy writes the built-in policy in the canonical form of
// deploy/policies/substation.json.
func printPolicy(stdout io.Writer) error {
	data, err := policy.Marshal(policy.DefaultSubstationPolicy())
	if err != nil {
		return err
	}
	_, err = stdout.Write(data)
	return err
}

func validate(path string, stdout io.Writer) error {
	p, err := policy.LoadFile(path)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "ok: %s is policy version %d with %d rules\n", path, p.Version, len(p.Rules))
	return err
}

// decide builds an access request from flags, asks the PDP and prints the
// decision. A deny returns errDenied, so scripts can test the exit status.
func decide(ctx context.Context, args []string, pdpURL string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ztcctl decide", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "subject SPIFFE ID, e.g. spiffe://grid.example/edge/pmu/1 (required)")
	action := fs.String("action", "read", "action: read, write, operate, execute, migrate or admin")
	resource := fs.String("resource", "", "resource ID, e.g. bay-1/telemetry/pmu-1 (required)")
	rtype := fs.String("type", "", "resource type, e.g. telemetry or breaker (required)")
	zone := fs.String("zone", "", "the subject's zone")
	rzone := fs.String("resource-zone", "", "the resource's zone (default: -zone)")
	source := fs.String("source-zone", "", "the zone the request comes from (default: -zone)")
	roles := fs.String("roles", "", "comma-separated roles of the subject")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}
	if *subject == "" || *resource == "" || *rtype == "" {
		return fmt.Errorf("%w: decide needs -subject, -resource and -type", errUsage)
	}
	layer, err := layerOf(*subject)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	req := model.AccessRequest{
		Subject:  model.Subject{ID: *subject, Layer: layer, Zone: *zone, Roles: splitRoles(*roles)},
		Action:   *action,
		Resource: model.Resource{ID: *resource, Type: *rtype, Zone: orDefault(*rzone, *zone)},
		Context:  model.Context{SourceZone: orDefault(*source, *zone), SourceLayer: layer},
	}
	d, err := (&pdp.RemoteClient{BaseURL: pdpURL, Timeout: 5 * time.Second}).Decide(ctx, req)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%s: %s (trust %.3f, decided by %s)\n",
		d.Effect, d.Reason, d.TrustScore, d.DecidedBy); err != nil {
		return err
	}
	if !d.Allowed() {
		return errDenied
	}
	return nil
}

// signal sends one trust signal, authenticated with ZTC_PDP_TOKEN.
func signal(ctx context.Context, args []string, pdpURL, token string, stderr io.Writer) error {
	fs := flag.NewFlagSet("ztcctl signal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "subject SPIFFE ID (required)")
	kind := fs.String("kind", "", "authentication, posture, behaviour, location, denial or compromise (required)")
	value := fs.Float64("value", 1, "signal value in [0, 1]")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}
	if *subject == "" || !trust.Kind(*kind).Valid() {
		return fmt.Errorf("%w: signal needs -subject and a valid -kind", errUsage)
	}
	if token == "" {
		return errors.New("ZTC_PDP_TOKEN is not set")
	}
	c := &pdp.RemoteClient{BaseURL: pdpURL, Token: token, Timeout: 5 * time.Second}
	return c.RecordSignal(ctx, trust.Signal{Subject: *subject, Kind: trust.Kind(*kind), Value: *value, Source: "ztcctl"})
}

// layerOf reads the layer from a SPIFFE ID of the form
// spiffe://<trust-domain>/<layer>/<kind>/<name>.
func layerOf(id string) (model.Layer, error) {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	parts := strings.Split(rest, "/")
	if !ok || len(parts) < 3 {
		return model.LayerUnknown, fmt.Errorf("subject %q is not of the form spiffe://<trust-domain>/<layer>/<kind>/<name>", id)
	}
	return model.ParseLayer(parts[1])
}

// splitRoles turns "operator, engineer" into ["operator" "engineer"].
func splitRoles(s string) []string {
	var roles []string
	for _, r := range strings.Split(s, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// parseError keeps -h a success and turns other flag errors into usage errors.
func parseError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return fmt.Errorf("%w: %w", errUsage, err)
}
