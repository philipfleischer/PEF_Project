// Ways to reach a decision other than calling a PDP directly: a client for a
// remote PDP, a chain of deciders, and the placement modes RQ1 compares.

package pdp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/philipfleischer/zero-trust-continuum/services/internal/model"
	"github.com/philipfleischer/zero-trust-continuum/services/internal/trust"
)

// Placement is where access decisions are made (research question RQ1).
type Placement string

// The placements.
const (
	// PlacementCloud sends every decision to the PDP in the cloud: always
	// fresh, but slow, and nothing is allowed while the WAN is down.
	PlacementCloud Placement = "cloud"
	// PlacementFog runs a full PDP on every fog node: fast and available
	// during a WAN outage, but policy changes arrive late.
	PlacementFog Placement = "fog"
	// PlacementHierarchical puts a decision cache on the fog node in front of
	// the cloud PDP: fast on a hit, fresh on a miss.
	PlacementHierarchical Placement = "hierarchical"
)

// ParsePlacement returns the placement called s, or an error if there is none.
func ParsePlacement(s string) (Placement, error) {
	switch p := Placement(s); p {
	case PlacementCloud, PlacementFog, PlacementHierarchical:
		return p, nil
	}
	return "", fmt.Errorf("pdp: unknown placement %q (want cloud, fog or hierarchical)", s)
}

// DefaultTimeout is how long a RemoteClient waits for an answer when its
// Timeout is 0.
const DefaultTimeout = 2 * time.Second

// maxResponse is the largest response body a RemoteClient reads (1 MiB).
const maxResponse = 1 << 20

// RemoteClient asks a PDP over HTTP. It implements Decider.
type RemoteClient struct {
	BaseURL string        // e.g. "http://localhost:8181"
	Token   string        // bearer token for writes such as RecordSignal
	Timeout time.Duration // per request; 0 means DefaultTimeout
	// HTTP is the client to use. nil means a client that does not follow
	// redirects, so a decision can only come from BaseURL.
	HTTP *http.Client
}

// noRedirects is the default HTTP client of a RemoteClient.
var noRedirects = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Decide sends req to POST /v1/decide. Any failure (unreachable, timeout, a
// status other than 200, a body that is not a decision) returns a deny and
// the error, so a PEP fails closed.
func (c *RemoteClient) Decide(ctx context.Context, req model.AccessRequest) (model.Decision, error) {
	deny := model.Decision{Effect: model.Deny, Reason: "remote PDP unavailable"}
	resp, err := c.post(ctx, "/v1/decide", req, "")
	if err != nil {
		return deny, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return deny, statusError(resp)
	}
	var d model.Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&d); err != nil {
		return deny, fmt.Errorf("pdp: decode decision: %w", err)
	}
	if d.Effect != model.Allow && d.Effect != model.Deny {
		return deny, fmt.Errorf("pdp: remote PDP returned effect %q", d.Effect)
	}
	return d, nil
}

// RecordSignal sends sig to POST /v1/signals with the client's token.
func (c *RemoteClient) RecordSignal(ctx context.Context, sig trust.Signal) error {
	resp, err := c.post(ctx, "/v1/signals", sig, c.Token)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return statusError(resp)
	}
	return nil
}

// post sends v as JSON to BaseURL+path within the client's timeout.
func (c *RemoteClient) post(ctx context.Context, path string, v any, bearer string) (*http.Response, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := c.HTTP
	if client == nil {
		client = noRedirects
	}
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("pdp: %w", err)
	}
	resp.Body = cancelOnClose{resp.Body, cancel}
	return resp, nil
}

// cancelOnClose releases the request's timeout when the body is closed, so
// the caller can still read the body after post returns.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// statusError turns an unexpected response into an error that carries the
// status and the start of the body.
func statusError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("pdp: remote PDP answered %s: %s", resp.Status, bytes.TrimSpace(msg))
}

// Chain asks each Decider in order and returns the first answer. A deny is an
// answer; only an error moves on to the next Decider. If none answers, the
// result is a deny and all errors joined.
type Chain []Decider

// Decide implements Decider.
func (ch Chain) Decide(ctx context.Context, req model.AccessRequest) (model.Decision, error) {
	errs := []error{errors.New("pdp: no decider answered")}
	for _, d := range ch {
		dec, err := d.Decide(ctx, req)
		if err == nil {
			return dec, nil
		}
		errs = append(errs, err)
	}
	return model.Decision{Effect: model.Deny, Reason: "no decider answered"}, errors.Join(errs...)
}

// DeciderFunc lets an ordinary function act as a Decider, for tests and
// small adapters.
type DeciderFunc func(ctx context.Context, req model.AccessRequest) (model.Decision, error)

// Decide calls f.
func (f DeciderFunc) Decide(ctx context.Context, req model.AccessRequest) (model.Decision, error) {
	return f(ctx, req)
}

// Check at compile time that the deciders satisfy Decider.
var (
	_ Decider = (*RemoteClient)(nil)
	_ Decider = Chain(nil)
	_ Decider = DeciderFunc(nil)
)
