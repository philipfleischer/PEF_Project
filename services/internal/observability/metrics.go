// Package observability gives every ZTC service metrics in the Prometheus
// text exposition format, health and readiness endpoints, request
// instrumentation and structured logging, using only the standard library.
//
// Industry equivalent: prometheus/client_golang and OpenTelemetry.
package observability

import (
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// metric is implemented by every metric type so the registry can render them
// without knowing which kind each one is.
type metric interface {
	writeTo(b *strings.Builder)
}

// Registry holds the metrics of one service. It is safe for concurrent use.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]metric
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{metrics: map[string]metric{}}
}

// register returns the metric called name, creating it with create if it does
// not exist yet. Registering the same name as two different kinds of metric
// is a programming error, so it panics.
func register[M metric](r *Registry, name string, create func() M) M {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.metrics[name]; ok {
		m, ok := existing.(M)
		if !ok {
			panic(fmt.Sprintf("observability: %q is already registered as %T", name, existing))
		}
		return m
	}
	m := create()
	r.metrics[name] = m
	return m
}

// Counter returns the counter called name, creating it if needed.
func (r *Registry) Counter(name, help string) *Counter {
	return register(r, name, func() *Counter {
		return &Counter{series{name: name, help: help, kind: "counter", values: map[string]float64{}}}
	})
}

// Gauge returns the gauge called name, creating it if needed.
func (r *Registry) Gauge(name, help string) *Gauge {
	return register(r, name, func() *Gauge {
		return &Gauge{series{name: name, help: help, kind: "gauge", values: map[string]float64{}}}
	})
}

// Histogram returns the histogram called name with the given bucket upper
// bounds, creating it if needed. The buckets of an existing histogram are kept.
func (r *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	return register(r, name, func() *Histogram {
		b := slices.Clone(buckets)
		slices.Sort(b)
		return &Histogram{name: name, help: help, buckets: b, series: map[string]*histSeries{}}
	})
}

// Write renders every metric, sorted by name, in the Prometheus text format.
func (r *Registry) Write(w io.Writer) error {
	// Copy the metric list while holding the lock, so a metric registered
	// concurrently by another goroutine cannot change the map under us.
	r.mu.Lock()
	names := slices.Sorted(maps.Keys(r.metrics))
	ms := make([]metric, len(names))
	for i, n := range names {
		ms[i] = r.metrics[n]
	}
	r.mu.Unlock()

	var b strings.Builder
	for _, m := range ms {
		m.writeTo(&b)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Handler serves the registry as a Prometheus scrape endpoint.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.Write(w)
	})
}

// series is the shared part of counters and gauges: one float64 per label set.
type series struct {
	name, help, kind string
	mu               sync.Mutex
	values           map[string]float64 // rendered label set -> value
}

func (s *series) add(v float64, labels []string) {
	k := renderLabels(labels)
	s.mu.Lock()
	s.values[k] += v
	s.mu.Unlock()
}

func (s *series) value(labels []string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[renderLabels(labels)]
}

func (s *series) writeTo(b *strings.Builder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", s.name, escapeHelp(s.help), s.name, s.kind)
	for _, k := range slices.Sorted(maps.Keys(s.values)) {
		fmt.Fprintf(b, "%s%s %s\n", s.name, k, formatFloat(s.values[k]))
	}
}

// Counter is a value that only goes up, for example the number of requests.
// Labels are given as key, value pairs: c.Inc("outcome", "allow").
type Counter struct{ series }

// Inc adds 1 for the given labels.
func (c *Counter) Inc(labels ...string) { c.Add(1, labels...) }

// Add adds v for the given labels. Negative values are ignored, because a
// counter never goes down.
func (c *Counter) Add(v float64, labels ...string) {
	if v < 0 {
		return
	}
	c.add(v, labels)
}

// Value returns the current value for the given labels.
func (c *Counter) Value(labels ...string) float64 { return c.value(labels) }

// Gauge is a value that can go up and down, for example a trust score.
type Gauge struct{ series }

// Set sets the gauge for the given labels.
func (g *Gauge) Set(v float64, labels ...string) {
	k := renderLabels(labels)
	g.mu.Lock()
	g.values[k] = v
	g.mu.Unlock()
}

// Add adds v (which may be negative) for the given labels.
func (g *Gauge) Add(v float64, labels ...string) { g.add(v, labels) }

// Value returns the current value for the given labels.
func (g *Gauge) Value(labels ...string) float64 { return g.value(labels) }

// Histogram counts observations, such as request latencies, in buckets.
type Histogram struct {
	name, help string
	buckets    []float64 // sorted upper bounds
	mu         sync.Mutex
	series     map[string]*histSeries
}

type histSeries struct {
	counts []uint64 // observations per bucket; made cumulative when rendered
	sum    float64
	count  uint64
}

// Observe records one value for the given labels.
func (h *Histogram) Observe(v float64, labels ...string) {
	k := renderLabels(labels)
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.series[k]
	if !ok {
		s = &histSeries{counts: make([]uint64, len(h.buckets))}
		h.series[k] = s
	}
	// The first bucket whose upper bound is >= v; values above every bound
	// are only counted in the implicit +Inf bucket.
	if i, _ := slices.BinarySearch(h.buckets, v); i < len(s.counts) {
		s.counts[i]++
	}
	s.sum += v
	s.count++
}

func (h *Histogram) writeTo(b *strings.Builder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, escapeHelp(h.help), h.name)
	for _, k := range slices.Sorted(maps.Keys(h.series)) {
		s := h.series[k]
		var cumulative uint64
		for i, upper := range h.buckets {
			cumulative += s.counts[i]
			fmt.Fprintf(b, "%s_bucket%s %d\n", h.name, withLabel(k, "le", formatFloat(upper)), cumulative)
		}
		fmt.Fprintf(b, "%s_bucket%s %d\n", h.name, withLabel(k, "le", "+Inf"), s.count)
		fmt.Fprintf(b, "%s_sum%s %s\n", h.name, k, formatFloat(s.sum))
		fmt.Fprintf(b, "%s_count%s %d\n", h.name, k, s.count)
	}
}

// DefBuckets are latency buckets in seconds suited to authorization
// decisions, from 0.5 ms to 5 s.
var DefBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// renderLabels turns ("b", "2", "a", "1") into {a="1",b="2"}. Pairs are sorted
// by key so the same label set always renders the same way; a trailing key
// without a value is ignored.
func renderLabels(labels []string) string {
	if len(labels) < 2 {
		return ""
	}
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		pairs = append(pairs, pair{labels[i], labels[i+1]})
	}
	slices.SortFunc(pairs, func(a, b pair) int { return strings.Compare(a.k, b.k) })

	var b strings.Builder
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, p.k, escapeLabel(p.v))
	}
	b.WriteByte('}')
	return b.String()
}

// withLabel adds one more label to an already rendered label set.
func withLabel(rendered, k, v string) string {
	extra := fmt.Sprintf(`%s="%s"`, k, escapeLabel(v))
	if rendered == "" {
		return "{" + extra + "}"
	}
	return rendered[:len(rendered)-1] + "," + extra + "}"
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }

func escapeHelp(s string) string { return helpEscaper.Replace(s) }

func formatFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
