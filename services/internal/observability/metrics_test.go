package observability

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("ztc_requests_total", "Requests.")
	c.Inc("outcome", "allow", "pep", "fog-1")
	c.Inc("pep", "fog-1", "outcome", "allow") // same label set, other order
	c.Add(-5, "outcome", "allow")             // ignored: counters never go down
	r.Gauge("ztc_trust_score", "Trust score.").Set(0.75, "subject", `a"b`)
	h := r.Histogram("ztc_latency_seconds", "Latency.", []float64{1, 0.1}) // unsorted on purpose
	h.Observe(0.05)
	h.Observe(0.5)
	h.Observe(5)

	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# HELP ztc_requests_total Requests.",
		"# TYPE ztc_requests_total counter",
		`ztc_requests_total{outcome="allow",pep="fog-1"} 2`,
		"# TYPE ztc_trust_score gauge",
		`ztc_trust_score{subject="a\"b"} 0.75`,
		"# TYPE ztc_latency_seconds histogram",
		`ztc_latency_seconds_bucket{le="0.1"} 1`,
		`ztc_latency_seconds_bucket{le="1"} 2`,
		`ztc_latency_seconds_bucket{le="+Inf"} 3`,
		"ztc_latency_seconds_sum 5.55",
		"ztc_latency_seconds_count 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n%s", want, out)
		}
	}
	if got := c.Value("pep", "fog-1", "outcome", "allow"); got != 2 {
		t.Errorf("Value = %v, want 2", got)
	}
}

func TestSameNameReturnsSameMetric(t *testing.T) {
	r := NewRegistry()
	r.Counter("ztc_x_total", "X.").Inc()
	r.Counter("ztc_x_total", "X.").Inc()
	if got := r.Counter("ztc_x_total", "X.").Value(); got != 2 {
		t.Errorf("Value = %v, want 2", got)
	}
}

func TestRegisteringNameAsOtherKindPanics(t *testing.T) {
	r := NewRegistry()
	r.Counter("ztc_x", "X.")
	defer func() {
		if recover() == nil {
			t.Error("registering a counter name as a gauge did not panic")
		}
	}()
	r.Gauge("ztc_x", "X.")
}

func TestHandler(t *testing.T) {
	r := NewRegistry()
	r.Counter("ztc_up_total", "Up.").Inc()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if !strings.Contains(rec.Body.String(), "ztc_up_total 1") {
		t.Errorf("body = %q, want it to contain ztc_up_total 1", rec.Body.String())
	}
}

// TestConcurrentUse registers, updates and renders metrics from several
// goroutines at once. Run it with -race: it fails if Write reads the metric
// map without holding the registry lock.
func TestConcurrentUse(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 100 {
				r.Counter(fmt.Sprintf("ztc_c%d_total", i%5), "C.").Inc("worker", strconv.Itoa(worker))
				_ = r.Write(io.Discard)
			}
		})
	}
	wg.Wait()

	var total float64
	for worker := range 8 {
		total += r.Counter("ztc_c0_total", "C.").Value("worker", strconv.Itoa(worker))
	}
	if total != 8*20 {
		t.Errorf("ztc_c0_total summed over workers = %v, want %d", total, 8*20)
	}
}
