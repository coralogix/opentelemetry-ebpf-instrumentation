// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

// TestHAProxyContextPropagation validates that W3C traceparent-based context
// propagation works correctly when HTTP traffic flows through HAProxy between
// each hop in the service chain:
//
//	tpclient-a --> haproxy:7001 --> tpclient-b --> haproxy:7002 --> tpclient-c
//
// HAProxy is also instrumented (its ports 7001/7002 are in OBI's discovery
// scope), so the trace contains both the tpclient and haproxy spans. This
// exercises the back_handle_st_rdy uprobe in bpf/generictracer/haproxy.c
// which correlates HAProxy's backend dispatch to the inbound stream so the
// outgoing client span and the inbound server span land in the same trace.
//
// The four sub-tests cover:
//  1. No incoming traceparent  -> eBPF generates one and propagates through
//     haproxy to all downstream services in a single connected trace.
//  2. Static traceparent       -> eBPF extracts the incoming trace ID and
//     every span (including HAProxy server+client spans at each hop)
//     shares it.
//  3. Forwarded traceparent    -> client forwards same traceparent unchanged
//     (span_id == parent_id); HAProxy passes it through; eBPF must still
//     detect the proxy-forwarding pattern and override span IDs.
//  4. HTTP/1.1 keepalive       -> hammer the chain N times so HAProxy's
//     idle-pool reuses backend connections; assert each request gets its
//     own correctly-correlated trace (cold-vs-warm parity).
func TestHAProxyContextPropagation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-haproxy.yml", path.Join(pathOutput, "test-suite-haproxy.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	// Wait for the tpclient chain to be reachable on the host-exposed port.
	waitForTestComponents(t, "http://localhost:6000")

	// Wait for instrumentation to be FULLY warm — not just tpclient-a, but
	// every process in the chain including HAProxy. Probe attachment to
	// HAProxy lags tpclient probe attachment by 2-3s during OBI startup
	// (verified via OBI debug logs); without this gate the very first
	// /no-tp request can slip through before back_handle_st_rdy is hooked
	// and produce an uncorrelated tpclient-c trace.
	//
	// Strategy: keep firing /no-tp until at least one resulting trace
	// contains spans from all four services. That guarantees every
	// uprobe / kprobe in the chain is attached and producing data.
	t.Log("waiting for instrumentation to be ready (full chain warm-up)")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:6000/no-tp", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&operation=GET%20%2Fno-tp&limit=20")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return
		}
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		fullChain := false
		for _, tr := range tq.Data {
			services := servicesInTrace(tr)
			_, hasA := services["tpclient-a"]
			_, hasB := services["tpclient-b"]
			_, hasC := services["tpclient-c"]
			_, hasHA := services["haproxy"]
			if hasA && hasB && hasC && hasHA {
				fullChain = true
				break
			}
		}
		require.True(ct, fullChain, "no fully-connected trace yet (HAProxy probes still attaching)")
	}, 2*time.Minute, 1*time.Second)
	t.Log("instrumentation ready (full chain observed)")

	t.Run("without_traceparent_through_haproxy", testHAProxyWithoutTraceparent)
	t.Run("with_traceparent_through_haproxy", testHAProxyWithTraceparent)
	t.Run("with_forwarded_traceparent_through_haproxy", testHAProxyWithForwardedTraceparent)
	t.Run("keepalive_warm_connection_correlation", testHAProxyKeepaliveCorrelation)

	require.NoError(t, compose.Close())
}

// servicesInTrace returns the unique set of service names that appear in
// the given trace (looked up via Jaeger's process map).
func servicesInTrace(trace jaeger.Trace) map[string]struct{} {
	seen := map[string]struct{}{}
	for _, span := range trace.Spans {
		proc, ok := trace.Processes[span.ProcessID]
		if !ok {
			continue
		}
		seen[proc.ServiceName] = struct{}{}
	}
	return seen
}

// requireConnectedHAProxyChain asserts the trace covers the full
// a -> haproxy -> b -> haproxy -> c chain with all spans sharing the same
// trace ID. This is the load-bearing assertion: if HAProxy correlation is
// broken, tpclient-c's spans land in a different trace and this fails.
func requireConnectedHAProxyChain(t *testing.T, trace jaeger.Trace, expectedTraceID string) {
	t.Helper()
	require.NotEmpty(t, trace.Spans)
	for _, span := range trace.Spans {
		require.Equal(t, expectedTraceID, span.TraceID,
			"all spans in the chain must share the same trace ID — span %s belongs to trace %s",
			span.SpanID, span.TraceID)
	}
	services := servicesInTrace(trace)
	for _, want := range []string{"tpclient-a", "tpclient-b", "tpclient-c", "haproxy"} {
		_, ok := services[want]
		require.True(t, ok,
			"trace %s should include spans from %q (HAProxy correlation must keep the chain connected); saw %v",
			expectedTraceID, want, services)
	}
}

// testHAProxyWithoutTraceparent validates that when NO traceparent is present,
// eBPF generates one on the tpclient-a outbound call and that the generated
// trace ID is preserved end-to-end through both HAProxy hops, with HAProxy's
// own server/client spans correlated into the same trace.
func testHAProxyWithoutTraceparent(t *testing.T) {
	ti.DoHTTPGet(t, "http://localhost:6000/no-tp", 200)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Fire an extra request each iteration so Jaeger accumulates
		// fresh (post-warmup) traces in case earlier ones were partial.
		ti.DoHTTPGet(ct, "http://localhost:6000/no-tp", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&operation=GET%20%2Fno-tp&limit=50")
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		matched := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/no-tp"})

		// Pick the first fully-connected trace (skip partial warm-up traces).
		found := false
		for _, tr := range matched {
			services := servicesInTrace(tr)
			_, hasA := services["tpclient-a"]
			_, hasC := services["tpclient-c"]
			_, hasHA := services["haproxy"]
			if hasA && hasC && hasHA {
				trace = tr
				found = true
				break
			}
		}
		require.True(ct, found, "no fully-connected /no-tp trace yet")
	}, testTimeout, 100*time.Millisecond)

	serviceASpans := trace.FindByOperationName("GET /no-tp", "server")
	require.GreaterOrEqual(t, len(serviceASpans), 1)
	serviceASpan := serviceASpans[0]

	// A real trace ID must have been generated.
	require.NotEmpty(t, serviceASpan.TraceID)
	require.Len(t, serviceASpan.TraceID, 32)
	require.NotEqual(t, staticTraceID, serviceASpan.TraceID,
		"eBPF should generate a new trace ID, not use the static one")

	// Strong end-to-end check: every service in the chain (including HAProxy)
	// must appear in this trace and share the same trace ID.
	requireConnectedHAProxyChain(t, trace, serviceASpan.TraceID)
}

// testHAProxyWithTraceparent validates that a traceparent injected at the
// edge propagates intact through HAProxy and is correctly correlated by
// the back_handle_st_rdy uprobe so HAProxy's spans join the same trace.
func testHAProxyWithTraceparent(t *testing.T) {
	ti.DoHTTPGet(t, "http://localhost:6000/with-tp", 200)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&traceID=" + staticTraceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.GreaterOrEqual(ct, len(tq.Data), 1, "should find trace with static trace ID")
		trace = tq.Data[0]
		require.NotEmpty(ct, trace.Spans)
	}, testTimeout, 100*time.Millisecond)

	requireConnectedHAProxyChain(t, trace, staticTraceID)
}

// testHAProxyWithForwardedTraceparent validates that when the client forwards
// the SAME traceparent unchanged (span_id == parent_id), HAProxy's pass-through
// behavior does not hide the forwarding pattern from eBPF: the tpinjector
// must still detect the collision and override the span ID so the spans in
// the trace do not all collapse onto a single forwarded span ID.
func testHAProxyWithForwardedTraceparent(t *testing.T) {
	ti.DoHTTPGet(t, "http://localhost:6000/with-forwarded-tp", 200)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&traceID=" + staticTraceID)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/with-forwarded-tp"})
		require.GreaterOrEqual(ct, len(traces), 1, "should find trace with forwarded traceparent")
		trace = traces[0]
		require.NotEmpty(ct, trace.Spans)
	}, testTimeout, 100*time.Millisecond)

	requireConnectedHAProxyChain(t, trace, staticTraceID)

	// Span IDs must not all be the forwarded span ID — eBPF must have
	// detected the forwarding pattern and generated fresh span IDs.
	allSpansHaveForwardedID := true
	for _, span := range trace.Spans {
		if span.SpanID != forwardedSpanID {
			allSpansHaveForwardedID = false
			break
		}
	}
	require.False(t, allSpansHaveForwardedID,
		"eBPF should override forwarded span IDs through HAProxy (not all spans should have %s)", forwardedSpanID)
}

// testHAProxyKeepaliveCorrelation hammers the chain N times to force
// HAProxy to reuse backend connections from its idle pool. With
// `http-reuse always` configured (see configs/haproxy.cfg), the second
// and subsequent requests should pick up warm connections rather than
// opening fresh ones — exercising the warm-path branch of
// back_handle_st_rdy. Each request must produce its own well-correlated
// trace; if the warm-path correlation is broken, traces will collapse
// onto a single (oldest) parent or split entirely.
func testHAProxyKeepaliveCorrelation(t *testing.T) {
	const iterations = 10
	for range iterations {
		ti.DoHTTPGet(t, "http://localhost:6000/no-tp", 200)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&operation=GET%20%2Fno-tp&limit=" +
			itoa(iterations*2)) // *2 to absorb traces from earlier sub-tests
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		// Pick out only the traces that contain our /no-tp operation
		// (filters out smoke/warmup traces that share the operation).
		matched := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/no-tp"})
		require.GreaterOrEqual(ct, len(matched), iterations,
			"expected at least %d /no-tp traces, got %d", iterations, len(matched))

		// Every captured /no-tp trace must contain all four services.
		// If the warm-connection correlation in back_handle_st_rdy is
		// broken, tpclient-c will be missing from later traces.
		fullChainCount := 0
		for _, tr := range matched {
			services := servicesInTrace(tr)
			_, hasA := services["tpclient-a"]
			_, hasB := services["tpclient-b"]
			_, hasC := services["tpclient-c"]
			_, hasHA := services["haproxy"]
			if hasA && hasB && hasC && hasHA {
				fullChainCount++
			}
		}
		require.GreaterOrEqual(ct, fullChainCount, iterations,
			"expected all %d /no-tp traces to be fully connected through HAProxy (cold + warm); got %d", iterations, fullChainCount)
	}, testTimeout, 250*time.Millisecond)
}

// itoa is a tiny inline helper to avoid pulling strconv into this test
// just for one URL parameter.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
