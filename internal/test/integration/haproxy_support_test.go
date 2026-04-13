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
// The eBPF tpinjector runs against the tpclient processes (ports 6000/6001/6002).
// HAProxy (2.8.5) acts as a transparent HTTP reverse proxy, preserving the
// traceparent header across hops. The test verifies three scenarios:
//  1. No incoming traceparent  -> eBPF generates one and propagates it through
//     HAProxy to downstream services.
//  2. Static traceparent       -> eBPF extracts the incoming trace ID and every
//     span in the chain shares it, even though each hop crosses HAProxy.
//  3. Forwarded traceparent    -> the client forwards the same traceparent
//     unchanged (span_id == parent_id). HAProxy passes it through; eBPF must
//     still detect the proxy-forwarding pattern and override span IDs.
func TestHAProxyContextPropagation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-haproxy.yml", path.Join(pathOutput, "test-suite-haproxy.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	// Wait for the tpclient chain to be reachable on the host-exposed port.
	waitForTestComponents(t, "http://localhost:6000")

	// Wait for instrumentation to be warm: a smoke request must produce a trace
	// in Jaeger for service "tpclient-a".
	t.Log("waiting for instrumentation to be ready")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:6000/smoke", 200)

		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&limit=1")
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			return
		}

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		if len(tq.Data) == 0 {
			return
		}
	}, 2*time.Minute, 1*time.Second)
	t.Log("instrumentation ready")

	t.Run("without_traceparent_through_haproxy", testHAProxyWithoutTraceparent)
	t.Run("with_traceparent_through_haproxy", testHAProxyWithTraceparent)
	t.Run("with_forwarded_traceparent_through_haproxy", testHAProxyWithForwardedTraceparent)

	require.NoError(t, compose.Close())
}

// testHAProxyWithoutTraceparent validates that when NO traceparent is present,
// eBPF generates one on the tpclient-a outbound call and that the generated
// trace ID is preserved by HAProxy so tpclient-b and tpclient-c join the same
// trace.
func testHAProxyWithoutTraceparent(t *testing.T) {
	ti.DoHTTPGet(t, "http://localhost:6000/no-tp", 200)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=tpclient-a&operation=GET%20%2Fno-tp")
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/no-tp"})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
		require.NotEmpty(ct, trace.Spans)
	}, testTimeout, 100*time.Millisecond)

	serviceASpans := trace.FindByOperationName("GET /no-tp", "server")
	require.GreaterOrEqual(t, len(serviceASpans), 1)
	serviceASpan := serviceASpans[0]

	// A real trace ID must have been generated.
	require.NotEmpty(t, serviceASpan.TraceID)
	require.Len(t, serviceASpan.TraceID, 32)
	require.NotEqual(t, staticTraceID, serviceASpan.TraceID,
		"eBPF should generate a new trace ID, not use the static one")

	// Every span (across HAProxy hops) must share the generated trace ID.
	for _, span := range trace.Spans {
		require.Equal(t, serviceASpan.TraceID, span.TraceID,
			"All spans should share the same trace ID after passing through HAProxy")
	}
}

// testHAProxyWithTraceparent validates that a traceparent injected at the edge
// (by tpclient-a with STATIC_TRACEPARENT) is correctly extracted on the
// tpclient-b and tpclient-c sides even though HAProxy sits between each hop.
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

	// HAProxy must have forwarded the traceparent unchanged so every span in
	// the chain ends up on the static trace ID.
	for _, span := range trace.Spans {
		require.Equal(t, staticTraceID, span.TraceID,
			"HAProxy must preserve the incoming traceparent so all spans share the static trace ID")
	}

	// Chain must contain spans from all three services (a -> haproxy -> b -> haproxy -> c).
	require.GreaterOrEqual(t, len(trace.Spans), 3,
		"Should have spans from all services in the chain (a, b, c)")
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

	// Trace ID must still match the static one (extraction works through HAProxy).
	for _, span := range trace.Spans {
		require.Equal(t, staticTraceID, span.TraceID,
			"eBPF should extract the static trace ID even when HAProxy forwards the traceparent")
	}

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

	require.GreaterOrEqual(t, len(trace.Spans), 3,
		"Should have spans from all services in the chain (a, b, c) through HAProxy")
}
