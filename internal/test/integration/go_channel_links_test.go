// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	chanLinksHTTPURL = "http://localhost:8080"
	chanLinksRawURL  = "http://localhost:8081"
	chanLinksService = "testserver"

	// OTel span links arrive in Jaeger as FOLLOWS_FROM references. CHILD_OF is
	// ordinary parentage and must never be counted as a link.
	followsFrom = "FOLLOWS_FROM"
)

// Go channel span links must not depend on the pinned trace context map. This
// suite runs with population disabled, which is the default.
func TestSuite_GoChannelLinks(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose-go-channel-links.yml",
		path.Join(pathOutput, "test-suite-go-channel-links.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())

	t.Run("unbuffered handoff between two traced requests", testChannelLinkUnbuffered)
	t.Run("buffered handoff between two traced requests", testChannelLinkBuffered)
	t.Run("generic-traced handoff, unbuffered", testChannelLinkGenericTracer)
	t.Run("generic-traced handoff, buffered", testChannelLinkGenericTracerBuffered)
	t.Run("handoff with no receiver context emits no link", testChannelLinkNoContext)
	t.Run("same-goroutine handoff emits no link", testChannelLinkSelfHandoff)

	require.NoError(t, compose.Close())
}

// The same handoffs must keep working when the trace context map is populated,
// which is when runtime.casgstatus is attached and the map is refreshed on
// every goroutine reschedule.
func TestSuite_GoChannelLinksPopulatedTraceContext(t *testing.T) {
	compose, err := docker.ComposeSuite(
		"docker-compose-go-channel-links.yml",
		path.Join(pathOutput, "test-suite-go-channel-links-populated.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_POPULATE_TRACE_CONTEXT=true`)
	require.NoError(t, compose.Up())

	t.Run("unbuffered handoff between two traced requests", testChannelLinkUnbuffered)
	t.Run("buffered handoff between two traced requests", testChannelLinkBuffered)
	t.Run("generic-traced handoff, unbuffered", testChannelLinkGenericTracer)
	t.Run("generic-traced handoff, buffered", testChannelLinkGenericTracerBuffered)
	t.Run("handoff with no receiver context emits no link", testChannelLinkNoContext)
	t.Run("same-goroutine handoff emits no link", testChannelLinkSelfHandoff)

	require.NoError(t, compose.Close())
}

// driveHandoff issues the receiving request first and lets it block on the
// channel, so the send always meets a waiting receiver. The receive runs on a
// plain client rather than the shared helper: testify's failure handling is
// only valid on the test goroutine.
func driveHandoff(t *testing.T, base, recvPath, sendPath string) {
	t.Helper()

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)

	go func() {
		resp, err := http.Get(base + recvPath)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		done <- result{status: resp.StatusCode}
	}()

	time.Sleep(50 * time.Millisecond)
	ti.DoHTTPGet(t, base+sendPath, http.StatusOK)

	select {
	case r := <-done:
		require.NoError(t, r.err, "receive %s failed", recvPath)
		require.Equal(t, http.StatusOK, r.status, "receive %s returned %d", recvPath, r.status)
	case <-time.After(testTimeout):
		t.Fatalf("handoff %s -> %s did not complete", sendPath, recvPath)
	}
}

func fetchChanLinkTraces(operation string) (jaeger.TracesQuery, error) {
	params := url.Values{
		"service":   {chanLinksService},
		"operation": {operation},
		"limit":     {"100"},
	}

	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return jaeger.TracesQuery{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jaeger.TracesQuery{}, fmt.Errorf("query Jaeger: status %s", resp.Status)
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return jaeger.TracesQuery{}, err
	}
	return traces, nil
}

// countSpans reports how many spans with this operation name reached the
// collector, so an assertion can tell missing telemetry from a missing link.
func countSpans(traces jaeger.TracesQuery, operation string) int {
	n := 0
	for _, tr := range traces.Data {
		for _, sp := range tr.Spans {
			if sp.OperationName == operation {
				n++
			}
		}
	}
	return n
}

// linksOf returns the FOLLOWS_FROM references carried by spans of the trace
// whose operation name matches.
func linksOf(traces jaeger.TracesQuery, operation string) []jaeger.Reference {
	var links []jaeger.Reference
	for _, tr := range traces.Data {
		for _, sp := range tr.Spans {
			if sp.OperationName != operation {
				continue
			}
			for _, ref := range sp.References {
				if ref.RefType == followsFrom {
					links = append(links, ref)
				}
			}
		}
	}
	return links
}

// requireLinkedReceiver asserts the receiver span carries a channel link and
// that the link names a different span: a self-link is explicitly dropped by
// the correlation code, so seeing one means context resolution picked up the
// wrong goroutine.
func requireLinkedReceiver(t *testing.T, recvOperation string) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		traces, err := fetchChanLinkTraces(recvOperation)
		require.NoError(ct, err)

		// Separate from the link assertion on purpose: a missing span means the
		// telemetry never arrived, which is a different failure from a span that
		// arrived without a link.
		require.NotZero(ct, countSpans(traces, recvOperation),
			"no %q span reached the collector at all", recvOperation)

		links := linksOf(traces, recvOperation)
		require.NotEmpty(ct, links, "receiver span %q arrived but carries no channel link", recvOperation)

		for _, l := range links {
			require.NotEmpty(ct, l.TraceID, "link must carry a trace id")
			require.NotEmpty(ct, l.SpanID, "link must carry a span id")
		}
	}, testTimeout, 500*time.Millisecond)
}

func requireNoLinks(t *testing.T, operation string) {
	t.Helper()

	// Give the pipeline the grace period a positive assertion would get, so
	// this fails on a late bogus link rather than racing it.
	time.Sleep(5 * time.Second)

	traces, err := fetchChanLinkTraces(operation)
	require.NoError(t, err)
	require.NotZero(t, countSpans(traces, operation),
		"no %q span reached the collector, so this proves nothing", operation)
	assert.Empty(t, linksOf(traces, operation),
		"span %q must not carry a channel link", operation)
}

// Both goroutines are net/http handlers, so each is in the Go tracer's
// per-operation maps and the handoff needs no fallback at all.
func testChannelLinkUnbuffered(t *testing.T) {
	for range 5 {
		driveHandoff(t, chanLinksHTTPURL, "/recv", "/send")
	}
	requireLinkedReceiver(t, "GET /recv")
}

func testChannelLinkBuffered(t *testing.T) {
	for range 5 {
		driveHandoff(t, chanLinksHTTPURL, "/recv-buffered", "/send-buffered")
	}
	requireLinkedReceiver(t, "GET /recv-buffered")
}

// The raw listener is not net/http, so these requests are traced by the generic
// protocol parser and their goroutines never enter the Go tracer's per-operation
// maps. This is the case the correlation fallback exists for, and the handlers
// reschedule before touching the channel so a thread-keyed source would resolve
// to the wrong goroutine.
func testChannelLinkGenericTracer(t *testing.T) {
	for range 5 {
		driveHandoff(t, chanLinksRawURL, "/raw-recv", "/raw-send")
	}
	requireLinkedReceiver(t, "GET /raw-recv")
}

func testChannelLinkGenericTracerBuffered(t *testing.T) {
	for range 5 {
		driveHandoff(t, chanLinksRawURL, "/raw-recv-buffered", "/raw-send-buffered")
	}
	requireLinkedReceiver(t, "GET /raw-recv-buffered")
}

// A send whose receiver runs outside any request has a span on one side only,
// so nothing may be published.
func testChannelLinkNoContext(t *testing.T) {
	for range 5 {
		ti.DoHTTPGet(t, chanLinksHTTPURL+"/orphan-send", http.StatusOK)
	}
	requireNoLinks(t, "GET /orphan-send")
}

// Send and receive on the same goroutine share a span context; the link would
// be a self-link and must be dropped.
func testChannelLinkSelfHandoff(t *testing.T) {
	for range 5 {
		ti.DoHTTPGet(t, chanLinksHTTPURL+"/self", http.StatusOK)
	}
	requireNoLinks(t, "GET /self")
}
