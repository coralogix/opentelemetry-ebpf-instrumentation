// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const tokioServerURL = "http://localhost:8092"

// TestRustTokioContextPropagation drives the consolidated Axum (multi-thread)
// server and asserts that OBI propagates trace context across the
// server -> backend boundary for each Tokio concurrency pattern:
//   - tokio::spawn (async ancestry walk, possibly cross-thread under work-stealing)
//   - nested tokio::spawn (depth-2 ancestry)
//   - spawn_blocking (blocking-pool bridge)
//   - tokio::spawn + spawn_blocking
//
// "Propagation works" = a single trace contains server's inbound server span,
// its outgoing client span to backend, and backend's server span, with the
// backend span CHILD_OF the client span.
func TestRustTokioContextPropagation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust-tokio.yml",
		path.Join(pathOutput, "test-suite-rust-tokio.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { _ = compose.Close() })

	// Wait until the server is accepting requests.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(tokioServerURL + "/health")
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, time.Second)

	t.Run("async spawn (depth 1, work-stealing)", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/ws-spawn")
	})
	t.Run("async nested spawn (depth 2)", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/ws-nested")
	})
	t.Run("spawn_blocking", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/blocking")
	})
	t.Run("spawn + spawn_blocking", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/blocking-nested")
	})
}

// assertTokioCrossServiceTrace drives a handful of sequential requests to urlPath
// and asserts that at least one produced a complete server -> backend trace.
//
// Requests are sequential (not concurrent) to avoid the documented §4.4 keep-alive
// connection-overwrite tail; we still require only ≥1 complete chain so the test is
// robust to any single timing miss rather than asserting a hard 100%.
func assertTokioCrossServiceTrace(t *testing.T, urlPath string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Drive one request per poll so load keeps flowing until OBI is attached
		// and traces appear — avoids a fixed up-front burst racing OBI's startup.
		resp, err := http.Get(tokioServerURL + urlPath)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		jr, err := http.Get(jaegerQueryURL + "?service=server&lookback=1h&limit=50")
		require.NoError(ct, err)
		defer jr.Body.Close()
		require.Equal(ct, http.StatusOK, jr.StatusCode)

		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(jr.Body).Decode(&tq))

		// Traces that contain a server span for this endpoint.
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: urlPath})
		require.NotEmpty(ct, traces, "no traces with url.path=%s yet", urlPath)

		// At least one of them must show the full cross-service chain.
		require.True(ct, anyCompleteTokioChain(traces, urlPath),
			"no trace with full server->backend chain for %s", urlPath)
	}, testTimeout, time.Second)
}

// anyCompleteTokioChain returns true if some trace contains:
//
//	server server span (url.path=urlPath)  ->  server client span (url.path=/ping)
//	                                        ->  backend server span (url.path=/ping)
//
// with the backend span CHILD_OF the client span (proving end-to-end propagation).
func anyCompleteTokioChain(traces []jaeger.Trace, urlPath string) bool {
	for i := range traces {
		tr := traces[i]
		serverRoot := tokioFindSpans(tr, "server", "server", urlPath)
		// The outgoing call to backend is a CLIENT span. OBI client spans carry the
		// target as url.full (e.g. http://127.0.0.1:8093/ping), not url.path, so match
		// on the /ping suffix of url.full rather than url.path.
		clientSpans := tokioFindClientSpans(tr, "server", "/ping")
		backendSpans := tokioFindSpans(tr, "backend", "server", "/ping")
		if len(serverRoot) != 1 || len(clientSpans) == 0 || len(backendSpans) == 0 {
			continue
		}
		for _, be := range backendSpans {
			for _, cl := range clientSpans {
				if childOfParent(be) == cl.SpanID && be.TraceID == serverRoot[0].TraceID {
					return true
				}
			}
		}
	}
	return false
}

// tokioFindSpans returns the spans in tr matching the given OBI service name,
// span.kind, and url.path tag (url.path is ignored when empty).
func tokioFindSpans(tr jaeger.Trace, service, kind, urlPath string) []jaeger.Span {
	var out []jaeger.Span
	for _, s := range tr.Spans {
		if tr.Processes[s.ProcessID].ServiceName != service {
			continue
		}
		if tokioSpanTag(s, "span.kind") != kind {
			continue
		}
		if urlPath != "" && tokioSpanTag(s, "url.path") != urlPath {
			continue
		}
		out = append(out, s)
	}
	return out
}

// tokioFindClientSpans returns the CLIENT spans in tr for the given OBI service
// whose url.full ends with pathSuffix (client spans use url.full, not url.path).
func tokioFindClientSpans(tr jaeger.Trace, service, pathSuffix string) []jaeger.Span {
	var out []jaeger.Span
	for _, s := range tr.Spans {
		if tr.Processes[s.ProcessID].ServiceName != service {
			continue
		}
		if tokioSpanTag(s, "span.kind") != "client" {
			continue
		}
		if !strings.HasSuffix(tokioSpanTag(s, "url.full"), pathSuffix) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func tokioSpanTag(s jaeger.Span, key string) string {
	for _, tg := range s.Tags {
		if tg.Key == key {
			return fmt.Sprint(tg.Value)
		}
	}
	return ""
}

func childOfParent(s jaeger.Span) string {
	for _, r := range s.References {
		if r.RefType == "CHILD_OF" {
			return r.SpanID
		}
	}
	return ""
}
