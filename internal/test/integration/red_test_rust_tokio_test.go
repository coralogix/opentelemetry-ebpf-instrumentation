// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
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
// Requests are sequential (not concurrent) to avoid the keep-alive
// connection-overwrite tail (a reused inbound connection can have its
// server_traces_aux entry overwritten before egress resolves it); we require only
// ≥1 complete chain so the test is robust to any single timing miss rather than
// asserting a hard 100%.
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

// tokioABCase parameterizes one A/B discrimination scenario. The app wires each
// server endpoint to a DISTINCT backend path, so app-wiring is the ground truth: a
// single trace containing both an A-marker and a B-marker can only arise from
// misattribution. Distinct backends per case also keep the subtests from
// cross-classifying each other's traces.
type tokioABCase struct {
	serverA, serverB   string // e.g. "/blocking-a", "/blocking-b"
	backendA, backendB string // e.g. "/ping-a", "/ping-b"
	minClean           int    // required clean chains per side (hard gate)
}

// TestRustTokioProbeDiscrimination distinguishes the Tokio implementation from
// OBI's generic context propagation. Unlike TestRustTokioContextPropagation (which
// asserts ≥1 complete chain and so passes on the generic path alone), it drives
// concurrent A/B load across distinct backends and counts how many chains are
// cleanly attributed. With the Tokio probes attached each cross-thread call is
// attributed by per-task identity -> many clean chains; with them detached the
// generic path cannot follow the cross-thread boundary -> clean chains collapse.
//
// Two scenarios:
//   - spawn_blocking (/blocking-a->/ping-a, /blocking-b->/ping-b): the closure ALWAYS
//     runs on a blocking-pool thread that never handled the inbound request, so the
//     generic baseline is ~0 clean. This is a hard pass(probes)/fail(no-probes)
//     discriminator (minClean=20; measured probes-on ≈ 60–140, probes-off ≈ 3–5).
//   - async spawn (/ws-spawn-a->/ping-c, /ws-spawn-b->/ping-d): tokio::spawn +
//     yield_now under load, so the child is frequently stolen by another worker
//     (measured 57% migration). It also turns out the generic path can't correlate
//     even NON-migrated async requests, because reqwest's async I/O egress runs on
//     the runtime's I/O worker, decoupled from the handler thread. So the baseline
//     collapses like spawn_blocking (measured probes-on ≈ 98/98, probes-off ≈ 2/4),
//     and this is a hard discriminator too (minClean=20).
func TestRustTokioProbeDiscrimination(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust-tokio-discrim.yml",
		path.Join(pathOutput, "test-suite-rust-tokio-discrim.log"))
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	t.Cleanup(func() { _ = compose.Close() })

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(tokioServerURL + "/health")
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, time.Second)

	t.Run("spawn_blocking", func(t *testing.T) {
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/blocking-a", serverB: "/blocking-b",
			backendA: "/ping-a", backendB: "/ping-b",
			minClean: 20,
		})
	})
	t.Run("async_spawn", func(t *testing.T) {
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-spawn-a", serverB: "/ws-spawn-b",
			backendA: "/ping-c", backendB: "/ping-d",
			// Lower bar than spawn_blocking: async HTTP egress runs on hyper's
			// connection-driver task, which the ancestry walk often can't reach, so a
			// large share of async egresses fall through to the racy process-level
			// fallback (observed ~160 fallback hits under this A/B burst). That makes
			// the clean-chain count genuinely variable run-to-run (measured 14–92 with
			// probes on) — but still far above the probes-off baseline (~2–4, since the
			// process-level fallback only exists WITH the Tokio probes). 10 stays below
			// the observed floor yet ≥2.5× the baseline, so it still discriminates.
			minClean: 10,
		})
	})
}

// tokioABDiscrimination drives case c and asserts ≥ c.minClean cleanly-attributed
// chains on each side. It always logs the full breakdown so probes-on and
// probes-off runs can be compared.
func tokioABDiscrimination(t *testing.T, c tokioABCase) {
	// Phase 1: drive light load until server traces are flowing (do NOT require
	// clean chains — probes-off must reach Phase 3 so it logs its breakdown).
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		driveTokioAB(c.serverA, c.serverB, 2)
		require.GreaterOrEqual(ct, len(tokioQueryServerTraces(ct, 400)), 10,
			"no server traces yet (OBI not attached?)")
	}, testTimeout, time.Second)

	// Phase 2: sustained concurrent A/B burst.
	driveTokioABConcurrent(t, c.serverA, c.serverB, 150, 20)

	// Phase 3: wait for the burst traces to export, then classify once and assert.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.GreaterOrEqual(ct, len(tokioQueryServerTraces(ct, 600)), 50,
			"waiting for burst traces to export")
	}, testTimeout, time.Second)

	cleanA, cleanB, contaminated, other := tokioClassifyAB(tokioQueryServerTracesT(t, 600), c)
	t.Logf("A/B discrimination [%s vs %s]: cleanA=%d cleanB=%d contaminated=%d other(incomplete)=%d",
		c.serverA, c.serverB, cleanA, cleanB, contaminated, other)

	require.GreaterOrEqualf(t, cleanA, c.minClean,
		"only %d clean A chains (need ≥%d) — Tokio probes not correlating %s; "+
			"contaminated=%d other=%d", cleanA, c.minClean, c.serverA, contaminated, other)
	require.GreaterOrEqualf(t, cleanB, c.minClean,
		"only %d clean B chains (need ≥%d) — Tokio probes not correlating %s; "+
			"contaminated=%d other=%d", cleanB, c.minClean, c.serverB, contaminated, other)
}

// driveTokioAB fires n sequential requests to each of serverA and serverB.
func driveTokioAB(serverA, serverB string, n int) {
	for i := 0; i < n; i++ {
		for _, p := range []string{serverA, serverB} {
			if resp, err := http.Get(tokioServerURL + p); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
}

// driveTokioABConcurrent fires perEndpoint requests to each of serverA and serverB,
// interleaved, with at most `concurrency` in flight at once.
func driveTokioABConcurrent(t *testing.T, serverA, serverB string, perEndpoint, concurrency int) {
	t.Helper()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < perEndpoint; i++ {
		for _, p := range []string{serverA, serverB} {
			wg.Add(1)
			sem <- struct{}{}
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()
				if resp, err := http.Get(tokioServerURL + p); err == nil {
					_ = resp.Body.Close()
				}
			}(p)
		}
	}
	wg.Wait()
}

// tokioQueryServerTraces returns all traces that contain a `server` span (CollectT
// variant, for use inside EventuallyWithT).
func tokioQueryServerTraces(ct *assert.CollectT, limit int) []jaeger.Trace {
	jr, err := http.Get(fmt.Sprintf("%s?service=server&lookback=1h&limit=%d", jaegerQueryURL, limit))
	require.NoError(ct, err)
	defer jr.Body.Close()
	require.Equal(ct, http.StatusOK, jr.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(jr.Body).Decode(&tq))
	return tq.Data
}

// tokioQueryServerTracesT is the *testing.T variant for the one-shot final query.
func tokioQueryServerTracesT(t *testing.T, limit int) []jaeger.Trace {
	t.Helper()
	jr, err := http.Get(fmt.Sprintf("%s?service=server&lookback=1h&limit=%d", jaegerQueryURL, limit))
	require.NoError(t, err)
	defer jr.Body.Close()
	require.Equal(t, http.StatusOK, jr.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(jr.Body).Decode(&tq))
	return tq.Data
}

// tokioClassifyAB buckets each trace (for the given case c) as a clean A chain, a
// clean B chain, cross-contaminated (containing both A and B markers — only
// possible via misattribution, since each server endpoint is wired to a distinct
// backend path), or other (incomplete: a server span with no joined backend span,
// i.e. the outgoing call was not correlated at all). Traces belonging to the other
// subtest's endpoints match none of c's markers and fall into `other` harmlessly.
func tokioClassifyAB(traces []jaeger.Trace, c tokioABCase) (cleanA, cleanB, contaminated, other int) {
	for i := range traces {
		tr := traces[i]
		aServer := len(tokioFindSpans(tr, "server", "server", c.serverA)) > 0
		bServer := len(tokioFindSpans(tr, "server", "server", c.serverB)) > 0
		aBackend := len(tokioFindSpans(tr, "backend", "server", c.backendA)) > 0
		bBackend := len(tokioFindSpans(tr, "backend", "server", c.backendB)) > 0

		hasA := aServer || aBackend
		hasB := bServer || bBackend
		switch {
		case hasA && hasB:
			contaminated++
		case aServer && aBackend:
			cleanA++
		case bServer && bBackend:
			cleanB++
		default:
			other++
		}
	}
	return cleanA, cleanB, contaminated, other
}
