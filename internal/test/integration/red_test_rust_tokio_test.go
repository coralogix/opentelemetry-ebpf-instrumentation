// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// tokioDebugBuild reports whether the Rust app was built with CARGO_PROFILE=debug, the env
// var the compose build consumes. Release correlates through the Header walk, debug through
// the id walk; the suites assert the same floors in both and use this flag only where the
// builds differ. See devdocs/rust-tokio-context-propagation.md.
func tokioDebugBuild() bool {
	return os.Getenv("CARGO_PROFILE") == "debug"
}

const (
	tokioServerURL     = "http://localhost:8092"
	tokioSyncServerURL = "http://localhost:8095" // the axum server's std-thread listener
)

// tokioOBILogLines bounds the OBI log slice the trust-window check reads. The
// context-propagation suite emits a few thousand lines, so this is the whole log.
const tokioOBILogLines = 200_000

// tokioAnchorCounts are the kernel debug lines OBI emits when a task is anchored to an
// inbound request (SET) and released at its response (CLEAR), on the Header path
// ("task") and on the id path ("id"), plus the Header-path SETs seen after the id setter
// probe was attached.
type tokioAnchorCounts struct {
	taskSet, taskClear, idSet, idClear, taskSetAfterAttach int
}

func (c tokioAnchorCounts) set() int   { return c.taskSet + c.idSet }
func (c tokioAnchorCounts) clear() int { return c.taskClear + c.idClear }

func tokioParseAnchorCounts(obiLog string) tokioAnchorCounts {
	lines := strings.Split(obiLog, "\n")

	// Probes attach per process in no fixed order: a request served between the poll probe
	// and the setter attaching anchors through the Header path even in debug, so Header SETs
	// are judged only after the last setter attach.
	setterAttached := -1
	for i, line := range lines {
		if strings.Contains(line, `msg="going to instrument function"`) &&
			strings.Contains(line, "function=tokio::runtime::context::set_current_task_id") {
			setterAttached = i
		}
	}

	var c tokioAnchorCounts
	for i, line := range lines {
		switch {
		case strings.Contains(line, "tokio handler task conn SET"):
			c.taskSet++
			if setterAttached >= 0 && i > setterAttached {
				c.taskSetAfterAttach++
			}
		case strings.Contains(line, "tokio handler task conn CLEAR"):
			c.taskClear++
		case strings.Contains(line, "tokio handler id conn SET"):
			c.idSet++
		case strings.Contains(line, "tokio handler id conn CLEAR"):
			c.idClear++
		}
	}
	return c
}

// assertTokioTrustWindow checks from OBI's log what the traces cannot show: every anchor
// opened at a span save is closed at the response (with slack for requests in flight), and
// in debug the id path owns every anchor once the setter is attached. Not run by the
// discrimination suite, whose bursts overflow the debug ringbuf and drop lines.
func assertTokioTrustWindow(t *testing.T, compose *docker.Compose) {
	t.Helper()
	obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
	require.NoError(t, err)

	c := tokioParseAnchorCounts(obiLog)
	t.Logf("anchors: task SET=%d CLEAR=%d, id SET=%d CLEAR=%d, task SET after setter attach=%d",
		c.taskSet, c.taskClear, c.idSet, c.idClear, c.taskSetAfterAttach)

	require.Positive(t, c.set(), "no anchor was ever set: the server-span save never reached the tokio tag")

	const inFlightSlack = 2
	unclosed := c.set() - c.clear()
	if unclosed < 0 {
		unclosed = -unclosed
	}
	assert.LessOrEqual(t, unclosed, inFlightSlack,
		"anchors opened (%d) and closed (%d) diverge: the trust window is not closing at the response",
		c.set(), c.clear())

	if tokioDebugBuild() {
		require.Positive(t, c.idSet, "debug build anchored nothing through the id path")
		assert.Zero(t, c.taskSetAfterAttach,
			"debug build anchored %d task(s) through the Header path after the id setter attached",
			c.taskSetAfterAttach)
	}
}

// TestRustTokioContextPropagation drives the axum multi-thread server and asserts one
// complete server -> client -> backend chain per Tokio pattern: the backend's server span
// is a child of the server's client span.
func TestRustTokioContextPropagation(t *testing.T) {
	runTokioContextPropagation(t, "docker-compose-rust-tokio.yml", "test-suite-rust-tokio.log", false)
}

// TestRustTokioContextPropagationOBIFirst is the production order: OBI runs before the app
// starts (START_DELAY in the compose file), so the probes attach before the first request.
// Same checks as the default suite, plus the order itself asserted from OBI's log.
func TestRustTokioContextPropagationOBIFirst(t *testing.T) {
	runTokioContextPropagation(t, "docker-compose-rust-tokio-obi-first.yml", "test-suite-rust-tokio-obi-first.log", true)
}

func runTokioContextPropagation(t *testing.T, composeFile, logFile string, obiFirst bool) {
	compose, err := docker.ComposeSuite(composeFile, path.Join(pathOutput, logFile))
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
	// The blocking-pool thread never ran the handler: the chain holds only through the
	// task lineage (release registers the blocking task at Spawner::spawn_task, debug
	// walks the ids).
	t.Run("spawn_blocking", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/blocking")
	})
	t.Run("spawn + spawn_blocking", func(t *testing.T) {
		assertTokioCrossServiceTrace(t, "/blocking-nested")
	})
	if obiFirst {
		t.Run("OBI attached before the first request", func(t *testing.T) {
			assertTokioAttachedBeforeFirstRequest(t, compose)
		})
	}
	t.Run("trust window: anchors close at the response", func(t *testing.T) {
		assertTokioTrustWindow(t, compose)
	})
	runWeaverValidation(t)
}

// assertTokioAttachedBeforeFirstRequest checks, from OBI's log, that the tokio probes of
// both processes (server and backend) were resolved before OBI saved its first server
// span: the order the OBI-first suite exists to exercise.
func assertTokioAttachedBeforeFirstRequest(t *testing.T, compose *docker.Compose) {
	t.Helper()
	obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
	require.NoError(t, err)

	const tokioProcesses = 2 // server + backend
	resolved, bothResolved, firstSave := 0, -1, -1
	for i, line := range strings.Split(obiLog, "\n") {
		switch {
		case strings.Contains(line, `msg="rust path resolved"`) &&
			strings.Contains(line, "path=tokio::runtime::task::harness::Harness::poll"):
			resolved++
			if resolved == tokioProcesses {
				bothResolved = i
			}
		case firstSave < 0 && strings.Contains(line, "Saving connection server span"):
			firstSave = i
		}
	}

	require.GreaterOrEqual(t, resolved, tokioProcesses, "the poll path was not resolved for both tokio processes")
	require.NotEqual(t, -1, firstSave, "no server span was saved")
	assert.Less(t, bothResolved, firstSave,
		"a server span was saved before both processes had their tokio probes attached (OBI-first order not achieved)")
}

// assertTokioCrossServiceTrace drives sequential requests to urlPath until one trace shows
// the complete server -> backend chain; one is enough, a hard 100% would make the test
// flaky on a single timing miss.
func assertTokioCrossServiceTrace(t *testing.T, urlPath string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// One request per poll: load keeps flowing until OBI is attached.
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

		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: urlPath})
		require.NotEmpty(ct, traces, "no traces with url.path=%s yet", urlPath)

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
		tr, _ := tokioUniqueSpans(traces[i])
		serverRoot := tokioFindSpans(tr, "server", urlPath)
		// Client spans carry the target as url.full, not url.path: match the /ping suffix.
		clientSpans := tokioFindClientSpans(tr, "server", "/ping")
		backendSpans := tokioFindSpans(tr, "backend", "/ping")
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

// tokioFindSpans returns the SERVER spans in tr matching the given OBI service name
// and url.path tag (url.path is ignored when empty).
func tokioFindSpans(tr jaeger.Trace, service, urlPath string) []jaeger.Span {
	var out []jaeger.Span
	for _, s := range tr.Spans {
		if tr.Processes[s.ProcessID].ServiceName != service {
			continue
		}
		if tokioSpanTag(s, "span.kind") != "server" {
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

// tokioABCase is one A/B discrimination scenario. Each server endpoint is wired to its own
// backend path, so a trace holding both an A and a B marker can only come from
// misattribution, and the subtests never cross-classify each other's traces.
type tokioABCase struct {
	serverA, serverB   string // e.g. "/blocking-a", "/blocking-b"
	backendA, backendB string // e.g. "/ping-a", "/ping-b"
	serverURL          string // base URL of the server endpoints; tokioServerURL when empty
	minClean           int    // required clean chains per side (hard gate); unused when failClosed
	// failClosed is for a shape OBI does not correlate: no clean-chain floor, zero
	// misattribution required instead (orphans are expected, a wrong span is a defect).
	failClosed bool
	// tolerateInFlightLeak drops the misattribution assertions (counts still logged). Only
	// for the channel-handoff worker: while its spawning request is in flight it serves
	// other requests' jobs under a legitimately matching epoch, and the runtime carries no
	// signal for whose job it is. See the devdoc Known Limitations.
	tolerateInFlightLeak bool
	// tolerateSameSidePile drops only the same-side piled assertion (cross-side stays
	// strict). For the shared pooled client: a driver whose establishing inbound connection
	// went idle keeps that request's anchor epoch and resolves it for later requests of the
	// same endpoint. See the devdoc Known Limitations.
	tolerateSameSidePile bool
	// beforeBurst runs between the warm-up and the concurrent burst, for a case that must
	// disturb the server first (the evicted-mailbox case refills the task map).
	beforeBurst func(t *testing.T)
}

// TestRustTokioProbeDiscrimination drives concurrent A/B load across distinct backends and
// counts cleanly attributed chains per side. It asserts both halves of the contract: a
// clean-chain floor where correlation is supported, and zero misattribution everywhere,
// cross-side (contaminated) and same-side (piled). Without the Tokio probes the generic
// path cannot follow a cross-thread egress and the clean chains collapse.
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

	// Logged so a failure report says which build it was.
	t.Logf("rust app built with CARGO_PROFILE debug=%v", tokioDebugBuild())

	t.Run("spawn_blocking", func(t *testing.T) {
		// The egress runs on a blocking-pool thread that never handled the request, so a
		// floor here proves the lineage: in release the blocking task is registered at
		// Spawner::spawn_task under the request task (its Cell::new copy is inlined), in
		// debug the id walk resolves it.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/blocking-a", serverB: "/blocking-b",
			backendA: "/ping-a", backendB: "/ping-b",
			minClean: 20,
		})
	})
	t.Run("direct_egress", func(t *testing.T) {
		// The spawned task writes its own TcpStream: the egress runs while the per-request
		// task is current, so both builds correlate it.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-direct-a", serverB: "/ws-direct-b",
			backendA: "/ping-e", backendB: "/ping-f",
			minClean: 20,
		})
	})
	t.Run("async_spawn", func(t *testing.T) {
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-spawn-a", serverB: "/ws-spawn-b",
			backendA: "/ping-c", backendB: "/ping-d",
			// Fresh reqwest client per call: every connection-driver task is first-use and
			// a child of the request task, so both builds correlate it. The floor sits far
			// below the measured counts.
			minClean: 20,
		})
	})
	t.Run("channel_handoff", func(t *testing.T) {
		// One long-lived worker task serves both sides over an mpsc channel and does the
		// egress itself: any stale lineage on it crosses the A/B boundary. Every worker
		// egress after its spawning request fails closed on the epoch guard.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-chan-a", serverB: "/ws-chan-b",
			backendA: "/ping-i", backendB: "/ping-j",
			failClosed:           true,
			tolerateInFlightLeak: true, // in-flight-window residual, see the field doc
		})
	})
	t.Run("pooled_reuse", func(t *testing.T) {
		// One process-wide reqwest client: concurrent A/B requests reuse keep-alive
		// connections and their long-lived driver tasks. A driver's lineage points at the
		// request that first used it; resolving through it later must fail closed, so only
		// the safety half is asserted and coverage is logged.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-pool-a", serverB: "/ws-pool-b",
			backendA: "/ping-g", backendB: "/ping-h",
			failClosed:           true,
			tolerateSameSidePile: true, // shared-client residual; cross-side stays strict
		})
	})
	t.Run("sync_threads", func(t *testing.T) {
		// The server's std-thread listener on 8095: the request is read and the backend
		// called on a thread that never polls a task. The process runs Tokio, so the task
		// walks own its runtime threads, but this thread must keep its own thread-keyed
		// server span as the parent, as it did before the Tokio probes existed.
		tokioABDiscrimination(t, tokioABCase{
			serverURL: tokioSyncServerURL,
			serverA:   "/sync-a", serverB: "/sync-b",
			backendA: "/ping-m", backendB: "/ping-n",
			minClean: 20,
		})
	})
	runWeaverValidation(t)
}

// tokioABDiscrimination drives case c and asserts ≥ c.minClean cleanly-attributed
// chains on each side. It always logs the full breakdown so probes-on and
// probes-off runs can be compared.
func tokioABDiscrimination(t *testing.T, c tokioABCase) {
	serverURL := c.serverURL
	if serverURL == "" {
		serverURL = tokioServerURL
	}

	// Phase 1: drive light load until server traces are flowing (do NOT require
	// clean chains — probes-off must reach Phase 3 so it logs its breakdown).
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		driveTokioAB(serverURL, c.serverA, c.serverB, 2)
		require.GreaterOrEqual(ct, len(tokioQueryServerTraces(ct, 400)), 10,
			"no server traces yet (OBI not attached?)")
	}, testTimeout, time.Second)

	if c.beforeBurst != nil {
		c.beforeBurst(t)
	}

	// Phase 2: sustained concurrent A/B burst.
	driveTokioABConcurrent(t, serverURL, c.serverA, c.serverB, 150, 20)

	// Phase 3: classify inside the poll so the gate waits for enough clean chains to export
	// instead of judging one mid-export snapshot. The query limit must exceed the total
	// traces both subtests produce (they share one Jaeger, and every orphan is its own
	// trace), or the second subtest's clean chains never fit the window.
	const classifyLimit = 3000
	var cleanA, cleanB, contaminated, piled, grouped, other, duplicates int
	t.Cleanup(func() {
		t.Logf("A/B discrimination [%s vs %s]: cleanA=%d cleanB=%d contaminated(egress)=%d piled(same-side)=%d grouped(inbound)=%d other(incomplete)=%d duplicates(exported twice)=%d",
			c.serverA, c.serverB, cleanA, cleanB, contaminated, piled, grouped, other, duplicates)
	})
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		cleanA, cleanB, contaminated, piled, grouped, other, duplicates = tokioClassifyAB(tokioQueryServerTraces(ct, classifyLimit), c)
		if c.failClosed {
			// Wait until the burst has exported, so this cannot pass before traffic flows,
			// then require zero misattribution, cross-side and same-side.
			require.GreaterOrEqualf(ct, cleanA+cleanB+contaminated+other, 100,
				"blocking traces not exported yet (total=%d)", cleanA+cleanB+contaminated+other)
			if c.tolerateInFlightLeak {
				// Counts logged via t.Cleanup, nothing gated: see the field doc.
				return
			}
			require.Zerof(ct, contaminated,
				"fail-closed case %s/%s misattributed %d chains (cleanA=%d cleanB=%d other=%d)",
				c.serverA, c.serverB, contaminated, cleanA, cleanB, other)
			if !c.tolerateSameSidePile {
				require.Zerof(ct, piled,
					"fail-closed case %s/%s produced %d same-side piled traces (a later request's "+
						"egress resolved an earlier request's trace)", c.serverA, c.serverB, piled)
			}
			return
		}
		require.GreaterOrEqualf(ct, cleanA, c.minClean,
			"only %d clean A chains (need ≥%d) — Tokio probes not correlating %s; "+
				"contaminated=%d other=%d", cleanA, c.minClean, c.serverA, contaminated, other)
		require.GreaterOrEqualf(ct, cleanB, c.minClean,
			"only %d clean B chains (need ≥%d) — Tokio probes not correlating %s; "+
				"contaminated=%d other=%d", cleanB, c.minClean, c.serverB, contaminated, other)
		// Supported shapes must also never misattribute: a wrong parent propagates
		// downstream, so zero is the only acceptable count.
		require.Zerof(ct, contaminated,
			"%s/%s produced %d misattributed chains (cleanA=%d cleanB=%d)",
			c.serverA, c.serverB, contaminated, cleanA, cleanB)
		require.Zerof(ct, piled,
			"%s/%s produced %d same-side piled traces (a later request's egress resolved "+
				"an earlier request's trace)", c.serverA, c.serverB, piled)
	}, testTimeout, time.Second)
}

// driveTokioAB fires n sequential requests to each of serverA and serverB.
func driveTokioAB(serverURL, serverA, serverB string, n int) {
	for range n {
		for _, p := range []string{serverA, serverB} {
			if resp, err := http.Get(serverURL + p); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
}

// driveTokioABConcurrent fires perEndpoint requests to each of serverA and serverB,
// interleaved, with at most `concurrency` in flight at once.
func driveTokioABConcurrent(t *testing.T, serverURL, serverA, serverB string, perEndpoint, concurrency int) {
	t.Helper()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for range perEndpoint {
		for _, p := range []string{serverA, serverB} {
			wg.Add(1)
			sem <- struct{}{}
			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()
				if resp, err := http.Get(serverURL + p); err == nil {
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

// tokioClassifyAB buckets each trace for case c: clean A, clean B, contaminated (both an A
// and a B marker, only possible by misattribution), piled, grouped (two server endpoints in
// one trace with no cross backend: inbound keep-alive grouping, not an egress error) or
// other (incomplete, or another subtest's endpoints).
//
// piled is the same-side temporal misattribution the A/B split is blind to: a trace that
// holds a same-side server span and more same-side backend spans than server spans. Each
// endpoint makes one backend call per request, so a surplus backend span is another
// request's egress resolved into this trace. The same-side server span is required: a
// fail-closed egress is an orphan trace (a backend span with no owning server span) and
// must land in other, not piled.
func tokioClassifyAB(traces []jaeger.Trace, c tokioABCase) (cleanA, cleanB, contaminated, piled, grouped, other, duplicates int) {
	for i := range traces {
		tr, dups := tokioUniqueSpans(traces[i])
		duplicates += dups
		aServers := len(tokioFindSpans(tr, "server", c.serverA))
		bServers := len(tokioFindSpans(tr, "server", c.serverB))
		aBackends := len(tokioFindSpans(tr, "backend", c.backendA))
		bBackends := len(tokioFindSpans(tr, "backend", c.backendB))
		aServer, bServer := aServers > 0, bServers > 0
		aBackend, bBackend := aBackends > 0, bBackends > 0

		switch {
		// Cross-side: the egress carried the wrong traceparent.
		case (aServer && bBackend) || (bServer && aBackend):
			contaminated++
		// Same-side surplus with the owning server span present.
		case (aServer && aBackends > aServers) || (bServer && bBackends > bServers):
			piled++
		// Inbound grouping, not an egress error.
		case aServer && bServer:
			grouped++
		case aServer && aBackend:
			cleanA++
		case bServer && bBackend:
			cleanB++
		default:
			other++
		}
	}
	return cleanA, cleanB, contaminated, piled, grouped, other, duplicates
}

// tokioUniqueSpans drops duplicate exports of one kernel record (first kept) and OBI's
// internal sub-spans, returning the number dropped. OBI can export one record twice under
// load (the kernel's submitted check is not atomic across the close and delayed-finish
// paths); counted per side, a duplicated backend span would read as a pile. The copies do
// not share a span ID when the request had queue time: the exporter gives the top-level
// span a random ID and puts the kernel ID on its "processing" child, so identity is the
// kernel ID recovered from that child, or the span's own ID.
func tokioUniqueSpans(tr jaeger.Trace) (jaeger.Trace, int) {
	kernelID := make(map[string]string, len(tr.Spans)) // top-level span ID -> kernel span ID
	for _, s := range tr.Spans {
		if s.OperationName == "processing" {
			kernelID[childOfParent(s)] = s.SpanID
		}
	}

	seen := make(map[string]struct{}, len(tr.Spans))
	unique := make([]jaeger.Span, 0, len(tr.Spans))
	dropped := 0
	for _, s := range tr.Spans {
		if s.OperationName == "processing" || s.OperationName == "in queue" {
			continue
		}
		id := s.SpanID
		if k, ok := kernelID[s.SpanID]; ok {
			id = k
		}
		if _, dup := seen[id]; dup {
			dropped++
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, s)
	}
	out := tr
	out.Spans = unique
	return out, dropped
}

// TestRustTokioRuntimeDisabled runs the same app with capture.runtimes.rust.enabled: false
// (Config v2, the only place the knob exists): no Tokio path is resolved, no poll fires, and
// the generic tracing still exports the server spans.
func TestRustTokioRuntimeDisabled(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust-tokio-off.yml", path.Join(pathOutput, "test-suite-rust-tokio-off.log"))
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

	// One request per poll until a server span is exported: the generic tracer still
	// instruments the process.
	const urlPath = "/ws-spawn"
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(tokioServerURL + urlPath)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		traces := tokioQueryServerTraces(ct, 50)
		var servers []jaeger.Span
		for i := range traces {
			servers = append(servers, tokioFindSpans(traces[i], "server", urlPath)...)
		}
		require.NotEmpty(ct, servers, "no server span for %s yet", urlPath)
	}, testTimeout, time.Second)

	obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
	require.NoError(t, err)
	assert.Contains(t, obiLog, "Saving connection server span", "the generic tracer did not see the requests")
	assert.NotContains(t, obiLog, `msg="rust path resolved"`, "a Tokio path was resolved with the Rust runtime off")
	assert.NotContains(t, obiLog, "tokio poll_future entry", "a Tokio probe fired with the Rust runtime off")
}
