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

// tokioDebugBuild reports whether the compose built the Rust app with CARGO_PROFILE=debug:
// release correlates through the Header walk, debug through the id walk.
func tokioDebugBuild() bool {
	return os.Getenv("CARGO_PROFILE") == "debug"
}

const (
	tokioServerURL     = "http://localhost:8092"
	tokioSyncServerURL = "http://localhost:8095" // the axum server's std-thread listener
)

// tokioOBILogLines covers the whole OBI log of a suite (a few thousand lines).
const tokioOBILogLines = 200_000

// tokioExecutables is how many executables the suites expect OBI to resolve the Tokio
// poll path for: the server and the backend. The second backend process shares the
// executable, and uprobes attach per file.
const tokioExecutables = 2

// tokioAnchorCounts counts the trust-window debug lines: anchors SET/CLEAR on the Header
// ("task") and id paths, Header SETs after the setter attached, registrations, releases.
type tokioAnchorCounts struct {
	taskSet, taskClear, idSet, idClear, taskSetAfterAttach int
	registered, released                                   int
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
		case strings.Contains(line, "tokio task_new:"):
			c.registered++
		case strings.Contains(line, "tokio task release:"):
			c.released++
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
	t.Logf("anchors: task SET=%d CLEAR=%d, id SET=%d CLEAR=%d, task SET after setter attach=%d; tasks registered=%d released=%d",
		c.taskSet, c.taskClear, c.idSet, c.idClear, c.taskSetAfterAttach, c.registered, c.released)

	require.Positive(t, c.set(), "no anchor was ever set: the server-span save never reached the tokio tag")

	// Every request's spawned tasks end within the request; connection tasks, pooled client
	// drivers and the runtime's own tasks outlive it, about half of the registrations in this
	// suite (57 of 105 released in release, 53 of 107 in debug). Without the completion
	// probe nothing is released at all, so a third is the floor.
	require.Positive(t, c.registered, "no task was registered")
	assert.GreaterOrEqual(t, c.released*3, c.registered,
		"only %d of %d registered tasks were released: the task-completion probe is not firing",
		c.released, c.registered)

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

	if obiFirst {
		// OBI runs before the app (START_DELAY): hold the first request until it has resolved
		// the poll path for both executables, or the order assertion below races the
		// backend's attach. The server attaches first and answers the health poll while the
		// backend's symbols are still being scanned, 2 ms apart in one run of eight.
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
			require.NoError(ct, err)
			resolved, _ := tokioPollPathResolutions(obiLog)
			require.GreaterOrEqual(ct, resolved, tokioExecutables,
				"the poll path is not resolved for both executables yet")
		}, testTimeout, time.Second)
	}

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

// assertTokioAttachedBeforeFirstRequest asserts from OBI's log that both executables
// resolved the poll path before the first server span was saved.
func assertTokioAttachedBeforeFirstRequest(t *testing.T, compose *docker.Compose) {
	t.Helper()
	obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
	require.NoError(t, err)

	resolved, bothResolved := tokioPollPathResolutions(obiLog)
	firstSave := -1
	for i, line := range strings.Split(obiLog, "\n") {
		if strings.Contains(line, "Saving connection server span") {
			firstSave = i
			break
		}
	}

	require.GreaterOrEqual(t, resolved, tokioExecutables, "the poll path was not resolved for both tokio processes")
	require.NotEqual(t, -1, firstSave, "no server span was saved")
	assert.Less(t, bothResolved, firstSave,
		"a server span was saved before both processes had their tokio probes attached (OBI-first order not achieved)")
}

// tokioPollPathResolutions counts the executables whose Harness::poll path OBI resolved in
// obiLog and returns the line at which the count reached tokioExecutables (-1 if never).
func tokioPollPathResolutions(obiLog string) (resolved, completedAt int) {
	completedAt = -1
	for i, line := range strings.Split(obiLog, "\n") {
		if strings.Contains(line, `msg="rust path resolved"`) &&
			strings.Contains(line, "path=tokio::runtime::task::harness::Harness::poll") {
			resolved++
			if resolved == tokioExecutables {
				completedAt = i
			}
		}
	}
	return resolved, completedAt
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

// anyCompleteTokioChain reports whether some trace holds the server span of urlPath, a
// client span to /ping and a backend server span to /ping that is CHILD_OF that client span.
func anyCompleteTokioChain(traces []jaeger.Trace, urlPath string) bool {
	for i := range traces {
		tr, _ := tokioUniqueSpans(traces[i])
		serverRoot := tokioFindSpans(tr, "server", urlPath)
		// Client spans carry the target as url.full, not url.path: match the /ping suffix.
		clientSpans := tokioFindClientSpans(tr, "/ping")
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

// tokioFindSpans returns the SERVER spans of service in tr, filtered by url.path when non-empty.
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

// tokioFindClientSpans returns the server service's CLIENT spans whose url.full ends with
// pathSuffix.
func tokioFindClientSpans(tr jaeger.Trace, pathSuffix string) []jaeger.Span {
	var out []jaeger.Span
	for _, s := range tr.Spans {
		if tr.Processes[s.ProcessID].ServiceName != "server" {
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
	// tolerateInFlightLeak drops the misattribution assertions (counts still logged): the
	// channel-handoff worker's in-flight residual, devdoc "Known Limitations".
	tolerateInFlightLeak bool
	// tolerateSameSidePile drops only the same-side piled assertion: the shared pooled
	// client's idle-connection residual, devdoc "Known Limitations".
	tolerateSameSidePile bool
	// beforeBurst runs between the warm-up and the concurrent burst, for a case that must
	// disturb the server first (the evicted-mailbox case refills the task map).
	beforeBurst func(t *testing.T)
	// perEndpoint is the burst length per side; 0 means tokioBurstPerEndpoint. A case whose
	// clean count sits near its floor at the default length drives more, so the floor is a
	// defect signal and not a timing one.
	perEndpoint int
}

// tokioBurstPerEndpoint is the default burst length per side, with tokioBurstConcurrency
// requests in flight at once.
const (
	tokioBurstPerEndpoint = 150
	tokioBurstConcurrency = 20
)

// TestRustTokioProbeDiscrimination drives concurrent A/B load across distinct backends and
// asserts a clean-chain floor where correlation is supported and zero misattribution
// everywhere. A cross-side backend span without its client span is the shared-ephemeral-
// port collision, logged not gated (tokioClassifyAB).
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

	t.Logf("rust app built with CARGO_PROFILE debug=%v", tokioDebugBuild())

	t.Run("spawn_blocking", func(t *testing.T) {
		// The egress runs on a blocking-pool thread that never handled the request: release
		// registers the blocking task at Spawner::spawn_task, debug walks the ids.
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
			// Fresh reqwest client per call: every connection driver is a child of the request task.
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
		// One process-wide reqwest client: a reused driver's lineage points at the request that
		// first used it, so only the safety half is asserted; coverage is logged.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/ws-pool-a", serverB: "/ws-pool-b",
			backendA: "/ping-g", backendB: "/ping-h",
			failClosed:           true,
			tolerateSameSidePile: true, // shared-client residual; cross-side stays strict
		})
	})
	t.Run("sync_threads", func(t *testing.T) {
		// The std-thread listener on 8095: a thread that never polls a task must keep its own
		// thread-keyed server span as the parent, in a process that also runs Tokio.
		tokioABDiscrimination(t, tokioABCase{
			serverURL: tokioSyncServerURL,
			serverA:   "/sync-a", serverB: "/sync-b",
			backendA: "/ping-m", backendB: "/ping-n",
			minClean: 20,
		})
	})
	runWeaverValidation(t)
}

// tokioABDiscrimination drives case c and asserts its contract; the breakdown is always logged.
func tokioABDiscrimination(t *testing.T, c tokioABCase) {
	serverURL := c.serverURL
	if serverURL == "" {
		serverURL = tokioServerURL
	}

	// Warm-up: light load until server traces flow.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		driveTokioAB(serverURL, c.serverA, c.serverB, 2)
		require.GreaterOrEqual(ct, len(tokioQueryServerTraces(ct, 400)), 10,
			"no server traces yet (OBI not attached?)")
	}, testTimeout, time.Second)

	if c.beforeBurst != nil {
		c.beforeBurst(t)
	}

	// Phase 2: sustained concurrent A/B burst.
	perEndpoint := c.perEndpoint
	if perEndpoint == 0 {
		perEndpoint = tokioBurstPerEndpoint
	}
	driveTokioABConcurrent(t, serverURL, c.serverA, c.serverB, perEndpoint, tokioBurstConcurrency)

	// Phase 3: classify inside the poll so the gate waits for enough clean chains to export
	// instead of judging one mid-export snapshot. The query limit must exceed the total
	// traces both subtests produce (they share one Jaeger, and every orphan is its own
	// trace), or the second subtest's clean chains never fit the window.
	const classifyLimit = 3000
	var cleanA, cleanB, contaminated, stray, piled, grouped, other, duplicates int
	var lastTraces []jaeger.Trace
	t.Cleanup(func() {
		t.Logf("A/B discrimination [%s vs %s]: cleanA=%d cleanB=%d contaminated(egress)=%d stray(backend-only)=%d piled(same-side)=%d grouped(inbound)=%d other(incomplete)=%d duplicates(exported twice)=%d",
			c.serverA, c.serverB, cleanA, cleanB, contaminated, stray, piled, grouped, other, duplicates)
		if contaminated+stray > 0 {
			tokioLogCrossSide(t, lastTraces, c)
		}
	})
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		lastTraces = tokioQueryServerTraces(ct, classifyLimit)
		cleanA, cleanB, contaminated, stray, piled, grouped, other, duplicates = tokioClassifyAB(lastTraces, c)
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

func driveTokioAB(serverURL, serverA, serverB string, n int) {
	for range n {
		for _, p := range []string{serverA, serverB} {
			if resp, err := http.Get(serverURL + p); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
}

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

// tokioQueryServerTraces returns up to limit traces holding a server span.
func tokioQueryServerTraces(ct *assert.CollectT, limit int) []jaeger.Trace {
	jr, err := http.Get(fmt.Sprintf("%s?service=server&lookback=1h&limit=%d", jaegerQueryURL, limit))
	require.NoError(ct, err)
	defer jr.Body.Close()
	require.Equal(ct, http.StatusOK, jr.StatusCode)

	var tq jaeger.TracesQuery
	require.NoError(ct, json.NewDecoder(jr.Body).Decode(&tq))
	return tq.Data
}

// tokioClassifyAB buckets each trace for case c: clean A, clean B, contaminated (one side's
// server span with the other side's CLIENT span: the walk resolved the wrong request), stray
// (the other side's BACKEND span only: OBI's same-host correlation colliding on a shared
// ephemeral port, devdoc "Known Limitations", logged not gated), piled (a same-side server
// span with more same-side backend spans than server spans: another request's egress
// resolved into this trace; an orphan with no server span lands in other), grouped (two
// endpoints in one trace with no cross backend: inbound keep-alive grouping) or other.
func tokioClassifyAB(traces []jaeger.Trace, c tokioABCase) (cleanA, cleanB, contaminated, stray, piled, grouped, other, duplicates int) {
	for i := range traces {
		tr, dups := tokioUniqueSpans(traces[i])
		duplicates += dups
		aServers := len(tokioFindSpans(tr, "server", c.serverA))
		bServers := len(tokioFindSpans(tr, "server", c.serverB))
		aBackends := len(tokioFindSpans(tr, "backend", c.backendA))
		bBackends := len(tokioFindSpans(tr, "backend", c.backendB))
		aServer, bServer := aServers > 0, bServers > 0
		aBackend, bBackend := aBackends > 0, bBackends > 0
		aClient := len(tokioFindClientSpans(tr, c.backendA)) > 0
		bClient := len(tokioFindClientSpans(tr, c.backendB)) > 0

		switch {
		// Cross-side egress: the client span carries the other side's trace.
		case (aServer && bClient) || (bServer && aClient):
			contaminated++
		// Cross-side backend span without its client span: the shared-port key, not the walk.
		case (aServer && bBackend) || (bServer && aBackend):
			stray++
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
	return cleanA, cleanB, contaminated, stray, piled, grouped, other, duplicates
}

// tokioLogCrossSide prints the first cross-side traces of a case, contaminated or stray,
// with every span and its start time (UTC, microseconds), so a wrong egress can be matched
// with OBI's walk lines at the same instant in the suite log.
func tokioLogCrossSide(t *testing.T, traces []jaeger.Trace, c tokioABCase) {
	t.Helper()
	const maxTraces = 5
	logged := 0
	for i := range traces {
		tr, _ := tokioUniqueSpans(traces[i])
		aServer := len(tokioFindSpans(tr, "server", c.serverA)) > 0
		bServer := len(tokioFindSpans(tr, "server", c.serverB)) > 0
		aBackend := len(tokioFindSpans(tr, "backend", c.backendA)) > 0
		bBackend := len(tokioFindSpans(tr, "backend", c.backendB)) > 0
		aClient := len(tokioFindClientSpans(tr, c.backendA)) > 0
		bClient := len(tokioFindClientSpans(tr, c.backendB)) > 0
		var kind string
		switch {
		case (aServer && bClient) || (bServer && aClient):
			kind = "contaminated"
		case (aServer && bBackend) || (bServer && aBackend):
			kind = "stray"
		default:
			continue
		}
		var b strings.Builder
		for _, s := range tr.Spans {
			fmt.Fprintf(&b, "\n    %s %s kind=%s path=%s start=%s dur=%dus",
				tr.Processes[s.ProcessID].ServiceName, s.OperationName, tokioSpanTag(s, "span.kind"),
				tokioSpanTag(s, "url.path"), time.UnixMicro(s.StartTime).UTC().Format("15:04:05.000000"), s.Duration)
		}
		t.Logf("%s trace %s:%s", kind, tr.TraceID, b.String())
		logged++
		if logged == maxTraces {
			return
		}
	}
}

// tokioUniqueSpans drops OBI's internal sub-spans and duplicate exports of one kernel record
// (OBI can export a record twice under load), returning the number dropped. A duplicate
// shares the kernel span ID, carried by the "processing" child when the request had queue
// time, else by the span itself.
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
