// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// tokioMailboxEvictFills bounds how many fills mailbox_evicted runs before it calls a
// surviving mailbox a defect. One fill misses when the mailbox's LRU node is pending in the
// local list of the CPU that registered it (one run in about seventeen).
const tokioMailboxEvictFills = 3

// TestRustTokioCurrentThread drives the actix-web server: one current-thread Tokio runtime
// per worker, so no task ever migrates. OBI still resolves a Tokio process only through the
// task walks, so this suite proves they carry the shapes a current-thread app uses, with
// the same floor and zero-misattribution contract as the work-stealing suite.
func TestRustTokioCurrentThread(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-rust-tokio-actix.yml",
		path.Join(pathOutput, "test-suite-rust-tokio-actix.log"))
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

	t.Run("direct", func(t *testing.T) {
		// The handler future is polled inside the per-connection dispatcher task the inbound
		// request was anchored on: the egress resolves at depth 0.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/direct-a", serverB: "/direct-b",
			backendA: "/ping-a", backendB: "/ping-b",
			minClean: 20,
		})
	})
	t.Run("spawn", func(t *testing.T) {
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/spawn-a", serverB: "/spawn-b",
			backendA: "/ping-c", backendB: "/ping-d",
			minClean: 20,
		})
	})
	t.Run("spawn_local", func(t *testing.T) {
		// LocalSet tasks: the egress is a raw write on the child task itself. The clean
		// count varies most here (22 to 152 per side across runs at the default length):
		// a longer burst keeps the floor a defect signal.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/local-a", serverB: "/local-b",
			backendA: "/ping-e", backendB: "/ping-f",
			minClean:    20,
			perEndpoint: 2 * tokioBurstPerEndpoint,
		})
	})
	t.Run("nested", func(t *testing.T) {
		// spawn_local, then tokio::spawn inside it: a depth-2 lineage mixing both kinds.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/nested-a", serverB: "/nested-b",
			backendA: "/ping-g", backendB: "/ping-h",
			minClean: 20,
		})
	})
	t.Run("pooled_reuse", func(t *testing.T) {
		// One reqwest client across the worker runtimes: a driver task opened on one worker
		// serves later requests from the others, and its lineage points at the request that
		// opened it. Only the safety half is asserted; coverage is logged.
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/pool-a", serverB: "/pool-b",
			backendA: "/ping-i", backendB: "/ping-j",
			failClosed:           true,
			tolerateSameSidePile: true,
		})
	})
	t.Run("mailbox_evicted", func(t *testing.T) {
		// A long-lived LocalSet mailbox whose map entry the fill evicts: its next wake comes from
		// inside a request's handler and must not adopt that request as parent, or every later job
		// resolves it. Its jobs orphan (release) or miss the id entry (debug): fail closed both ways.
		fill := func(t *testing.T) {
			resp, err := http.Get(tokioServerURL + "/evict-fill")
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		}
		// The first fill spawns the mailbox, so the poll probe must already fire: the health
		// check only proves the server is up, and a mailbox spawned before OBI attached is
		// never registered nor counted.
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := http.Get(tokioServerURL + "/health")
			require.NoError(ct, err)
			_ = resp.Body.Close()
			obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
			require.NoError(ct, err)
			require.Contains(ct, obiLog, "tokio poll_future entry", "the Tokio poll probe has not fired yet")
		}, testTimeout, time.Second)
		fill(t)
		tokioABDiscrimination(t, tokioABCase{
			serverA: "/mbox-a", serverB: "/mbox-b",
			backendA: "/ping-k", backendB: "/ping-l",
			failClosed: true,
			beforeBurst: func(t *testing.T) {
				// Require the guard to have fired (origin=3: a task re-registered at a wake with no
				// parent), since zero misattribution also holds when nothing was evicted. Checked
				// before the second fill: the re-registered entry sits in the registering CPU's local
				// LRU list until that CPU allocates 128 more nodes, so a later fill evicts it only by
				// chance, and a fill after the worker moved CPU evicts nothing. Fill and wake again a
				// few times before giving up.
				for attempt := 1; ; attempt++ {
					obiLog, err := compose.LogsTail(tokioOBILogLines, "obi")
					require.NoError(t, err)
					if strings.Contains(obiLog, "origin=3") {
						break
					}
					require.Less(t, attempt, tokioMailboxEvictFills,
						"no task was re-registered at a wake without a parent: %d fills did not evict the mailbox", attempt)
					fill(t)
					driveTokioAB(tokioServerURL, "/mbox-a", "/mbox-b", 1) // wake the mailbox
				}
				fill(t) // evict the mailbox again before the burst
			},
		})
	})
	runWeaverValidation(t)
}
