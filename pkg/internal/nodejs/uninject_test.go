// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

// The uninstall pass is both agent scripts with every gate left off: each
// prologue tears down the previous injection and the gated bodies are then
// skipped. A gate that ever defaults to on would turn the uninstall into a
// reinstall.
func TestUninstallCodeLeavesEveryGateOff(t *testing.T) {
	code := uninstallCode()

	require.Contains(t, code, rtEnabledPlaceholder)
	require.Contains(t, code, tracesEnabledPlaceholder)
	require.Contains(t, code, spansEnabledPlaceholder)
	require.NotContains(t, code, rtEnabledOn)
	require.NotContains(t, code, tracesEnabledOn)
	require.NotContains(t, code, spansEnabledOn)
}

// The uninstall pass must carry the bridge too, otherwise a manual-spans
// deployment leaves it resident.
func TestUninstallCodeIncludesSpanBridge(t *testing.T) {
	require.Contains(t, uninstallCode(), "__obiSpanBridge")
}

// The bridge only ships when manual spans are on, and it ships with its gate
// substituted: an unsubstituted gate would install nothing at all.
func TestAgentCodeGatesSpanBridge(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.NodeJS.ManualSpans = false
	require.NotContains(t, NewNodeInjector(&cfg).agentCode(), "__obiSpanBridge")

	cfg.NodeJS.ManualSpans = true
	code := NewNodeInjector(&cfg).agentCode()
	require.Contains(t, code, "__obiSpanBridge")
	require.Contains(t, code, spansEnabledOn)
	require.NotContains(t, code, spansEnabledPlaceholder)
}

// The set is drained whatever happens to the individual processes, so a process
// that has since exited cannot be retried or signaled twice.
func TestUninjectAllDrainsTheSet(t *testing.T) {
	cfg := obi.DefaultConfig

	i := NewNodeInjector(&cfg)
	i.injected[4242] = 99

	i.UninjectAll(time.Now())

	require.Empty(t, i.injected)
}

// testAdmissionWindow is how long these tests leave the pass to admit targets
// in. testShutdownTimeout derives the setting that produces it, so they stay
// honest if the slices of the allowance change.
const testAdmissionWindow = 100 * time.Millisecond

func testShutdownTimeout() time.Duration {
	return (uninjectCommitTail + testAdmissionWindow) * uninjectAllowanceShare
}

// countingHandles is a stand-in handle constructor that takes work while
// refusing every process, so a target can be counted and made slow without a
// real one behind it.
//
// It is handed to one injector rather than swapped into the package variable:
// a pass that abandons its workers leaves them running past the test, and
// restoring a global underneath them is a data race the test cannot close.
func countingHandles(work time.Duration) (func(app.PID, uint64) (*procs.ProcessHandle, error), *atomic.Int64) {
	open, started, _ := countingHandlesDone(work)

	return open, started
}

// countingHandlesDone also counts the workers that ran to completion, so a
// test can tell a target that finished from one the pass walked away from.
func countingHandlesDone(work time.Duration) (func(app.PID, uint64) (*procs.ProcessHandle, error), *atomic.Int64, *atomic.Int64) {
	var started, finished atomic.Int64

	open := func(pid app.PID, _ uint64) (*procs.ProcessHandle, error) {
		started.Add(1)
		time.Sleep(work)
		finished.Add(1)

		return nil, fmt.Errorf("opening process %d: refused by test", pid)
	}

	return open, &started, &finished
}

// Admission holds back a whole committed tail, so every target taken up has
// time to finish before the pass returns. A target still mid-handshake when
// UninjectAll returns is killed by the exiting process with the debugger port
// it reopened still listening — the one outcome this design must not produce.
func TestUninjectAllLetsAdmittedTargetsFinish(t *testing.T) {
	const perWork = 200 * time.Millisecond

	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = testShutdownTimeout()

	open, started, finished := countingHandlesDone(perWork)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30200; pid++ {
		i.injected[pid] = 99
	}

	i.UninjectAll(time.Now())

	require.Positive(t, started.Load(), "no target was taken up at all")
	require.Equal(t, started.Load(), finished.Load(),
		"the pass returned with a target still being worked on")
}

// Admission stops while a whole committed tail still fits, so the loop cannot
// work through every one of these targets: at this concurrency that would take
// far longer than the allowance.
func TestUninjectAllStopsAdmittingAtTheAllowance(t *testing.T) {
	const (
		perWork = 30 * time.Millisecond
		targets = 200
	)

	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = testShutdownTimeout()

	open, started := countingHandles(perWork)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30000+targets; pid++ {
		i.injected[pid] = 99
	}

	i.UninjectAll(time.Now())

	require.Empty(t, i.injected)

	// What the budget can pay for, generously rounded up: anything near the
	// full set means the loop ran to completion regardless of it.
	reachable := int64(testAdmissionWindow/perWork+1) * uninjectConcurrency
	require.Less(t, started.Load(), reachable*2,
		"the dispatch loop kept admitting targets past the allowance")
}

// A started target is committed: its inspector may already be reopened, and
// only the handshake closes it again. Returning when the budget expires would
// leave that work to be killed by the exiting process, so the pass waits for
// the workers it started.
func TestUninjectAllWaitsForTheTargetsItStarted(t *testing.T) {
	const perWork = 300 * time.Millisecond

	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = testShutdownTimeout()

	open, started := countingHandles(perWork)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30008; pid++ {
		i.injected[pid] = 99
	}

	begin := time.Now()
	i.UninjectAll(time.Now())
	elapsed := time.Since(begin)

	require.Positive(t, started.Load(), "no target was started at all")
	require.GreaterOrEqual(t, elapsed, perWork,
		"UninjectAll returned while a started target was still being worked on")
}

// The allowance is the only budgeted quantity: every deadline inside the pass
// is carved out of it, so the pass itself must never outlive it. Asserting
// against half the shutdown timeout rather than the whole of it is the point —
// the rest of the shutdown path runs on the same clock.
func TestUninjectAllReturnsInsideItsAllowance(t *testing.T) {
	// A subtest each: this pass deliberately abandons its workers, so they
	// outlive it. Their stub has to be released and waited for before the next
	// case installs its own, which is what t.Cleanup gives per subtest.
	for _, shutdown := range []time.Duration{
		testShutdownTimeout(),
		obi.DefaultConfig.ShutdownTimeout,
	} {
		t.Run(shutdown.String(), func(t *testing.T) {
			cfg := obi.DefaultConfig
			cfg.ShutdownTimeout = shutdown

			allowance := cfg.ShutdownTimeout / uninjectAllowanceShare

			// Longer than the pass may take, so the workers never end it early.
			open, _ := countingHandles(2 * cfg.ShutdownTimeout)

			i := NewNodeInjector(&cfg)
			i.openHandle = open
			for pid := app.PID(30000); pid < 30100; pid++ {
				i.injected[pid] = 99
			}

			begin := time.Now()
			i.UninjectAll(time.Now())
			elapsed := time.Since(begin)

			require.LessOrEqual(t, elapsed, allowance+500*time.Millisecond,
				"the pass outlived its allowance at shutdown_timeout %v", shutdown)
		})
	}
}

// warnCounter counts warnings without asserting on their wording, which is the
// only part of a log line worth pinning here.
type warnCounter struct {
	warns atomic.Int64
}

func (h *warnCounter) Enabled(context.Context, slog.Level) bool { return true }

func (h *warnCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.warns.Add(1)
	}

	return nil
}

func (h *warnCounter) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *warnCounter) WithGroup(string) slog.Handler { return h }

// An allowance too small to hold one target's work buys nothing by starting
// it. Nothing may be signaled, and the reason is reported once for the
// configuration rather than once per process: on a node running many Node.js
// services the per-process form buries it.
func TestUninjectAllStartsNothingWithoutAllowance(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = uninjectCommitTail

	open, started := countingHandles(0)
	logs := &warnCounter{}

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	i.log = slog.New(logs)

	for pid := app.PID(30000); pid < 30050; pid++ {
		i.injected[pid] = 99
	}

	i.UninjectAll(time.Now())

	require.Zero(t, started.Load(), "a target was started with no budget to finish it")
	require.Empty(t, i.injected)
	require.EqualValues(t, 1, logs.warns.Load(),
		"a shutdown timeout that cannot hold a handshake should be reported once, not once per process")
}

// The allowance runs from when shutdown began, not from when this pass is
// entered. Whatever ran first shares the same timeout — draining the injection
// queues can spend all of it waiting on a target that stopped answering — so a
// pass that started its own clock late would take up targets the process will
// not be alive to finish, reopening debugger ports with nothing left to close
// them again.
func TestUninjectAllTakesUpNothingWhenShutdownIsAlreadyOut(t *testing.T) {
	cfg := obi.DefaultConfig

	open, started := countingHandles(0)
	logs := &warnCounter{}

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	i.log = slog.New(logs)

	for pid := app.PID(30000); pid < 30050; pid++ {
		i.injected[pid] = 99
	}

	// Shutdown began a whole allowance ago: nothing of it is left.
	shutdownAt := time.Now().Add(-i.uninjectAllowance())

	begin := time.Now()
	i.UninjectAll(shutdownAt)
	elapsed := time.Since(begin)

	require.Zero(t, started.Load(), "no target may be taken up with the allowance already spent")
	require.Empty(t, i.injected)
	require.Less(t, elapsed, time.Second, "the pass must return at once rather than start its own clock")
	require.EqualValues(t, 1, logs.warns.Load(),
		"the reason is reported once for the pass, not once per process")
}

// The same allowance, entered promptly, does take targets up — otherwise the
// test above would pass on a pass that never does anything.
func TestUninjectAllTakesUpTargetsWhenShutdownIsFresh(t *testing.T) {
	cfg := obi.DefaultConfig

	open, started := countingHandles(0)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30004; pid++ {
		i.injected[pid] = 99
	}

	i.UninjectAll(time.Now())

	require.Positive(t, started.Load(), "a fresh shutdown must still reach its targets")
}

// The evaluate that closes the inspector is the whole point of the handshake:
// it keeps its own budget even once the deadline bounding the rest has passed,
// or a signaled application is left with an open debugger port for good.
func TestDebugEndKeepsItsBudgetPastTheDeadline(t *testing.T) {
	expired := time.Now().Add(-time.Hour)

	require.Equal(t, debugEndBudget, debugEndTimeout(expired))
	require.Positive(t, debugEndTimeout(expired))

	require.LessOrEqual(t, stepTimeout(expired), time.Duration(0),
		"the steps bounded by the deadline should be out of time")
}

// The zero deadline is what the injection path passes: it works against no
// budget of its own, so every step keeps its full timeout.
func TestStepTimeoutFollowsTheDeadline(t *testing.T) {
	require.Equal(t, inspectorRequestTimeout, stepTimeout(time.Time{}))
	require.Equal(t, inspectorRequestTimeout, debugEndTimeout(time.Time{}))

	near := time.Now().Add(inspectorRequestTimeout / 2)
	require.Less(t, stepTimeout(near), inspectorRequestTimeout)

	far := time.Now().Add(10 * inspectorRequestTimeout)
	require.Equal(t, inspectorRequestTimeout, stepTimeout(far))
}

func TestForgetDropsProcess(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	i.injected[4242] = 99
	i.Forget(4242)

	require.Empty(t, i.injected)
}

func TestGatePlaceholdersMatchTheScript(t *testing.T) {
	require.Equal(t, 1, strings.Count(_extractorCode, rtEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_extractorCode, tracesEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_spanBridgeCode, spansEnabledPlaceholder))
}
