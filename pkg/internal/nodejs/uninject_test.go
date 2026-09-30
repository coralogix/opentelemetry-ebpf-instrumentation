// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestUninstallCodeLeavesEveryGateOff(t *testing.T) {
	code := uninstallCode()

	require.Contains(t, code, rtEnabledPlaceholder)
	require.Contains(t, code, tracesEnabledPlaceholder)
	require.Contains(t, code, spansEnabledPlaceholder)
	require.Contains(t, code, ctxHookEnabledPlaceholder)
	require.NotContains(t, code, rtEnabledOn)
	require.NotContains(t, code, tracesEnabledOn)
	require.NotContains(t, code, spansEnabledOn)
	require.NotContains(t, code, ctxHookEnabledOn)
}

func TestUninstallCodeIncludesSpanBridge(t *testing.T) {
	require.Contains(t, uninstallCode(), "__obiSpanBridge")
}

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

func TestUninjectAllDrainsTheSet(t *testing.T) {
	cfg := obi.DefaultConfig

	i := NewNodeInjector(&cfg)
	i.injected[4242] = injectedProcess{startTime: 99}

	i.UninjectAll(time.Now())

	require.Empty(t, i.injected)
}

const testAdmissionWindow = 100 * time.Millisecond

func testShutdownTimeout() time.Duration {
	return (uninjectCommitTail + testAdmissionWindow) * uninjectAllowanceShare
}

func countingHandles(work time.Duration) (func(app.PID, uint64) (*procs.ProcessHandle, error), *atomic.Int64) {
	open, started, _ := countingHandlesDone(work)

	return open, started
}

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

func TestUninjectAllLetsAdmittedTargetsFinish(t *testing.T) {
	const perWork = 200 * time.Millisecond

	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = testShutdownTimeout()

	open, started, finished := countingHandlesDone(perWork)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30200; pid++ {
		i.injected[pid] = injectedProcess{startTime: 99}
	}

	i.UninjectAll(time.Now())

	require.Positive(t, started.Load(), "no target was taken up at all")
	require.Equal(t, started.Load(), finished.Load(),
		"the pass returned with a target still being worked on")
}

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
		i.injected[pid] = injectedProcess{startTime: 99}
	}

	i.UninjectAll(time.Now())

	require.Empty(t, i.injected)

	reachable := int64(testAdmissionWindow/perWork+1) * uninjectConcurrency
	require.Less(t, started.Load(), reachable*2,
		"the dispatch loop kept admitting targets past the allowance")
}

func TestUninjectAllWaitsForTheTargetsItStarted(t *testing.T) {
	const perWork = 300 * time.Millisecond

	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = testShutdownTimeout()

	open, started := countingHandles(perWork)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30008; pid++ {
		i.injected[pid] = injectedProcess{startTime: 99}
	}

	begin := time.Now()
	i.UninjectAll(time.Now())
	elapsed := time.Since(begin)

	require.Positive(t, started.Load(), "no target was started at all")
	require.GreaterOrEqual(t, elapsed, perWork,
		"UninjectAll returned while a started target was still being worked on")
}

func TestUninjectAllReturnsInsideItsAllowance(t *testing.T) {
	for _, shutdown := range []time.Duration{
		testShutdownTimeout(),
		obi.DefaultConfig.ShutdownTimeout,
	} {
		t.Run(shutdown.String(), func(t *testing.T) {
			cfg := obi.DefaultConfig
			cfg.ShutdownTimeout = shutdown

			allowance := cfg.ShutdownTimeout / uninjectAllowanceShare

			open, _ := countingHandles(2 * cfg.ShutdownTimeout)

			i := NewNodeInjector(&cfg)
			i.openHandle = open
			for pid := app.PID(30000); pid < 30100; pid++ {
				i.injected[pid] = injectedProcess{startTime: 99}
			}

			begin := time.Now()
			i.UninjectAll(time.Now())
			elapsed := time.Since(begin)

			require.LessOrEqual(t, elapsed, allowance+500*time.Millisecond,
				"the pass outlived its allowance at shutdown_timeout %v", shutdown)
		})
	}
}

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

func TestUninjectAllStartsNothingWithoutAllowance(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.ShutdownTimeout = uninjectCommitTail

	open, started := countingHandles(0)
	logs := &warnCounter{}

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	i.log = slog.New(logs)

	for pid := app.PID(30000); pid < 30050; pid++ {
		i.injected[pid] = injectedProcess{startTime: 99}
	}

	i.UninjectAll(time.Now())

	require.Zero(t, started.Load(), "a target was started with no budget to finish it")
	require.Empty(t, i.injected)
	require.EqualValues(t, 1, logs.warns.Load(),
		"a shutdown timeout that cannot hold a handshake should be reported once, not once per process")
}

func TestUninjectAllTakesUpNothingWhenShutdownIsAlreadyOut(t *testing.T) {
	cfg := obi.DefaultConfig

	open, started := countingHandles(0)
	logs := &warnCounter{}

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	i.log = slog.New(logs)

	for pid := app.PID(30000); pid < 30050; pid++ {
		i.injected[pid] = injectedProcess{startTime: 99}
	}

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

func TestUninjectAllTakesUpTargetsWhenShutdownIsFresh(t *testing.T) {
	cfg := obi.DefaultConfig

	open, started := countingHandles(0)

	i := NewNodeInjector(&cfg)
	i.openHandle = open
	for pid := app.PID(30000); pid < 30004; pid++ {
		i.injected[pid] = injectedProcess{startTime: 99}
	}

	i.UninjectAll(time.Now())

	require.Positive(t, started.Load(), "a fresh shutdown must still reach its targets")
}

func TestDebugEndKeepsItsBudgetPastTheDeadline(t *testing.T) {
	expired := time.Now().Add(-time.Hour)

	require.Equal(t, debugEndBudget, debugEndTimeout(expired))
	require.Positive(t, debugEndTimeout(expired))

	require.LessOrEqual(t, stepTimeout(expired), time.Duration(0),
		"the steps bounded by the deadline should be out of time")
}

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

	i.injected[4242] = injectedProcess{startTime: 99}
	i.Forget(4242)

	require.Empty(t, i.injected)
}

func TestGatePlaceholdersMatchTheScript(t *testing.T) {
	require.Equal(t, 1, strings.Count(_extractorCode, rtEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_extractorCode, tracesEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_extractorCode, ctxHookEnabledPlaceholder))
	require.Equal(t, 1, strings.Count(_spanBridgeCode, spansEnabledPlaceholder))
}

func TestSignalGatesRememberOnlyAFinishedScan(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	g := &signalGates{}

	g.sourceReferencesSIGUSR1(cancelled, os.Getpid())
	require.False(t, g.scanned)

	g.sourceReferencesSIGUSR1(t.Context(), os.Getpid())
	require.True(t, g.scanned)
}

func TestSignalGatesReuseAFinishedScan(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	g := &signalGates{scanned: true, sourceHit: true}

	require.True(t, g.sourceReferencesSIGUSR1(cancelled, os.Getpid()))
}
