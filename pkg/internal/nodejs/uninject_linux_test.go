// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

// selfStartTime reads field 22 of /proc/self/stat, the token OpenProcessHandle
// validates against. The comm field is parenthesized and may contain spaces, so
// the fields after it begin past the final ')'.
func selfStartTime() (uint64, error) {
	buf, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}

	stat := string(buf)

	commEnd := strings.LastIndexByte(stat, ')')
	if commEnd < 0 {
		return 0, errors.New("unparsable /proc/self/stat")
	}

	fields := strings.Fields(stat[commEnd+1:])

	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, errors.New("unparsable /proc/self/stat")
	}

	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
}

// Reopening is what refuses a process that is not the one that was injected:
// the handle validates the recorded start time, so nothing downstream of it —
// the gates, the signal — is reached. A live PID with a start time that cannot
// match covers the recycled-PID case without needing one to be recycled.
func TestUninjectRefusesAProcessThatIsNotTheOneInjected(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	err := i.uninject(t.Context(), app.PID(os.Getpid()), 1, uninstallCode())

	require.ErrorContains(t, err, "replaced before injection")
}

// A PID above pid_max is one the kernel cannot have allocated, so the refusal
// is the handle's and not an accident of what happens to be running here.
func TestUninjectRefusesAProcessThatIsGone(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	pid := app.PID(unusedPID(t))

	err := i.uninject(t.Context(), pid, 99, uninstallCode())

	require.ErrorContains(t, err, fmt.Sprintf("reopening process %d to remove the agent", pid))
}

// The gate above stops a target whose allowance is gone. This one stops a
// target whose allowance is still running but can no longer hold the whole
// handshake: the signal would reopen a port with no time left to close it.
func TestUninjectRefusesToSignalWithoutTimeToClose(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	signals := 0
	restore := sendSIGUSR1
	sendSIGUSR1 = func(*procs.ProcessHandle) error {
		signals++
		return nil
	}
	t.Cleanup(func() { sendSIGUSR1 = restore })

	// Alive, so the gates are reached and ctx.Err() is nil, but far shorter
	// than uninjectSignalTail.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	pid := app.PID(os.Getpid())

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(ctx, pid, startTime, uninstallCode())

	require.ErrorContains(t, err, "too little to reopen and close its inspector")
	require.Zero(t, signals, "a process was signaled with no time left to close its inspector")
}

// SIGUSR1 reopens the application's debugger port and only a completed
// handshake closes it again, so a target reached with the budget already gone
// must not be signaled at all: there is nothing left to close it with.
//
// The assertions pin which gate stopped it. The budget's own error is the one
// that must come back, and the signal must not have been sent — a gate that
// let the process through would refuse it further down for some reason of its
// own, and an error alone would not tell the two apart.
func TestUninjectDoesNotSignalOnceTheBudgetIsGone(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	signals := 0
	restore := sendSIGUSR1
	sendSIGUSR1 = func(*procs.ProcessHandle) error {
		signals++
		return nil
	}
	t.Cleanup(func() { sendSIGUSR1 = restore })

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()

	// Our own process: a live PID whose recorded start time matches, so the
	// gates are reached and the budget is what stops it.
	pid := app.PID(os.Getpid())

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(ctx, pid, startTime, uninstallCode())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, signals, "a process was signaled with no budget left to close its inspector again")
}

// An already-listening inspector needs no signal, so the probe for one gets the
// whole of a target's share. Reserving the signal path's slice out of it left
// the probe a fraction of the time the conversation needs, and an --inspect
// process would fail its uninstall under any load while that slice went unused.
//
// The probe is driven for real: a listener on the inspector port answers slower
// than the reserved slice but well inside the full share, so reinstating the
// reservation changes which path uninject takes.
func TestUninjectProbesAnOpenInspectorWithTheWholeShare(t *testing.T) {
	const answerDelay = 800 * time.Millisecond

	require.Greater(t, uninjectCommitTail, answerDelay,
		"the share must be able to absorb the delay")
	require.Less(t, uninjectCommitTail-uninjectSignalTail, answerDelay,
		"and the reserved slice must not, or this test proves nothing")

	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(answerDelay)
		_, _ = w.Write([]byte(`{"Browser":"node.js/v22.0.0","Protocol-Version":"1.1"}`))
	})
	mux.HandleFunc("/json/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	})

	// The inspector port is fixed by the protocol, so this test cannot pick a
	// free one. A machine already running node --inspect skips it rather than
	// reporting someone else's inspector as a failure.
	ln, err := net.Listen("tcp", "127.0.0.1:9229")
	if err != nil {
		t.Skipf("inspector port already in use, skipping: %v", err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Nothing may be signaled: this target's inspector is already open.
	signals := 0
	restore := sendSIGUSR1
	sendSIGUSR1 = func(*procs.ProcessHandle) error {
		signals++
		return nil
	}
	t.Cleanup(func() { sendSIGUSR1 = restore })

	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(t.Context(), app.PID(os.Getpid()), startTime, uninstallCode())

	// Reaching the target list means the probe survived the slow answer. With
	// the signal tail reserved out of it, the probe times out instead, reports
	// no inspector, and uninject walks the gates toward SIGUSR1.
	require.ErrorContains(t, err, "no debugging targets available")
	require.Zero(t, signals, "a process whose inspector was already open must not be signaled")
}
