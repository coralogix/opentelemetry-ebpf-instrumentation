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

// selfStartTime reads field 22 of /proc/self/stat. The comm field may contain
// spaces, so fields are counted from the final ')'.
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

func unusedPID(t *testing.T) int {
	t.Helper()

	raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Skipf("cannot read pid_max: %v", err)
	}

	pidMax, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Skipf("cannot parse pid_max: %v", err)
	}

	return pidMax + 1
}

func stubSIGUSR1(t *testing.T) *int {
	signals := 0
	restore := sendSIGUSR1
	sendSIGUSR1 = func(*procs.ProcessHandle) error {
		signals++
		return nil
	}
	t.Cleanup(func() { sendSIGUSR1 = restore })

	return &signals
}

func TestUninjectRefusesAProcessThatIsNotTheOneInjected(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	err := i.uninject(t.Context(), app.PID(os.Getpid()), injectedProcess{startTime: 1}, uninstallCode())

	require.ErrorContains(t, err, "replaced before injection")
}

func TestUninjectRefusesAProcessThatIsGone(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	pid := app.PID(unusedPID(t))

	err := i.uninject(t.Context(), pid, injectedProcess{startTime: 99}, uninstallCode())

	require.ErrorContains(t, err, fmt.Sprintf("reopening process %d to remove the agent", pid))
}

func TestUninjectRefusesToSignalWithoutTimeToClose(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)
	signals := stubSIGUSR1(t)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(ctx, app.PID(os.Getpid()), injectedProcess{startTime: startTime}, uninstallCode())

	require.ErrorContains(t, err, "too little to reopen and close its inspector")
	require.Zero(t, *signals, "a process was signaled with no time left to close its inspector")
}

func TestUninjectDoesNotSignalOnceTheBudgetIsGone(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)
	signals := stubSIGUSR1(t)

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(ctx, app.PID(os.Getpid()), injectedProcess{startTime: startTime}, uninstallCode())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, *signals, "a process was signaled with no budget left to close its inspector again")
}

// The inspector answers slower than the commit tail minus the signal tail but
// inside the full tail, so reserving the signal tail out of the probe would
// make it time out and walk toward SIGUSR1.
func TestUninjectProbesAnOpenInspectorWithTheWholeShare(t *testing.T) {
	const answerDelay = 800 * time.Millisecond

	require.Greater(t, uninjectCommitTail, answerDelay)
	require.Less(t, uninjectCommitTail-uninjectSignalTail, answerDelay)

	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(answerDelay)
		_, _ = w.Write([]byte(`{"Browser":"node.js/v22.0.0","Protocol-Version":"1.1"}`))
	})
	mux.HandleFunc("/json/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]"))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:9229")
	if err != nil {
		t.Skipf("inspector port already in use, skipping: %v", err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	signals := stubSIGUSR1(t)

	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)

	startTime, err := selfStartTime()
	require.NoError(t, err)

	err = i.uninject(t.Context(), app.PID(os.Getpid()), injectedProcess{startTime: startTime}, uninstallCode())

	require.ErrorContains(t, err, "no debugging targets available")
	require.Zero(t, *signals, "a process whose inspector was already open must not be signaled")
}

func TestUninjectReusesTheGatesFromInjection(t *testing.T) {
	cfg := obi.DefaultConfig
	i := NewNodeInjector(&cfg)
	signals := stubSIGUSR1(t)

	startTime, err := selfStartTime()
	require.NoError(t, err)

	proc := injectedProcess{
		startTime: startTime,
		gates:     &signalGates{symsRead: true, scanned: true, sourceHit: true},
	}

	err = i.uninject(t.Context(), app.PID(os.Getpid()), proc, uninstallCode())

	require.ErrorContains(t, err, refusalSourceReferencesSIGUSR1)
	require.Zero(t, *signals)
}
