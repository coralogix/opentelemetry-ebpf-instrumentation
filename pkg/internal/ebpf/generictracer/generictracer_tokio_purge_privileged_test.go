// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// Two instrumented processes by OBI-view pid. The thread map is keyed by the host pid_tgid,
// which is another number in pod mode, so the fixture gives every thread key a different
// high half and the purge has to match on the value's tgid.
const (
	tokioPidA      uint32 = 41000
	tokioPidB      uint32 = 41007
	tokioHostTgid  uint64 = 7
	tokioTaskShift        = 16 // Header values: tgid << shift | task ordinal
)

// newTestTokioTracer loads the four Tokio maps from the compiled object, pinning off, so
// the purge runs against the real map types and key layouts.
func newTestTokioTracer(t *testing.T) *Tracer {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		if m.Pinning == ebpfconvenience.PinInternal || m.Pinning == ebpf.PinByName {
			m.Pinning = ebpf.PinNone
		}
	}

	var objs struct {
		Process     *ebpf.Map `ebpf:"tokio_process"`
		TaskState   *ebpf.Map `ebpf:"tokio_task_state"`
		TaskIDState *ebpf.Map `ebpf:"tokio_task_id_state"`
		ThreadState *ebpf.Map `ebpf:"tokio_thread_state"`
	}
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		objs.Process.Close()
		objs.TaskState.Close()
		objs.TaskIDState.Close()
		objs.ThreadState.Close()
	})

	tracer := &Tracer{log: tlog()}
	tracer.bpfObjects.TokioProcess = objs.Process
	tracer.bpfObjects.TokioTaskState = objs.TaskState
	tracer.bpfObjects.TokioTaskIdState = objs.TaskIDState
	tracer.bpfObjects.TokioThreadState = objs.ThreadState

	return tracer
}

// putTokioProcess marks tgid as a Tokio process with `tasks` Header entries, one id entry
// and one thread entry per task, like a process that polled, spawned and anchored.
func putTokioProcess(t *testing.T, tracer *Tracer, tgid uint32, tasks int) {
	t.Helper()
	objs := &tracer.bpfObjects

	require.NoError(t, objs.TokioProcess.Put(tgid, uint8(1)))
	require.NoError(t, objs.TokioTaskIdState.Put(BpfTokioTaskKeyT{Tgid: tgid, Id: uint64(tgid)}, BpfTokioTaskIdStateT{}))
	for i := range tasks {
		header := uint64(tgid)<<tokioTaskShift | uint64(i+1)
		require.NoError(t, objs.TokioTaskState.Put(BpfTokioTaskKeyT{Tgid: tgid, Id: header}, BpfTokioTaskStateT{Version: 1}))

		pidTgid := tokioHostTgid<<32 | (uint64(tgid) + uint64(i))
		require.NoError(t, objs.TokioThreadState.Put(pidTgid, BpfTokioThreadStateT{CurrentTask: header, Tgid: tgid}))
	}
}

func countTokioTaskKeys(t *testing.T, m *ebpf.Map, tgid uint32, value any) int {
	t.Helper()
	n := 0
	var key BpfTokioTaskKeyT
	it := m.Iterate()
	for it.Next(&key, value) {
		if key.Tgid == tgid {
			n++
		}
	}
	require.NoError(t, it.Err())
	return n
}

// assertTokioEntries checks what each map still holds for tgid: the process flag, the
// Header entries, the id entries and the thread entries.
func assertTokioEntries(t *testing.T, tracer *Tracer, tgid uint32, flag, tasks, ids, threads int) {
	t.Helper()
	objs := &tracer.bpfObjects

	gotFlag := 0
	var one uint8
	if err := objs.TokioProcess.Lookup(tgid, &one); err == nil {
		gotFlag = 1
	} else {
		require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	}

	gotThreads := 0
	var key uint64
	var thread BpfTokioThreadStateT
	it := objs.TokioThreadState.Iterate()
	for it.Next(&key, &thread) {
		if thread.Tgid == tgid {
			gotThreads++
		}
	}
	require.NoError(t, it.Err())

	got := []int{
		gotFlag,
		countTokioTaskKeys(t, objs.TokioTaskState, tgid, &BpfTokioTaskStateT{}),
		countTokioTaskKeys(t, objs.TokioTaskIdState, tgid, &BpfTokioTaskIdStateT{}),
		gotThreads,
	}
	assert.Equal(t, []int{flag, tasks, ids, threads}, got, "tgid %d: flag, tasks, ids, threads", tgid)
}

func TestPurgeTokioStateDropsOnlyTheDeadProcess(t *testing.T) {
	tracer := newTestTokioTracer(t)
	putTokioProcess(t, tracer, tokioPidA, 2)
	putTokioProcess(t, tracer, tokioPidB, 1)

	tracer.purgeTokioState(tokioPidA)

	assertTokioEntries(t, tracer, tokioPidA, 0, 0, 0, 0)
	assertTokioEntries(t, tracer, tokioPidB, 1, 1, 1, 1)
}

func TestPurgeTokioStateSkipsAProcessThatNeverPolledTokio(t *testing.T) {
	tracer := newTestTokioTracer(t)
	putTokioProcess(t, tracer, tokioPidB, 1)

	// No flag for A: the one failed delete is the whole cost of a non-Tokio exit.
	tracer.purgeTokioState(tokioPidA)

	assertTokioEntries(t, tracer, tokioPidB, 1, 1, 1, 1)
}

func TestPurgeTokioStateToleratesMissingMaps(t *testing.T) {
	// Before the objects are loaded there is nothing to purge and nothing to crash on.
	(&Tracer{log: tlog()}).purgeTokioState(tokioPidA)

	tracer := newTestTokioTracer(t)
	putTokioProcess(t, tracer, tokioPidA, 1)
	tracer.bpfObjects.TokioThreadState = nil

	tracer.purgeTokioState(tokioPidA)

	var one uint8
	require.ErrorIs(t, tracer.bpfObjects.TokioProcess.Lookup(tokioPidA, &one), ebpf.ErrKeyNotExist)
	assert.Equal(t, 0, countTokioTaskKeys(t, tracer.bpfObjects.TokioTaskState, tokioPidA, &BpfTokioTaskStateT{}))
	assert.Equal(t, 0, countTokioTaskKeys(t, tracer.bpfObjects.TokioTaskIdState, tokioPidA, &BpfTokioTaskIdStateT{}))
}

// BlockPID is the caller: a process removal must reach the purge.
func TestBlockPIDPurgesTokioState(t *testing.T) {
	tracer := newTestTokioTracer(t)
	tracer.bpfObjects.ValidPids = newTestValidPids(t, validPidsWords)
	tracer.pidsFilter = fakeServiceFilter{}
	putTokioProcess(t, tracer, tokioPidA, 2)
	putTokioProcess(t, tracer, tokioPidB, 1)

	tracer.BlockPID(app.PID(tokioPidA), 0)

	assertTokioEntries(t, tracer, tokioPidA, 0, 0, 0, 0)
	assertTokioEntries(t, tracer, tokioPidB, 1, 1, 1, 1)
}
