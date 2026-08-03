// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"errors"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type failingLoadTracer struct {
	recordingTracer
}

func (f *failingLoadTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	return nil, errors.New("BPF load failure")
}

// After an optional common tracer fails during ProcessTracer.Init, it must be
// pruned from ta.commonTracers so that only successfully loaded common tracers
// receive AllowPID and BlockPID notifications.
func TestCommonTracersPrunedAfterLoadFailure(t *testing.T) {
	okTracer := &recordingTracer{}
	failedTracer := &failingLoadTracer{}

	cfg := &obi.Config{}
	cfg.EBPF.BPFFSPath = t.TempDir()
	tracer := ebpf.NewProcessTracer(ebpf.Generic, []ebpf.Tracer{okTracer, failedTracer}, cfg, imetrics.NoopReporter{})
	require.NoError(t, tracer.Init(&ebpfcommon.EBPFEventContext{}, cfg))
	require.Equal(t, []ebpf.Tracer{okTracer}, tracer.Programs)

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	ta := &traceAttacher{
		log:                slog.With("component", t.Name()),
		Metrics:            imetrics.NoopReporter{},
		commonTracers:      []ebpf.Tracer{okTracer, failedTracer},
		existingTracers:    map[ebpf.ExecutableKey]executableTracer{},
		processInstances:   maps.MultiCounter[ebpf.ExecutableKey]{},
		OutputTracerEvents: tracerEvents,
	}

	ta.dropUnloadedTracers(tracer.Programs)
	assert.Equal(t, []ebpf.Tracer{okTracer}, ta.commonTracers)

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.monitorPIDs(tracer, ie)
	assert.NotEmpty(t, okTracer.allowed)
	assert.Empty(t, failedTracer.allowed)

	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	ta.processInstances.Inc(key)

	ta.notifyProcessDeletion(ie)
	assert.NotEmpty(t, okTracer.blocked)
	assert.Empty(t, failedTracer.blocked)
}

type recordingMetricsReporter struct {
	imetrics.NoopReporter
	instrumentedProcesses []string
	instrumentationErrors []string
}

func (r *recordingMetricsReporter) InstrumentProcess(processName string) {
	r.instrumentedProcesses = append(r.instrumentedProcesses, processName)
}

func (r *recordingMetricsReporter) InstrumentationError(_ string, errorType string) {
	r.instrumentationErrors = append(r.instrumentationErrors, errorType)
}

// A failed uprobe attach on the reuse path must not be reported as an
// instrumented process: that is how #2838-class breakage hides from operators.
func TestReuseTracer_DoesNotReportFailedInstrumentation(t *testing.T) {
	const missingPID app.PID = 999999999

	metrics := &recordingMetricsReporter{}
	cfg := &obi.Config{}
	tracer := ebpf.NewProcessTracer(ebpf.Go, nil, cfg, metrics)
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     "/bin/test",
		ProExeLinkPath: "/proc/self/exe",
		Pid:            missingPID,
		Dev:            100,
		Ino:            1234,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}
	ta := &traceAttacher{
		log:             slog.With("component", t.Name()),
		Metrics:         metrics,
		existingTracers: map[ebpf.ExecutableKey]executableTracer{},
	}

	ok := ta.reuseTracer(tracer, ie)

	assert.False(t, ok)
	assert.Empty(t, metrics.instrumentedProcesses)
	assert.Equal(t, []string{imetrics.InstrumentationErrorAttachingUprobe}, metrics.instrumentationErrors)
	assert.Empty(t, ta.existingTracers)
}

func TestGetTracer_DoesNotReportFailedExistingGenericInstrumentation(t *testing.T) {
	const missingPID app.PID = 999999999

	executablePath, err := os.Executable()
	require.NoError(t, err)
	statInfo, err := os.Stat(executablePath)
	require.NoError(t, err)
	stat, ok := statInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	metrics := &recordingMetricsReporter{}
	cfg := &obi.Config{}
	tracer := ebpf.NewProcessTracer(ebpf.Generic, nil, cfg, metrics)
	currentFileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     executablePath,
		ProExeLinkPath: "/proc/self/exe",
		Pid:            app.PID(os.Getpid()),
		Dev:            stat.Dev,
		Ino:            stat.Ino,
	})
	exe, err := link.OpenExecutable(currentFileInfo.ProExeLinkPath())
	require.NoError(t, err)
	require.NoError(t, tracer.NewExecutable(exe, &ebpf.Instrumentable{FileInfo: currentFileInfo}))

	failedFileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     executablePath,
		ProExeLinkPath: "/proc/self/exe",
		Pid:            missingPID,
		Dev:            stat.Dev,
		Ino:            stat.Ino,
	})
	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGeneric,
		FileInfo: failedFileInfo,
	}
	ta := &traceAttacher{
		log:     slog.With("component", t.Name()),
		Cfg:     cfg,
		Metrics: metrics,
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			executableKey(failedFileInfo): {tracer: tracer, generation: 1},
		},
		routeHarvester: harvest.NewRouteHarvester(&cfg.Discovery.RouteHarvestConfig, nil, time.Second),
	}

	success := ta.getTracer(ie)

	assert.False(t, success)
	assert.Empty(t, metrics.instrumentedProcesses)
	assert.Equal(t, []string{imetrics.InstrumentationErrorAttachingUprobe}, metrics.instrumentationErrors)
	assert.Len(t, ta.existingTracers, 1)
}
