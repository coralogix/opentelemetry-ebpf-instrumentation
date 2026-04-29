// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

type (
	StatsTCPRtt              StatsTcpRttT
	StatsTCPFailedConnection StatsTcpFailedConnectionT
)

type probe struct {
	progName string
	hookName string
	enabled  bool
	out      **ebpf.Program
}

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose = "tcp_close"

	// Tracepoints: group/name.
	TracepointInetSockSetState = "sock/inet_sock_set_state"
)

// Probe names
const (
	ObiKprobeTcpCloseSrtt         = "obi_kprobe_tcp_close_srtt"
	ObiTracepointInetSockSetState = "obi_tracepoint_inet_sock_set_state"
)

// Map names
const (
	StatsEvents = "stats_events"
	DebugEvents = "debug_events"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type tcp_rtt_t -type tcp_failed_connection_t -target amd64,arm64 Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log       *slog.Logger
	objects   *StatsObjects
	closables []io.Closer
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher(cfg *config.EBPFTracer, features *export.Features) (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	objects := &StatsObjects{}

	// Probe metadata, grouped by attach type. Each slice drives both spec
	// deletion (so disabled probes never enter the kernel) and the per-type
	// attach loop below.
	//
	// Do not use LoadSpec from the convenience pkg because we need
	// NewCollectionWithOptions instead of LoadAndAssign for this use case.
	kprobes := []probe{
		{
			progName: ObiKprobeTcpCloseSrtt,
			hookName: KprobeTCPClose,
			enabled:  features.StatsTCPRtt(),
			out:      &objects.ObiKprobeTcpCloseSrtt,
		},
	}
	tracepoints := []probe{
		{
			progName: ObiTracepointInetSockSetState,
			hookName: TracepointInetSockSetState,
			enabled:  features.StatsTCPFailedConnections(),
			out:      &objects.ObiTracepointInetSockSetState,
		},
	}

	// Drop programs the user disabled so NewCollectionWithOptions won't load them.
	for _, p := range kprobes {
		if !p.enabled {
			delete(spec.Programs, p.progName)
		}
	}
	for _, p := range tracepoints {
		if !p.enabled {
			delete(spec.Programs, p.progName)
		}
	}

	if err := ebpfconvenience.RewriteConstants(spec, map[string]any{
		"g_bpf_debug": cfg.BpfDebug,
	}); err != nil {
		return nil, fmt.Errorf("rewriting BPF constants: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	collOpts, err := ebpfconvenience.ResolveMaps(spec, sharedMaps, &mu)
	if err != nil {
		return nil, fmt.Errorf("resolving maps: %w", err)
	}
	collOpts.Programs = ebpf.ProgramOptions{LogSizeStart: 640 * 1024}
	// collOpts.Maps.PinPath stays zero; statsolly passes "" today.

	coll, err := ebpf.NewCollectionWithOptions(spec, *collOpts)
	if err != nil {
		return nil, fmt.Errorf("loading stats eBPF collection: %w", err)
	}

	objects.StatsEvents = coll.DetachMap(StatsEvents)
	objects.DebugEvents = coll.DetachMap(DebugEvents)

	closables := []io.Closer{objects}

	// kprobes
	for _, k := range kprobes {
		prog := coll.DetachProgram(k.progName)
		if prog == nil {
			continue
		}
		*k.out = prog

		l, err := link.Kprobe(k.hookName, prog, nil)
		if err != nil {
			closeAll(closables)
			coll.Close()
			return nil, fmt.Errorf("failed kprobe attachment %s: %w", k.hookName, err)
		}
		closables = append(closables, l)
	}

	// tracepoints
	for _, t := range tracepoints {
		prog := coll.DetachProgram(t.progName)
		if prog == nil {
			continue
		}
		*t.out = prog

		group, tp, ok := strings.Cut(t.hookName, "/")
		if !ok {
			closeAll(closables)
			coll.Close()
			return nil, fmt.Errorf("invalid tracepoint %q: must be group/name", t.hookName)
		}
		l, err := link.Tracepoint(group, tp, prog, nil)
		if err != nil {
			closeAll(closables)
			coll.Close()
			return nil, fmt.Errorf("failed tracepoint attachment %s: %w", t.hookName, err)
		}
		closables = append(closables, l)
	}

	// detached entries are no-ops; frees anything we didn't claim.
	coll.Close()

	return &StatsFetcher{
		log:       tlog,
		objects:   objects,
		closables: closables,
	}, nil
}

func closeAll(closables []io.Closer) {
	for _, c := range closables {
		if c != nil {
			c.Close()
		}
	}
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	for _, c := range m.closables {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// StatsEventsMap returns the ring buffer map for stats events.
// The caller (ForwardRingbuf) is responsible for creating and closing the reader.
func (m *StatsFetcher) StatsEventsMap() *ebpf.Map {
	return m.objects.StatsEvents
}

func (m *StatsFetcher) DebugEventsMap() *ebpf.Map {
	return m.objects.DebugEvents
}
