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
	out      func(*ebpf.Program)
}

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose = "tcp_close"

	// Tracepoints: group/name.
	TracepointInetSockSetState = "sock/inet_sock_set_state"
)

// Program names
const (
	progObiKprobeTCPCloseSrtt         = "obi_kprobe_tcp_close_srtt"
	progObiTracepointInetSockSetState = "obi_tracepoint_inet_sock_set_state"
)

// Map names
const (
	mapStatsEvents = "stats_events"
	mapDebugEvents = "debug_events"
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

	// Probe metadata, grouped by attach type. Each slice drives both the
	// enabled-program list passed to LoadSpec and the per-type attach
	// loop below.
	kprobes := []probe{
		{
			progName: progObiKprobeTCPCloseSrtt,
			hookName: KprobeTCPClose,
			enabled:  features.StatsTCPRtt(),
			out:      func(p *ebpf.Program) { objects.ObiKprobeTcpCloseSrtt = p },
		},
	}
	tracepoints := []probe{
		{
			progName: progObiTracepointInetSockSetState,
			hookName: TracepointInetSockSetState,
			enabled:  features.StatsTCPFailedConnections(),
			out:      func(p *ebpf.Program) { objects.ObiTracepointInetSockSetState = p },
		},
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	// statsolly intentionally doesn't share maps with other specs.
	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	coll, err := ebpfconvenience.LoadSpec(spec, ebpfconvenience.LoadSpecOptions{
		EnabledPrograms: enabledProgramNames(kprobes, tracepoints),
		Constants:       map[string]any{"g_bpf_debug": cfg.BpfDebug},
		SharedMaps:      sharedMaps,
		Mu:              &mu,
	})
	if err != nil {
		return nil, fmt.Errorf("loading stats eBPF collection: %w", err)
	}
	// Frees any programs/maps not claimed via DetachMap/DetachProgram below
	defer coll.Close()

	objects.StatsEvents = coll.DetachMap(mapStatsEvents)
	if objects.StatsEvents == nil {
		objects.Close()
		return nil, fmt.Errorf("map %q not found in collection", mapStatsEvents)
	}
	objects.DebugEvents = coll.DetachMap(mapDebugEvents)
	if objects.DebugEvents == nil {
		objects.Close()
		return nil, fmt.Errorf("map %q not found in collection", mapDebugEvents)
	}

	closables := []io.Closer{objects}

	// kprobes
	for _, k := range kprobes {
		if !k.enabled {
			continue
		}
		prog := coll.DetachProgram(k.progName)
		if prog == nil {
			closeAll(closables)
			return nil, fmt.Errorf("enabled kprobe program %q not found in collection", k.progName)
		}
		k.out(prog)

		l, err := link.Kprobe(k.hookName, prog, nil)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed kprobe attachment %s: %w", k.hookName, err)
		}
		closables = append(closables, l)
	}

	// tracepoints
	for _, t := range tracepoints {
		if !t.enabled {
			continue
		}
		prog := coll.DetachProgram(t.progName)
		if prog == nil {
			closeAll(closables)
			return nil, fmt.Errorf("enabled tracepoint program %q not found in collection", t.progName)
		}
		t.out(prog)

		group, tp, _ := strings.Cut(t.hookName, "/")
		l, err := link.Tracepoint(group, tp, prog, nil)
		if err != nil {
			closeAll(closables)
			return nil, fmt.Errorf("failed tracepoint attachment %s: %w", t.hookName, err)
		}
		closables = append(closables, l)
	}

	return &StatsFetcher{
		log:       tlog,
		objects:   objects,
		closables: closables,
	}, nil
}

// enabledProgramNames returns the program names of all enabled probes across
// the given groups. Used to tell LoadSpec which programs should reach the
// kernel; disabled probes are stripped from the spec before load.
func enabledProgramNames(probeGroups ...[]probe) []string {
	var names []string
	for _, group := range probeGroups {
		for _, p := range group {
			if p.enabled {
				names = append(names, p.progName)
			}
		}
	}
	return names
}

func closeAll(closables []io.Closer) {
	for _, c := range closables {
		if c != nil {
			c.Close()
		}
	}
}

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
