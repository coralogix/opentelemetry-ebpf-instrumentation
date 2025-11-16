// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -target amd64,arm64 Bpf ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -target amd64,arm64 BpfDebug ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf -DBPF_DEBUG

type Tracer struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
	pf         ebpfcommon.ServiceFilter
	fdCache    *expirable.LRU[string, *os.File]
}

func New(pf ebpfcommon.ServiceFilter, cfg *obi.Config) *Tracer {
	logger := slog.With("component", "logenricher")

	if !ebpfcommon.SupportsLogInjection(logger) {
		logger.Warn("log enrichment not supported on this system!")
		return nil
	}

	return &Tracer{
		log: logger,
		cfg: cfg,
		pf:  pf,
		fdCache: expirable.NewLRU[string, *os.File](cfg.EBPF.LogEnricher.CacheSize, func(_ string, f *os.File) {
			f.Close()
		}, cfg.EBPF.LogEnricher.CacheTTL),
	}
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return LoadBpfDebug()
	}

	return LoadBpf()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	return nil
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	m := map[string]ebpfcommon.ProbeDesc{
		"tty_write": {
			Start:    p.bpfObjects.ObiKprobeTtyWrite,
			Required: true,
		},
		"ksys_write": {
			Start:    p.bpfObjects.ObiKprobeKsysWrite,
			Required: true,
		},
	}

	hasPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymPipeWrite)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymPipeWrite, "error", err)
	}

	if hasPipeWrite {
		m["pipe_write"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobePipeWrite,
			Required: true,
		}
	} else {
		hasAnonPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymAnonPipeWrite)
		if err != nil {
			p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymAnonPipeWrite, "error", err)
		}

		if hasAnonPipeWrite {
			m["anon_pipe_write"] = ebpfcommon.ProbeDesc{
				Start:    p.bpfObjects.ObiKprobePipeWrite,
				Required: true,
			}
		} else {
			p.log.Error("neither anon_pipe_write nor pipe_write kernel symbols are available; log enrichment may not work correctly")
		}
	}

	return m
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func (p *Tracer) flattenPIDs() []uint64 {
	newPids := make([]uint64, 0)

	for nsid, pids := range p.pf.CurrentPIDs(ebpfcommon.PIDTypeLogEnricher) {
		for pid := range pids {
			newPids = append(newPids, p.pidKey(nsid, pid))
		}
	}

	return newPids
}

func (p *Tracer) addPID(key uint64) error {
	if err := p.bpfObjects.LogEnricherPids.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		return fmt.Errorf("error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) initPIDsMap(m *ebpf.Map) error {
	if m == nil {
		return errors.New("pids bpf map is nil")
	}

	pids := p.flattenPIDs()

	p.log.Debug("allowing pids", "count", len(pids))

	for _, pid := range pids {
		if err := p.addPID(pid); err != nil {
			return err
		}
	}

	return nil
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.log.Debug("adding pid", "pid", pid, "ns", ns)
	p.pf.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeLogEnricher)
	if err := p.addPID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.log.Debug("removing pid", "pid", pid, "ns", ns)
	p.pf.BlockPID(pid, ns)
	if err := p.removePID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}
}

func (p *Tracer) Run(ctx context.Context, eventCtx *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("starting")

	if err := p.initPIDsMap(p.bpfObjects.LogEnricherPids); err != nil {
		p.log.Error("failed to init pids map, not starting", "error", err)
		return
	}

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LogEvents,
		eventCtx.CommonPIDsFilter,
		p.handleLogEvent,
		p.log,
		nil,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)

	p.log.Debug("terminating")
}

func (p *Tracer) Required() bool {
	return false
}

func (p *Tracer) handleLogEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(BpfLogEventT{})) - uint32(unsafe.Sizeof(uintptr(0))) // Remove `log` placeholder

	event, err := ebpfcommon.ReinterpretCast[BpfLogEventT](record.RawSample)
	if err != nil {
		// This should never happen -- if it does, we can't really recover
		// and the targeted process will miss his logs.
		return request.Span{}, true, err
	}

	procFdPath := func(fd int) string {
		return filepath.Join("/proc", strconv.FormatUint(uint64(event.Tgid), 10), "fd", strconv.Itoa(fd))
	}

	var filePath string
	if event.Fd != 0 {
		// This is a pipe write, use the target process pipe fd
		filePath = procFdPath(int(event.Fd))
	} else {
		// TTY write
		filePath = unix.ByteSliceToString(event.FilePath[:])
		if filePath == "" {
			// Fallback to process stdout in the case path resolver failed
			filePath = procFdPath(1)
		}
	}

	// Get or open the file descriptor
	f, ok := p.fdCache.Get(filePath)
	if !ok {
		f2, err2 := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0)
		if err2 != nil {
			p.log.Error("failed to open log file for writing", "path", filePath, "error", err2)
			return request.Span{}, true, err2
		}
		p.fdCache.Add(filePath, f2)
		f = f2
	}

	logLine := make([]byte, event.Len)
	copy(logLine, record.RawSample[hdrSize:hdrSize+event.Len])

	var (
		zeroTraceID [16]uint8
		zeroSpanID  [8]uint8
	)
	if event.PidTp.Tp.TraceId == zeroTraceID || event.PidTp.Tp.SpanId == zeroSpanID {
		// No trace context to inject, write original log line
		_, err = f.Write(logLine)
		return request.Span{}, true, err
	}

	var (
		b       bytes.Buffer
		spanID  = trace.SpanID(event.PidTp.Tp.SpanId)
		traceID = trace.TraceID(event.PidTp.Tp.TraceId)
	)

	var m map[string]any
	if err := json.Unmarshal(logLine[:event.Len], &m); err == nil {
		// JSON -> enrich with context
		m["trace_id"] = traceID.String()
		m["span_id"] = spanID.String()

		out, err2 := json.Marshal(m)
		if err2 != nil {
			p.log.Warn("failed to marshal enriched log line, writing original", "error", err2)
			b.Write(logLine[:event.Len])
			return request.Span{}, true, nil
		}

		b.Write(out)
		b.WriteByte('\n')
	} else {
		// Not JSON -> preserve the original logline
		b.Write(logLine[:event.Len])
	}

	_, err = f.Write(b.Bytes())
	return request.Span{}, true, err
}
