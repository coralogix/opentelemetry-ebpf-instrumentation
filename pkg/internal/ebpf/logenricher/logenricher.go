// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
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
}

func New(pf ebpfcommon.ServiceFilter, cfg *obi.Config) *Tracer {
	return &Tracer{
		log: slog.With("component", "logenricher"),
		cfg: cfg,
		pf:  pf,
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
	return map[string]ebpfcommon.ProbeDesc{
		"tty_write": {
			Start:    p.bpfObjects.ObiKprobeTtyWrite,
			Required: true,
		},
		"pipe_write": { // todo(matt): should use anon_pipe_write in newer kernels
			Start:    p.bpfObjects.ObiKprobePipeWrite,
			Required: true,
		},
		"ksys_write": {
			Start:    p.bpfObjects.ObiKprobeKsysWrite,
			Required: true,
		},
	}
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
		return fmt.Errorf("logenricher: error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		return fmt.Errorf("logenricher: error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) initPIDsMap(m *ebpf.Map) error {
	if m == nil {
		return errors.New("logenricher: pids bpf map is nil")
	}

	pids := p.flattenPIDs()

	p.log.Debug("logenricher: allowing pids", "count", len(pids))

	for _, pid := range pids {
		if err := p.addPID(pid); err != nil {
			return err
		}
	}

	return nil
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.log.Debug("logenricher: adding pid", "pid", pid, "ns", ns)
	p.pf.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeLogEnricher)
	if err := p.addPID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.log.Debug("logenricher: removing pid", "pid", pid, "ns", ns)
	p.pf.BlockPID(pid, ns)
	if err := p.removePID(p.pidKey(ns, pid)); err != nil {
		p.log.Error(err.Error())
	}
}

func (p *Tracer) Run(ctx context.Context, eventCtx *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("logenricher: starting")

	if err := p.initPIDsMap(p.bpfObjects.LogEnricherPids); err != nil {
		p.log.Error("logenricher: failed to init pids map, not starting", "error", err)
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

	p.log.Debug("logenricher: terminating")
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

	f, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		slog.With("component", "logEnricher").Error("failed to open log file for writing", "path", filePath, "error", err)
		return request.Span{}, true, err
	}
	defer f.Close()

	logLine := make([]byte, event.Len)
	copy(logLine, record.RawSample[hdrSize:hdrSize+event.Len])

	var (
		b       bytes.Buffer
		spanID  = trace.SpanID(event.PidTp.Tp.SpanId)
		traceID = trace.TraceID(event.PidTp.Tp.TraceId)
	)

	// Only handle JSON logs for now
	if logLine[event.Len-2] == byte('}') {
		b.Write(logLine[:event.Len-3])
		b.WriteString(`", "trace_id": "`)
		b.WriteString(traceID.String())
		b.WriteString(`", "span_id": "`)
		b.WriteString(spanID.String())
		b.WriteString(`"}`)
		b.WriteByte('\n')
	} else {
		// preserve the original logline
		b.Write(logLine[:event.Len])
	}

	_, err = f.Write(b.Bytes())
	return request.Span{}, true, err
}
