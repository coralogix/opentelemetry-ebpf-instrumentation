// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
)

// CustomSpanDef binds a config span to its runtime cookie and the per-arg
// attribute layout used to decode incoming events.
type CustomSpanDef struct {
	Cookie    uint64
	Name      string
	IsPair    bool
	PairOnTid bool // function-paired: pair entry+ret on (pid, tid, cookie)
	usedSlots []customSpanAttrSlot
}

type customSpanAttrSlot struct {
	ArgIdx uint8
	Name   string
	Type   config.CustomSpanAttrType
}

func NewCustomSpanDef(span *config.CustomSpanSpec, compiled obiebpf.CompiledCustomSpanSpec) *CustomSpanDef {
	def := &CustomSpanDef{
		Cookie:    compiled.Cookie,
		Name:      span.Name,
		IsPair:    span.IsUSDTSpan() || span.IsFunctionSpan(),
		PairOnTid: span.IsFunctionSpan(),
	}
	for name, a := range span.Attrs {
		if int(a.Arg) >= customSpanMaxArgs {
			continue
		}
		def.usedSlots = append(def.usedSlots, customSpanAttrSlot{
			ArgIdx: a.Arg,
			Name:   name,
			Type:   a.Type,
		})
	}
	return def
}

// CustomSpanRegistry resolves an event cookie back to its CustomSpanDef.
type CustomSpanRegistry struct {
	mu   sync.RWMutex
	defs map[uint64]*CustomSpanDef
}

func NewCustomSpanRegistry() *CustomSpanRegistry {
	return &CustomSpanRegistry{defs: map[uint64]*CustomSpanDef{}}
}

func (r *CustomSpanRegistry) Register(def *CustomSpanDef) {
	r.mu.Lock()
	r.defs[def.Cookie] = def
	r.mu.Unlock()
}

func (r *CustomSpanRegistry) Lookup(cookie uint64) (*CustomSpanDef, bool) {
	r.mu.RLock()
	d, ok := r.defs[cookie]
	r.mu.RUnlock()
	return d, ok
}

// customSpanPairKey indexes the userspace pairing map. For USDT-paired spans,
// Key = arg_int[0] (the "arg 0 is the correlation key" convention). For
// function-paired spans, Key = global TID so entry uprobe + uretprobe pair on
// the firing thread.
type customSpanPairKey struct {
	PID    uint32
	Cookie uint64
	Key    uint64
}

func makePairKey(def *CustomSpanDef, ev *CustomSpanRawEvent) customSpanPairKey {
	k := customSpanPairKey{PID: ev.GlobalPid, Cookie: ev.Cookie}
	if def.PairOnTid {
		k.Key = uint64(ev.GlobalTid)
	} else {
		k.Key = ev.ArgInt[0]
	}
	return k
}

type customSpanPending struct {
	StartedAt   time.Time
	StartTimeNs uint64
	Attrs       map[string]string
	HasTraceCtx bool
	TraceID     trace.TraceID
	SpanID      trace.SpanID
	GlobalPid   uint32
	GlobalTid   uint32
	NsPid       uint32
	NsTid       uint32
	PidNsID     uint32
}

// CustomSpanPairer correlates start/end events by (pid, cookie, arg0) and ages
// out stale starts after TTL.
type CustomSpanPairer struct {
	now     func() time.Time
	ttl     time.Duration
	mu      sync.Mutex
	pending map[customSpanPairKey]customSpanPending
}

func NewCustomSpanPairer(ttl time.Duration) *CustomSpanPairer {
	return &CustomSpanPairer{
		now:     time.Now,
		ttl:     ttl,
		pending: map[customSpanPairKey]customSpanPending{},
	}
}

func (p *CustomSpanPairer) putStart(key customSpanPairKey, pending customSpanPending) {
	p.mu.Lock()
	p.pending[key] = pending
	p.mu.Unlock()
}

func (p *CustomSpanPairer) takeStart(key customSpanPairKey) (customSpanPending, bool) {
	p.mu.Lock()
	v, ok := p.pending[key]
	if ok {
		delete(p.pending, key)
	}
	p.mu.Unlock()
	return v, ok
}

// EvictExpired removes start frames older than TTL. Returns the count evicted.
// Caller invokes this periodically; the package does not own a goroutine.
func (p *CustomSpanPairer) EvictExpired() int {
	cutoff := p.now().Add(-p.ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for k, v := range p.pending {
		if v.StartedAt.Before(cutoff) {
			delete(p.pending, k)
			n++
		}
	}
	return n
}

// PendingLen returns the size of the in-flight map.
func (p *CustomSpanPairer) PendingLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// Builder turns BPF events into request.Span instances.
type CustomSpanBuilder struct {
	reg    *CustomSpanRegistry
	pairer *CustomSpanPairer
}

func NewCustomSpanBuilder(reg *CustomSpanRegistry, pairer *CustomSpanPairer) *CustomSpanBuilder {
	return &CustomSpanBuilder{reg: reg, pairer: pairer}
}

// Build consumes one decoded event. It returns (span, true, nil) when a span
// is ready to emit (end-of-pair or single-shot), (zero, false, nil) when the
// event was buffered as a pending start, or (zero, false, err) on bad input.
// Unknown cookies / unknown event kinds resolve to (zero, false, nil).
func (b *CustomSpanBuilder) Build(ev *CustomSpanRawEvent) (request.Span, bool, error) {
	if ev == nil {
		return request.Span{}, false, errors.New("custom_span: nil event")
	}
	def, ok := b.reg.Lookup(ev.Cookie)
	if !ok {
		return request.Span{}, false, nil
	}

	switch ev.Kind {
	case uint8(obiebpf.CustomSpanKindStart):
		if !def.IsPair {
			return request.Span{}, false, nil
		}
		b.pairer.putStart(makePairKey(def, ev), customSpanPending{
			StartedAt:   b.pairer.now(),
			StartTimeNs: ev.Timestamp,
			Attrs:       extractAttrs(def, ev),
			HasTraceCtx: ev.HasTraceCtx != 0,
			TraceID:     trace.TraceID(ev.TraceID),
			SpanID:      trace.SpanID(ev.SpanID),
			GlobalPid:   ev.GlobalPid,
			GlobalTid:   ev.GlobalTid,
			NsPid:       ev.NsPid,
			NsTid:       ev.NsTid,
			PidNsID:     ev.PidNsID,
		})
		return request.Span{}, false, nil

	case uint8(obiebpf.CustomSpanKindEnd):
		if !def.IsPair {
			return request.Span{}, false, nil
		}
		pending, found := b.pairer.takeStart(makePairKey(def, ev))
		if !found {
			return request.Span{}, false, nil
		}
		return composeSpan(def, &pending, ev, ev.Timestamp), true, nil

	case uint8(obiebpf.CustomSpanKindSingle):
		if def.IsPair {
			return request.Span{}, false, nil
		}
		pending := customSpanPending{
			StartedAt:   b.pairer.now(),
			StartTimeNs: ev.Timestamp,
			Attrs:       extractAttrs(def, ev),
			HasTraceCtx: ev.HasTraceCtx != 0,
			TraceID:     trace.TraceID(ev.TraceID),
			SpanID:      trace.SpanID(ev.SpanID),
			GlobalPid:   ev.GlobalPid,
			GlobalTid:   ev.GlobalTid,
			NsPid:       ev.NsPid,
			NsTid:       ev.NsTid,
			PidNsID:     ev.PidNsID,
		}
		return composeSpan(def, &pending, ev, ev.Timestamp), true, nil
	}
	return request.Span{}, false, nil
}

func extractAttrs(def *CustomSpanDef, ev *CustomSpanRawEvent) map[string]string {
	out := make(map[string]string, len(def.usedSlots))
	applyAttrs(def, ev, out)
	return out
}

// applyAttrs writes each used slot into out when the event's wire kind agrees
// with the declared type. The kind gate prevents a paired probe whose
// start/end arg layouts diverge from poisoning the span with garbage.
func applyAttrs(def *CustomSpanDef, ev *CustomSpanRawEvent, out map[string]string) {
	for _, slot := range def.usedSlots {
		i := slot.ArgIdx
		kind := ev.ArgKind[i]
		switch {
		case slot.Type.IsString() && kind == uint8(obiebpf.CustomSpanArgStr):
			out[slot.Name] = TrimNUL(ev.ArgStr[i][:], ev.ArgStrLen[i])
		case !slot.Type.IsString() && kind == uint8(obiebpf.CustomSpanArgInt):
			// Empty Type (USDT int auto-derived) → format as unsigned u64.
			signed := slot.Type.Signed()
			width := int(slot.Type.SizeBytes())
			if width == 0 {
				width = 8
			}
			out[slot.Name] = FormatArgInt(ev.ArgInt[i], obiebpf.CustomSpanArgInt, signed, width)
		}
	}
}

func composeSpan(def *CustomSpanDef, pending *customSpanPending, ev *CustomSpanRawEvent, endNs uint64) request.Span {
	attrs := pending.Attrs
	if def.IsPair {
		mergeEndAttrs(def, ev, attrs)
	}
	span := request.Span{
		Type:         request.EventTypeCustomSpan,
		Method:       def.Name,
		RequestStart: int64(pending.StartTimeNs),
		Start:        int64(pending.StartTimeNs),
		End:          int64(endNs),
		Pid: request.PidInfo{
			HostPID:   app.PID(pending.GlobalPid),
			UserPID:   app.PID(pending.NsPid),
			Namespace: pending.PidNsID,
		},
		CustomSpan: &request.CustomSpan{
			Name:  def.Name,
			Attrs: attrs,
		},
	}
	if pending.HasTraceCtx {
		span.TraceID = pending.TraceID
		span.ParentSpanID = pending.SpanID
	}
	return span
}

// mergeEndAttrs overlays end-side attrs (e.g. status code) onto a map
// populated by extractAttrs from the start event.
func mergeEndAttrs(def *CustomSpanDef, ev *CustomSpanRawEvent, into map[string]string) {
	applyAttrs(def, ev, into)
}
