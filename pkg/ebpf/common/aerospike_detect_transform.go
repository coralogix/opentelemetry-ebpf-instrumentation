// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

// Aerospike native client protocol (proto version 2) parser.
//
// Aerospike rides the generic kprobe TCP path: the request and response payloads
// captured for an unclassified TCP connection are handed here and parsed entirely
// in userspace. The protocol is one-request-one-response per connection (FIFO),
// so the generic direction-flip correlation is sufficient — no kernel state is
// needed. Only type-3 AS_MSG data frames produce spans; type-1 Info (text admin)
// and type-2 security/auth frames are ignored, and type-4 compressed frames are
// skipped (the zlib body is opaque to byte parsing).
//
// Wire layout (all multi-byte integers big-endian):
//
//	proto header (8 bytes): version(1)=2, type(1), size(6)  // size = body length
//	as_msg header (22 bytes): header_sz(1)=22, info1(1), info2(1), info3(1),
//	    info4(1), result_code(1), generation(4), record_ttl(4), transaction_ttl(4),
//	    n_fields(2), n_ops(2)
//	field:  field_sz(4)=len(type+value), type(1), value(field_sz-1)
//	op:     op_sz(4), op(1), particle_type(1), version(1), name_sz(1), name, value

import (
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	asProtoHeaderLen = 8
	asMsgHeaderLen   = 22
	asProtoVersion   = 2

	asTypeInfo       = 1
	asTypeSecurity   = 2
	asTypeMessage    = 3 // AS_MSG: the data protocol
	asTypeCompressed = 4

	// info1 flags (read side)
	asInfo1Read   = 0x01
	asInfo1GetAll = 0x02
	asInfo1Batch  = 0x08
	asInfo1NoBins = 0x20 // GET_NO_BINS, used by exists

	// info2 flags (write side)
	asInfo2Write  = 0x01
	asInfo2Delete = 0x02

	// field type ids
	asFieldNamespace   = 0
	asFieldSet         = 1
	asFieldKey         = 2
	asFieldDigestRipe  = 4
	asFieldIndexNameLo = 21 // index-related fields span 21..26 (secondary-index query)
	asFieldIndexHi     = 26
	asFieldUDFLo       = 30 // UDF fields span 30..33
	asFieldUDFHi       = 33
	asFieldBatch       = 41 // batch (41) / batch-with-set (42)
	asFieldBatchSet    = 42

	// op type ids
	asOpWrite = 2
	asOpTouch = 11

	// largest declared proto body we will treat as plausibly Aerospike
	asMaxBodyLen = 128 * 1024 * 1024

	// status / result codes
	asResultKeyNotFound = 2

	asResultCodeOffset = asProtoHeaderLen + 5 // result_code: as_msg header byte 5
)

type aerospikeInfo struct {
	op        string
	namespace string
	set       string
	userKey   string
	batchSize int
}

func beUint(b []uint8) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// validProtoHeader reports whether the 8-byte slice is a plausible Aerospike proto
// header, returning the message type.
func validProtoHeader(h []uint8) (uint8, bool) {
	if len(h) < asProtoHeaderLen || h[0] != asProtoVersion {
		return 0, false
	}
	typ := h[1]
	switch typ {
	case asTypeInfo, asTypeSecurity, asTypeMessage, asTypeCompressed:
	default:
		return 0, false
	}
	bodyLen := beUint(h[2:asProtoHeaderLen])
	if bodyLen == 0 || bodyLen > asMaxBodyLen {
		return 0, false
	}
	return typ, true
}

// isAerospikeProto reports whether a buffer begins with a plausible Aerospike
// proto header of any message type.
func isAerospikeProto(buf *largebuf.LargeBuffer) bool {
	if buf == nil || buf.Len() < asProtoHeaderLen {
		return false
	}
	r := buf.NewReader()
	h, err := r.ReadN(asProtoHeaderLen)
	if err != nil {
		return false
	}
	_, ok := validProtoHeader(h)
	return ok
}

// asMsgIsRequest distinguishes a request from a response AS_MSG body. Requests
// always carry at least one read/batch/write intent bit; responses do not.
func asMsgIsRequest(info1, info2 uint8) bool {
	return info1&(asInfo1Read|asInfo1Batch) != 0 || info2&asInfo2Write != 0
}

// parseAerospikeRequest parses a type-3 AS_MSG request frame. Returns nil if the
// buffer is not a type-3 request (info/auth/compressed, a response, or malformed).
// Parsing is defensive: a short/truncated read stops the walk and returns what was
// decoded so far.
func parseAerospikeRequest(buf *largebuf.LargeBuffer) *aerospikeInfo {
	if buf == nil || buf.Len() < asProtoHeaderLen+asMsgHeaderLen {
		return nil
	}
	r := buf.NewReader()

	proto, err := r.ReadN(asProtoHeaderLen)
	if err != nil {
		return nil
	}
	typ, ok := validProtoHeader(proto)
	if !ok || typ != asTypeMessage {
		return nil
	}

	asm, err := r.ReadN(asMsgHeaderLen)
	if err != nil {
		return nil
	}
	// header_sz is a constant 22; checking it makes the (version==2, type==3,
	// header_sz==22, request-intent bits) signature strong enough to classify the
	// connection from a single frame without false positives.
	if asm[0] != asMsgHeaderLen {
		return nil
	}
	info1, info2 := asm[1], asm[2]
	if !asMsgIsRequest(info1, info2) {
		return nil
	}
	nFields := int(beUint(asm[18:20]))
	nOps := int(beUint(asm[20:22]))

	info := &aerospikeInfo{}
	hasDigest := false
	hasIndex := false
	hasUDF := false

	// A truncated read (e.g. a scan/query partition list cut off at the capture
	// boundary) stops the walk; the operation is still classified from the flags
	// and the fields decoded before the cut.
fieldLoop:
	for i := 0; i < nFields; i++ {
		fsz, err := r.ReadU32BE()
		if err != nil || fsz < 1 {
			break
		}
		ftype, err := r.ReadU8()
		if err != nil {
			break
		}
		valLen := int(fsz) - 1
		switch {
		case ftype == asFieldNamespace:
			v, err := r.ReadN(valLen)
			if err != nil {
				break fieldLoop
			}
			info.namespace = string(v)
		case ftype == asFieldSet:
			v, err := r.ReadN(valLen)
			if err != nil {
				break fieldLoop
			}
			info.set = string(v)
		case ftype == asFieldKey:
			// value = 1-byte particle type + key bytes; decode string keys.
			if valLen > 1 {
				v, err := r.ReadN(valLen)
				if err != nil {
					break fieldLoop
				}
				info.userKey = string(v[1:])
			} else if r.Skip(valLen) != nil {
				break fieldLoop
			}
		case ftype == asFieldBatch || ftype == asFieldBatchSet:
			// batch field value begins with a 4-byte operation count.
			if valLen >= 4 {
				n, err := r.ReadU32BE()
				if err != nil {
					break fieldLoop
				}
				info.batchSize = int(n)
				if r.Skip(valLen-4) != nil {
					break fieldLoop
				}
			} else if r.Skip(valLen) != nil {
				break fieldLoop
			}
		case ftype >= asFieldIndexNameLo && ftype <= asFieldIndexHi:
			hasIndex = true
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		case ftype >= asFieldUDFLo && ftype <= asFieldUDFHi:
			hasUDF = true
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		default:
			if ftype == asFieldDigestRipe {
				hasDigest = true
			}
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		}
	}

	info.op = classifyAerospikeOp(info1, info2, &r, nOps, hasDigest, hasIndex, hasUDF)
	return info
}

// classifyAerospikeOp derives the operation name from the info flags plus, for
// writes, the per-op type bytes (to separate PUT / TOUCH / OPERATE). The reader
// cursor must be positioned at the first op.
func classifyAerospikeOp(info1, info2 uint8, r *largebuf.LargeBufferReader, nOps int, hasDigest, hasIndex, hasUDF bool) string {
	switch {
	case hasUDF:
		return "UDF"
	case info1&asInfo1Batch != 0:
		return "BATCH"
	case info2&asInfo2Write != 0 && info2&asInfo2Delete != 0:
		return "DELETE"
	case info2&asInfo2Write != 0:
		return classifyAerospikeWrite(r, nOps)
	case info1&asInfo1Read != 0:
		switch {
		case hasIndex:
			return "QUERY"
		case !hasDigest:
			return "SCAN"
		case info1&asInfo1NoBins != 0:
			return "EXISTS"
		default:
			return "GET"
		}
	}
	return "UNKNOWN"
}

// classifyAerospikeWrite separates PUT (all writes), TOUCH (a lone touch op) and
// OPERATE (anything else: increment/append/CDT/mixed read+write) from the per-op
// type bytes.
func classifyAerospikeWrite(r *largebuf.LargeBufferReader, nOps int) string {
	allWrite := true
	allTouch := true
	count := 0
	for i := 0; i < nOps; i++ {
		opSz, err := r.ReadU32BE()
		if err != nil || opSz < 1 {
			break
		}
		opType, err := r.ReadU8()
		if err != nil {
			break
		}
		count++
		if opType != asOpWrite {
			allWrite = false
		}
		if opType != asOpTouch {
			allTouch = false
		}
		if r.Skip(int(opSz)-1) != nil {
			break
		}
	}
	switch {
	case count == 0:
		return "PUT"
	case allTouch:
		return "TOUCH"
	case allWrite:
		return "PUT"
	default:
		return "OPERATE"
	}
}

// aerospikeStatus reads the result_code from a response AS_MSG and maps it to a
// span status (0 = ok). KEY_NOT_FOUND is treated as a non-error miss.
func aerospikeStatus(buf *largebuf.LargeBuffer) (int, request.DBError) {
	if buf == nil || buf.Len() < asProtoHeaderLen+asMsgHeaderLen {
		return 0, request.DBError{}
	}
	version, err := buf.U8At(0)
	if err != nil || version != asProtoVersion {
		return 0, request.DBError{}
	}
	typ, err := buf.U8At(1)
	if err != nil || typ != asTypeMessage {
		return 0, request.DBError{}
	}
	resultCode, err := buf.U8At(asResultCodeOffset)
	if err != nil || resultCode == 0 || resultCode == asResultKeyNotFound {
		return 0, request.DBError{}
	}
	name := aerospikeResultName(resultCode)
	return 1, request.DBError{ErrorCode: name, Description: name}
}

func aerospikeResultName(code uint8) string {
	switch code {
	case 1:
		return "SERVER_ERROR"
	case 2:
		return "KEY_NOT_FOUND_ERROR"
	case 3:
		return "GENERATION_ERROR"
	case 4:
		return "PARAMETER_ERROR"
	case 5:
		return "KEY_EXISTS_ERROR"
	case 6:
		return "BIN_EXISTS_ERROR"
	case 8:
		return "SERVER_FULL"
	case 9:
		return "TIMEOUT"
	case 13:
		return "RECORD_TOO_BIG"
	case 14:
		return "KEY_BUSY"
	case 22:
		return "FORBIDDEN"
	default:
		return uintToStr(uint64(code))
	}
}

func uintToStr(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TCPToAerospikeToSpan(trace *TCPRequestInfo, info *aerospikeInfo, status int, dbError request.DBError) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeAerospikeClient,
		Method:       info.op,
		Path:         info.set,
		Peer:         peer,
		PeerPort:     int(trace.ConnInfo.S_port),
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		Status:       status,
		TraceID:      trace.Tp.TraceId,
		SpanID:       trace.Tp.SpanId,
		ParentSpanID: trace.Tp.ParentId,
		TraceFlags:   trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		DBNamespace:   info.namespace,
		DBSystem:      "aerospike",
		DBError:       dbError,
		Statement:     info.userKey,
		ContentLength: int64(info.batchSize),
	}
}
