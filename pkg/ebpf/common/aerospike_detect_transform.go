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

	// op type ids
	asOpWrite = 2
	asOpTouch = 11

	// largest declared proto body we will treat as plausibly Aerospike
	asMaxBodyLen = 128 * 1024 * 1024
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

// asProtoType validates the 8-byte proto header and returns (type, ok). The
// declared body length is validated for sanity but not returned: the captured
// buffer may be shorter than the declared length when the kernel truncated a
// large frame (e.g. an 8 KB scan request), so callers parse against what they
// actually have.
func asProtoType(buf []uint8) (uint8, bool) {
	if len(buf) < asProtoHeaderLen {
		return 0, false
	}
	if buf[0] != asProtoVersion {
		return 0, false
	}
	typ := buf[1]
	switch typ {
	case asTypeInfo, asTypeSecurity, asTypeMessage, asTypeCompressed:
	default:
		return 0, false
	}
	bodyLen := int(beUint(buf[2:8]))
	if bodyLen <= 0 || bodyLen > asMaxBodyLen {
		return 0, false
	}
	return typ, true
}

// isAerospikeProto reports whether a buffer begins with a plausible Aerospike
// proto header of any message type.
func isAerospikeProto(buf *largebuf.LargeBuffer) bool {
	if buf == nil {
		return false
	}
	_, ok := asProtoType(buf.UnsafeView())
	return ok
}

// asMsgIsRequest distinguishes a request from a response AS_MSG body. Requests
// always carry at least one read/batch/write intent bit; responses do not.
func asMsgIsRequest(info1, info2 uint8) bool {
	return info1&(asInfo1Read|asInfo1Batch) != 0 || info2&asInfo2Write != 0
}

// parseAerospikeRequest parses a type-3 AS_MSG request frame. It returns nil if
// the buffer is not a type-3 request (info/auth/compressed, a response, or
// malformed). Parsing is defensive: it always advances by the declared field/op
// sizes and stops at the end of the captured (possibly truncated) buffer.
func parseAerospikeRequest(buf []uint8) *aerospikeInfo {
	typ, ok := asProtoType(buf)
	if !ok || typ != asTypeMessage {
		return nil
	}
	body := buf[asProtoHeaderLen:]
	if len(body) < asMsgHeaderLen {
		return nil
	}
	// header_sz is a constant 22; checking it makes the (version==2, type==3,
	// header_sz==22, request-intent bits) signature strong enough to classify the
	// connection from a single frame without false positives.
	if body[0] != asMsgHeaderLen {
		return nil
	}
	info1, info2 := body[1], body[2]
	if !asMsgIsRequest(info1, info2) {
		return nil
	}
	nFields := int(beUint(body[18:20]))

	info := &aerospikeInfo{}
	hasDigest := false
	hasIndex := false
	hasUDF := false

	p := asMsgHeaderLen
	for i := 0; i < nFields && p+4 <= len(body); i++ {
		fsz := int(beUint(body[p : p+4]))
		if fsz < 1 || p+4+fsz > len(body) {
			break
		}
		ftype := body[p+4]
		val := body[p+5 : p+4+fsz]
		switch {
		case ftype == asFieldNamespace:
			info.namespace = string(val)
		case ftype == asFieldSet:
			info.set = string(val)
		case ftype == asFieldKey:
			// value is prefixed by a 1-byte particle type; decode string keys.
			if len(val) > 1 {
				info.userKey = string(val[1:])
			}
		case ftype == asFieldDigestRipe:
			hasDigest = true
		case ftype >= asFieldIndexNameLo && ftype <= asFieldIndexHi:
			hasIndex = true
		case ftype >= asFieldUDFLo && ftype <= asFieldUDFHi:
			hasUDF = true
		}
		p += 4 + fsz
	}

	info.op = classifyAerospikeOp(info1, info2, body, p, hasDigest, hasIndex, hasUDF, &info.batchSize)
	return info
}

// classifyAerospikeOp derives the operation name from the info flags plus, for
// writes, the per-op type bytes (to separate PUT / TOUCH / OPERATE). opStart is
// the offset of the first op within body.
func classifyAerospikeOp(info1, info2 uint8, body []uint8, opStart int, hasDigest, hasIndex, hasUDF bool, batchSize *int) string {
	switch {
	case hasUDF:
		return "UDF"
	case info1&asInfo1Batch != 0:
		if bs := aerospikeBatchSize(body); bs > 0 {
			*batchSize = bs
		}
		return "BATCH"
	case info2&asInfo2Write != 0 && info2&asInfo2Delete != 0:
		return "DELETE"
	case info2&asInfo2Write != 0:
		return classifyAerospikeWrite(body, opStart)
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
// OPERATE (anything else: increment/append/CDT/mixed read+write).
func classifyAerospikeWrite(body []uint8, opStart int) string {
	allWrite := true
	allTouch := true
	count := 0
	p := opStart
	for p+4 <= len(body) {
		opSz := int(beUint(body[p : p+4]))
		if opSz < 1 || p+4+opSz > len(body) {
			break
		}
		opType := body[p+4]
		count++
		if opType != asOpWrite {
			allWrite = false
		}
		if opType != asOpTouch {
			allTouch = false
		}
		p += 4 + opSz
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

// aerospikeBatchSize best-effort counts the entries in a batch request from the
// batch field header (field type 41/42); 0 if it can't be determined.
func aerospikeBatchSize(body []uint8) int {
	nFields := int(beUint(body[18:20]))
	p := asMsgHeaderLen
	for i := 0; i < nFields && p+4 <= len(body); i++ {
		fsz := int(beUint(body[p : p+4]))
		if fsz < 1 || p+4+fsz > len(body) {
			break
		}
		ftype := body[p+4]
		if (ftype == 41 || ftype == 42) && fsz >= 5 {
			// batch field value begins with a 4-byte count of operations.
			return int(beUint(body[p+5 : p+9]))
		}
		p += 4 + fsz
	}
	return 0
}

// aerospikeStatus reads the result_code from a response AS_MSG and maps it to a
// span status (0 = ok). KEY_NOT_FOUND is treated as a non-error miss.
func aerospikeStatus(buf *largebuf.LargeBuffer) (int, request.DBError) {
	if buf == nil {
		return 0, request.DBError{}
	}
	data := buf.UnsafeView()
	typ, ok := asProtoType(data)
	if !ok || typ != asTypeMessage {
		return 0, request.DBError{}
	}
	if len(data) < asProtoHeaderLen+asMsgHeaderLen {
		return 0, request.DBError{}
	}
	resultCode := data[asProtoHeaderLen+5]
	if resultCode == 0 || resultCode == asResultKeyNotFound {
		return 0, request.DBError{}
	}
	return 1, request.DBError{
		ErrorCode:   aerospikeResultName(resultCode),
		Description: aerospikeResultName(resultCode),
	}
}

const asResultKeyNotFound = 2

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
