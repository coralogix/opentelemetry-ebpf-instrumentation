// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type mssqlPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtID   uint32
}

const (
	kMSSQLHeaderLen = 8
	kMSSQLBatch     = 1
	kMSSQLRPC       = 3
	kMSSQLResponse  = 4

	// Well-known RPC procedure IDs (MS-TDS 2.2.6.6)
	kMSSQLProcIDExecuteSQL = 10
	kMSSQLProcIDPrepare    = 11
	kMSSQLProcIDExecute    = 12
	kMSSQLProcIDPrepExec   = 13

	// NameLenProcID value announcing that a procedure ID follows instead of a name
	kMSSQLProcIDMarker   = 0xFFFF
	kMSSQLOptionFlagsLen = 2
	kMSSQLUCS2CharLen    = 2

	// sp_prepare and sp_prepexec take @handle, @params and then @stmt
	kMSSQLPreparedStmtParamIndex = 2

	// ALL_HEADERS (MS-TDS 2.2.5.3)
	kMSSQLAllHeadersTotalLenSize       = 4
	kMSSQLHeaderLenSize                = 4
	kMSSQLHeaderTypeSize               = 2
	kMSSQLAllHeadersPrefixLen          = kMSSQLAllHeadersTotalLenSize + kMSSQLHeaderLenSize + kMSSQLHeaderTypeSize
	kMSSQLHeaderTypeQueryNotifications = 1
	kMSSQLHeaderTypeTraceActivity      = 3

	kMSSQLExecuteOperation = "EXECUTE"
	kMSSQLExecKeyword      = "EXEC"

	// TDS Token types
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7091f6f6-b83d-4ed2-afeb-ba5013dfb18f
	kMSSQLTokenReturnValue = 0xAC

	// TDS TypeInfo type identifiers
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/d2ed21d6-527b-46ac-8035-94f6f68eb9a8
	kMSSQLTypeIntN       = 0x26 // variable-length integer (length byte precedes value)
	kMSSQLTypeInt4       = 0x38 // fixed-length 4-byte integer
	kMSSQLTypeBigVarChar = 0xA7
	kMSSQLTypeNVarChar   = 0xE7

	kMSSQLInt4Len        = 4
	kMSSQLIntNMaxLenSize = 1
	kMSSQLCollationLen   = 5
	kMSSQLMaxLenPLP      = 0xFFFF // MAXLEN of a (max) type, whose value is PLP encoded
	kMSSQLNullLen        = 0xFFFF
	kMSSQLPLPNull        = math.MaxUint64

	// Fixed lengths for TDS RETURNVALUE (0xAC) token fields that follow the name
	kMSSQLStatusLen   = 1
	kMSSQLUserTypeLen = 4
	kMSSQLFlagsLen    = 2
	// Sum of Status, UserType, and Flags fields
	kMSSQLReturnValueMetadataLen = kMSSQLStatusLen + kMSSQLUserTypeLen + kMSSQLFlagsLen

	// Maximum size of a single TDS packet as defined by the protocol.
	// Defaults to 4096, but can be negotiated up to 32767.
	kMSSQLMaxPacketSize = 32767
)

// isMSSQL checks whether b looks like a TDS packet carrying SQL traffic.
// It intentionally excludes login (0x10) and pre-login (0x12) packet types:
// those are accepted by the BPF classifier to identify the connection early,
// but they carry no SQL and are never passed to this parser.
func isMSSQL(b *largebuf.LargeBuffer) bool {
	if b.Len() < kMSSQLHeaderLen {
		return false
	}

	pktType, err := b.U8At(0)
	if err != nil {
		return false
	}
	if pktType != kMSSQLBatch && pktType != kMSSQLRPC && pktType != kMSSQLResponse {
		return false
	}

	// Status byte check: upper 4 bits are reserved and should be 0.
	// This helps filter out random binary data that might match the packet type.
	status, err := b.U8At(1)
	if err != nil {
		return false
	}
	if (status & 0xF0) != 0 {
		return false
	}

	// Length is big-endian in TDS. It's the total number of bytes in the Packet
	// including the 8-byte header.
	length, err := b.U16BEAt(2)
	if err != nil {
		return false
	}

	// Check the length:
	// 1. MUST be at least 8 bytes (the size of the header itself).
	// 2. MUST be less than or equal to the maximum allowable negotiated packet
	//    size (32,767 bytes).
	// Note: While the *negotiated* packet size must be between 512 and 32,767,
	// individual packets can be much smaller (e.g., a simple SELECT batch).
	if length < uint16(kMSSQLHeaderLen) || length > kMSSQLMaxPacketSize {
		return false
	}

	// The Window byte (at offset 7) is currently unused and should be 0.
	window, err := b.U8At(7)
	if err != nil {
		return false
	}
	return window == 0
}

func ucs2ToUTF8(b []byte) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	out := make([]byte, 0, len(b))

	for i := 0; i < len(b); i += 2 {
		u1 := binary.LittleEndian.Uint16(b[i:])

		if utf16.IsSurrogate(rune(u1)) && i+2 < len(b) {
			u2 := binary.LittleEndian.Uint16(b[i+2:])
			if r := utf16.DecodeRune(rune(u1), rune(u2)); r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
				i += 2
				continue
			}
		}

		out = utf8.AppendRune(out, rune(u1))
	}

	return out
}

// extractTDSPayloads iterates over all TDS packets in b and returns their
// concatenated payload bytes with every 8-byte packet header stripped out.
// This is necessary because a single TDS message may span multiple packets,
// and naively treating the whole buffer as one payload would corrupt decoding
// wherever an embedded packet header appears.
func extractTDSPayloads(b *largebuf.LargeBuffer) []byte {
	total := b.Len()
	var payload []byte

	for offset := 0; offset+kMSSQLHeaderLen <= total; {
		pktLen, err := b.U16BEAt(offset + 2)
		if err != nil || int(pktLen) < kMSSQLHeaderLen || offset+int(pktLen) > total {
			break
		}
		payloadLen := int(pktLen) - kMSSQLHeaderLen
		if payloadLen > 0 {
			chunk, err := b.UnsafeViewAt(offset+kMSSQLHeaderLen, payloadLen)
			if err != nil {
				break
			}
			payload = append(payload, chunk...)
		}
		offset += int(pktLen)
	}

	return payload
}

func mssqlExtractBatchSQL(b *largebuf.LargeBuffer) (string, []string, string) {
	if b.Len() <= kMSSQLHeaderLen {
		return "", nil, ""
	}

	pktType, _ := b.U8At(0)
	if pktType == kMSSQLBatch {
		stmt := ucs2ToUTF8(extractTDSPayloads(b))
		return detectSQL(stmt)
	}

	return "", nil, ""
}

func handleMSSQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		op, stmt string
		tables   []string
		span     request.Span
	)

	if requestBuffer.Len() < kMSSQLHeaderLen {
		slog.Debug("MSSQL request too short")
		return span, errFallback
	}

	reqRaw := requestBuffer.UnsafeView()
	respRaw := responseBuffer.UnsafeView()

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMSSQL, reqRaw)
	sqlError := sqlprune.SQLParseError(request.DBMSSQL, respRaw)

	switch sqlCommand {
	case "SQL_BATCH":
		op, tables, stmt = mssqlExtractBatchSQL(requestBuffer)
	case "RPC":
		return handleMSSQLRPC(parseCtx, event, requestBuffer, responseBuffer, sqlError)
	}

	if !validSQL(op, len(tables) > 0, request.DBMSSQL) {
		slog.Debug("MSSQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, tables, stmt, request.DBMSSQL, sqlCommand, sqlError), nil
}

func handleMSSQLRPC(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, sqlError *request.SQLError) (request.Span, error) {
	rpc, err := parseMSSQLRPC(requestBuffer)
	if err != nil {
		slog.Debug("MSSQL RPC request could not be parsed", "error", err)
		return request.Span{}, errFallback
	}

	if rpc.procName != "" {
		return mssqlProcedureSpan(event, rpc.procName, "", sqlError), nil
	}

	var stmt string
	switch rpc.procID {
	case kMSSQLProcIDExecuteSQL:
		stmt = mssqlReadStatementParam(&rpc.params, 0)
	case kMSSQLProcIDPrepExec:
		stmt = mssqlReadStatementParam(&rpc.params, kMSSQLPreparedStmtParamIndex)
		mssqlCachePreparedStatement(parseCtx, event, responseBuffer, stmt)
	case kMSSQLProcIDPrepare:
		stmt = mssqlReadStatementParam(&rpc.params, kMSSQLPreparedStmtParamIndex)
		mssqlCachePreparedStatement(parseCtx, event, responseBuffer, stmt)
		return request.Span{}, errIgnore
	case kMSSQLProcIDExecute:
		stmt = mssqlLookupPreparedStatement(parseCtx, event, &rpc.params)
	default:
		slog.Debug("MSSQL RPC procedure ID unhandled", "procID", rpc.procID)
		return request.Span{}, errFallback
	}

	op, tables := sqlprune.SQLParseOperationAndTables(stmt)
	if validSQL(op, len(tables) > 0, request.DBMSSQL) {
		return TCPToSQLToSpan(event, op, tables, stmt, request.DBMSSQL, "RPC", sqlError), nil
	}

	if proc := mssqlExecProcedureName(stmt); proc != "" {
		return mssqlProcedureSpan(event, proc, stmt, sqlError), nil
	}

	slog.Debug("MSSQL RPC operation is invalid", "procID", rpc.procID, "stmt", stmt)
	return request.Span{}, errFallback
}

func mssqlProcedureSpan(event *TCPRequestInfo, proc, stmt string, sqlError *request.SQLError) request.Span {
	span := TCPToSQLToSpan(event, kMSSQLExecuteOperation, []string{proc}, stmt, request.DBMSSQL, "RPC", sqlError)
	// A stored procedure is not a collection.
	span.Path = ""
	return span
}

// mssqlExecProcedureName returns the procedure invoked by an
// "EXEC[UTE] procedure ..." statement, or "" for any other statement.
func mssqlExecProcedureName(stmt string) string {
	rest, found := mssqlCutKeyword(strings.TrimLeftFunc(stmt, unicode.IsSpace), kMSSQLExecuteOperation)
	if !found {
		rest, found = mssqlCutKeyword(strings.TrimLeftFunc(stmt, unicode.IsSpace), kMSSQLExecKeyword)
	}
	if !found {
		return ""
	}

	rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
	if end := strings.IndexFunc(rest, isMSSQLProcedureNameEnd); end >= 0 {
		rest = rest[:end]
	}
	if rest == "" || rest[0] == '@' {
		return ""
	}
	return rest
}

func mssqlCutKeyword(s, keyword string) (string, bool) {
	if len(s) <= len(keyword) || !strings.EqualFold(s[:len(keyword)], keyword) {
		return "", false
	}
	if !unicode.IsSpace(rune(s[len(keyword)])) {
		return "", false
	}
	return s[len(keyword):], true
}

func isMSSQLProcedureNameEnd(r rune) bool {
	return unicode.IsSpace(r) || r == ';' || r == '('
}

func mssqlCachePreparedStatement(parseCtx *EBPFParseContext, event *TCPRequestInfo, responseBuffer *largebuf.LargeBuffer, stmt string) {
	if stmt == "" {
		return
	}
	handle, ok := parseHandleFromPrepareResponse(responseBuffer)
	if !ok {
		return
	}
	parseCtx.mssqlPreparedStatements.Add(mssqlPreparedStatementsKey{
		connInfo: event.ConnInfo,
		stmtID:   handle,
	}, stmt)
}

func mssqlLookupPreparedStatement(parseCtx *EBPFParseContext, event *TCPRequestInfo, params *largebuf.LargeBufferReader) string {
	param, err := mssqlReadParam(params)
	if err != nil {
		return ""
	}
	handle, ok := param.int32Value()
	if !ok {
		return ""
	}
	stmt, found := parseCtx.mssqlPreparedStatements.Get(mssqlPreparedStatementsKey{
		connInfo: event.ConnInfo,
		stmtID:   handle,
	})
	if !found {
		slog.Debug("MSSQL sp_execute with unknown handle", "handle", handle)
	}
	return stmt
}

// mssqlReadStatementParam returns the text of the RPC parameter at index, or
// "" if it can't be read as a string.
func mssqlReadStatementParam(params *largebuf.LargeBufferReader, index int) string {
	for range index {
		if _, err := mssqlReadParam(params); err != nil {
			return ""
		}
	}
	param, err := mssqlReadParam(params)
	if err != nil {
		return ""
	}
	return param.text()
}

type mssqlRPCRequest struct {
	procID   uint16
	procName string
	params   largebuf.LargeBufferReader
}

// parseMSSQLRPC decodes the header of an RPC request (MS-TDS 2.2.6.6) and
// returns a reader positioned at its first parameter.
func parseMSSQLRPC(b *largebuf.LargeBuffer) (mssqlRPCRequest, error) {
	var rpc mssqlRPCRequest

	r := largebuf.NewLargeBufferFrom(extractTDSPayloads(b)).NewReader()
	if err := mssqlSkipAllHeaders(&r); err != nil {
		return rpc, err
	}

	nameLen, err := r.ReadU16LE()
	if err != nil {
		return rpc, err
	}

	if nameLen == kMSSQLProcIDMarker {
		rpc.procID, err = r.ReadU16LE()
	} else {
		var name []byte
		name, err = r.ReadN(int(nameLen) * kMSSQLUCS2CharLen)
		rpc.procName = string(ucs2ToUTF8(name))
	}
	if err != nil {
		return rpc, err
	}

	if err := r.Skip(kMSSQLOptionFlagsLen); err != nil {
		return rpc, err
	}

	rpc.params = r
	return rpc, nil
}

// mssqlSkipAllHeaders skips the ALL_HEADERS block that TDS 7.2+ clients put
// before the RPC header. Older clients omit it, so it is only skipped when its
// declared lengths and first header type are consistent.
func mssqlSkipAllHeaders(r *largebuf.LargeBufferReader) error {
	prefix, err := r.Peek(kMSSQLAllHeadersPrefixLen)
	if err != nil {
		return nil
	}

	totalLen := binary.LittleEndian.Uint32(prefix)
	headerLen := binary.LittleEndian.Uint32(prefix[kMSSQLAllHeadersTotalLenSize:])
	headerType := binary.LittleEndian.Uint16(prefix[kMSSQLAllHeadersTotalLenSize+kMSSQLHeaderLenSize:])

	if totalLen > uint32(r.Remaining()) ||
		headerLen < kMSSQLHeaderLenSize+kMSSQLHeaderTypeSize ||
		headerLen > totalLen-kMSSQLAllHeadersTotalLenSize ||
		headerType < kMSSQLHeaderTypeQueryNotifications ||
		headerType > kMSSQLHeaderTypeTraceActivity {
		return nil
	}

	return r.Skip(int(totalLen))
}

type mssqlParam struct {
	typ   uint8
	value []byte
}

func (p mssqlParam) int32Value() (uint32, bool) {
	if (p.typ != kMSSQLTypeIntN && p.typ != kMSSQLTypeInt4) || len(p.value) != kMSSQLInt4Len {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p.value), true
}

func (p mssqlParam) text() string {
	switch p.typ {
	case kMSSQLTypeNVarChar:
		return string(ucs2ToUTF8(p.value))
	case kMSSQLTypeBigVarChar:
		return string(p.value)
	}
	return ""
}

// mssqlReadParam reads one RPC parameter (ParamMetaData followed by its
// value). Values cut short by the capture limit are returned truncated.
func mssqlReadParam(r *largebuf.LargeBufferReader) (mssqlParam, error) {
	nameLen, err := r.ReadU8()
	if err != nil {
		return mssqlParam{}, err
	}
	if err := r.Skip(int(nameLen)*kMSSQLUCS2CharLen + kMSSQLStatusLen); err != nil {
		return mssqlParam{}, err
	}
	return mssqlReadTypedValue(r)
}

// mssqlReadTypedValue reads a TYPE_INFO followed by its value, for the types
// that carry prepared statement handles and statement text.
func mssqlReadTypedValue(r *largebuf.LargeBufferReader) (mssqlParam, error) {
	typ, err := r.ReadU8()
	if err != nil {
		return mssqlParam{}, err
	}

	param := mssqlParam{typ: typ}
	switch typ {
	case kMSSQLTypeInt4:
		param.value, err = r.ReadN(kMSSQLInt4Len)
	case kMSSQLTypeIntN:
		param.value, err = mssqlReadIntN(r)
	case kMSSQLTypeNVarChar, kMSSQLTypeBigVarChar:
		param.value, err = mssqlReadVarChar(r)
	default:
		err = fmt.Errorf("unsupported MSSQL type 0x%x", typ)
	}
	return param, err
}

func mssqlReadIntN(r *largebuf.LargeBufferReader) ([]byte, error) {
	if err := r.Skip(kMSSQLIntNMaxLenSize); err != nil {
		return nil, err
	}
	length, err := r.ReadU8()
	if err != nil {
		return nil, err
	}
	return r.ReadN(int(length))
}

func mssqlReadVarChar(r *largebuf.LargeBufferReader) ([]byte, error) {
	maxLen, err := r.ReadU16LE()
	if err != nil {
		return nil, err
	}
	if err := r.Skip(kMSSQLCollationLen); err != nil {
		return nil, err
	}

	if maxLen == kMSSQLMaxLenPLP {
		return mssqlReadPLP(r)
	}

	length, err := r.ReadU16LE()
	if err != nil || length == kMSSQLNullLen {
		return nil, err
	}
	return r.ReadN(min(int(length), r.Remaining()))
}

// mssqlReadPLP reads a partially length-prefixed value: a total length
// followed by length-prefixed chunks and a zero-length terminator.
func mssqlReadPLP(r *largebuf.LargeBufferReader) ([]byte, error) {
	totalLen, err := r.ReadU64LE()
	if err != nil || totalLen == kMSSQLPLPNull {
		return nil, err
	}

	var value []byte
	for r.Remaining() > 0 {
		chunkLen, err := r.ReadU32LE()
		if err != nil || chunkLen == 0 {
			break
		}
		chunk, err := r.ReadN(min(int(chunkLen), r.Remaining()))
		if err != nil {
			break
		}
		value = append(value, chunk...)
	}
	return value, nil
}

// parseHandleFromPrepareResponse returns the prepared statement handle from
// the RETURNVALUE token (MS-TDS 2.2.7.18) that sp_prepare and sp_prepexec send
// back for their first, OUTPUT, parameter.
func parseHandleFromPrepareResponse(b *largebuf.LargeBuffer) (uint32, bool) {
	r := largebuf.NewLargeBufferFrom(extractTDSPayloads(b)).NewReader()

	for {
		idx := r.IndexByte(kMSSQLTokenReturnValue)
		if idx < 0 {
			return 0, false
		}
		_ = r.Skip(idx + 1)

		if handle, ok := mssqlReadHandleReturnValue(r); ok {
			return handle, true
		}
	}
}

func mssqlReadHandleReturnValue(r largebuf.LargeBufferReader) (uint32, bool) {
	ordinal, err := r.ReadU16LE()
	if err != nil || ordinal != 0 {
		return 0, false
	}
	nameLen, err := r.ReadU8()
	if err != nil {
		return 0, false
	}
	if err := r.Skip(int(nameLen)*kMSSQLUCS2CharLen + kMSSQLReturnValueMetadataLen); err != nil {
		return 0, false
	}
	param, err := mssqlReadTypedValue(&r)
	if err != nil {
		return 0, false
	}
	return param.int32Value()
}
