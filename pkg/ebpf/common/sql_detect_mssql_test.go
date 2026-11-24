// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestIsMSSQL(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want bool
	}{
		{
			name: "valid batch packet",
			buf:  []byte{0x01, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "valid rpc packet",
			buf:  []byte{0x03, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "valid response packet",
			buf:  []byte{0x04, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "too short",
			buf:  []byte{0x01, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid type",
			buf:  []byte{0x05, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid status",
			buf:  []byte{0x01, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid length too small",
			buf:  []byte{0x01, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid length too large",
			buf:  []byte{0x01, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid window byte",
			buf:  []byte{0x01, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMSSQL(largebuf.NewLargeBufferFrom(tt.buf)))
		})
	}
}

func TestUCS2ToUTF8(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []byte
	}{
		{
			name: "simple ascii",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T'},
		},
		{
			name: "with special chars",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '*', 0, ' ', 0, 'F', 0, 'R', 0, 'O', 0, 'M', 0},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M'},
		},
		{
			name: "odd length",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, 'X'},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ucs2ToUTF8(tt.buf))
		})
	}
}

func makeTDSPacket(pktType, status byte, payload []byte) []byte {
	totalLen := kMSSQLHeaderLen + len(payload)
	hdr := []byte{
		pktType, status,
		byte(totalLen >> 8), byte(totalLen),
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window
	}
	return append(hdr, payload...)
}

func TestExtractTDSPayloads(t *testing.T) {
	sqlPart1 := []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0}
	sqlPart2 := []byte{' ', 0, '1', 0}

	tests := []struct {
		name string
		buf  []byte
		want []byte
	}{
		{
			name: "single packet",
			buf:  makeTDSPacket(kMSSQLBatch, 0x01, sqlPart1),
			want: sqlPart1,
		},
		{
			name: "two packets concatenated",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, sqlPart1),
				makeTDSPacket(kMSSQLBatch, 0x01, sqlPart2)...,
			),
			want: append(sqlPart1, sqlPart2...),
		},
		{
			name: "truncated second packet ignored",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, sqlPart1),
				[]byte{kMSSQLBatch, 0x01, 0x00, 0x0A}..., // header claims 10 bytes but nothing follows
			),
			want: sqlPart1,
		},
		{
			name: "empty payload packet",
			buf:  makeTDSPacket(kMSSQLBatch, 0x01, nil),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTDSPayloads(largebuf.NewLargeBufferFrom(tt.buf))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMSSQLBatchParsing(t *testing.T) {
	selectSQL := []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '*', 0, ' ', 0, 'F', 0, 'R', 0, 'O', 0, 'M', 0, ' ', 0, 't', 0}
	tests := []struct {
		name       string
		buf        []byte
		wantOp     string
		wantTables []string
		wantStmt   string
	}{
		{
			name:   "valid single-packet batch",
			buf:    makeTDSPacket(kMSSQLBatch, 0x01, []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '1', 0}),
			wantOp: "SELECT", wantTables: nil, wantStmt: "SELECT 1",
		},
		{
			name: "sql split across two TDS packets",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, selectSQL[:len(selectSQL)/2]),
				makeTDSPacket(kMSSQLBatch, 0x01, selectSQL[len(selectSQL)/2:])...,
			),
			wantOp: "SELECT", wantTables: []string{"t"}, wantStmt: "SELECT * FROM t",
		},
		{
			name:       "too short",
			buf:        makeTDSPacket(kMSSQLBatch, 0x01, nil),
			wantOp:     "",
			wantTables: nil,
			wantStmt:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, tables, stmt := mssqlExtractBatchSQL(largebuf.NewLargeBufferFrom(tt.buf))
			assert.Equal(t, tt.wantOp, op)
			assert.Equal(t, tt.wantTables, tables)
			assert.Equal(t, tt.wantStmt, stmt)
		})
	}
}

// Packets captured from the Microsoft JDBC driver 12.8.1 against SQL Server 2022.
const (
	jdbcExecuteSQLRequest = "030100990040010016000000120000000200000000000000000001000000ffff0a0000000000e7401f0904d000344600530045004c0045004300540020006e0061006d0065002000460052004f004d002000740020005700480045005200450020006900640020003d002000200040005000300020000000e7401f0904d000340e00400050003000200069006e007400000026040401000000"
	jdbcPrepExecRequest   = "030100a20040010016000000120000000200000000000000000001000000ffff0d0000000001260404000000000000e7401f0904d000340e00400050003000200069006e0074000000e7401f0904d000344600530045004c0045004300540020006e0061006d0065002000460052004f004d002000740020005700480045005200450020006900640020003d00200020004000500030002000000026040402000000"
	jdbcPrepExecResponse  = "0401005e004001008101000000000000000900e764000904d00034046e0061006d006500d10600740077006f00ff1100c10001000000000000007900000000ac0000000100000000000026040401000000fe0000e0000000000000000000"
	jdbcExecuteRequest    = "030100360040010016000000120000000200000000000000000001000000ffff0c000000000026040401000000000026040403000000"
	jdbcResultResponse    = "04010050004001008101000000000000000900e764000904d00034046e0061006d006500d10a0074006800720065006500ff1100c10001000000000000007900000000fe0000e0000000000000000000"
	jdbcCallNoopRequest   = "030100440040010016000000120000000200000000000000000001000000ffff0a0000000000e7401f0904d000341400450058004500430020006e006f006f0070002000"
	jdbcCallParamRequest  = "030100790040010016000000120000000200000000000000000001000000ffff0a0000000000e7401f0904d000342600450058004500430020006700650074005f006e0061006d0065002000200040005000300020000000e7401f0904d000340e00400050003000200069006e007400000026040402000000"

	jdbcSelectStatement = "SELECT name FROM t WHERE id =  @P0 "
)

var mssqlTestAllHeaders = []byte{
	0x16, 0x00, 0x00, 0x00, // TotalLength
	0x12, 0x00, 0x00, 0x00, // HeaderLength
	0x02, 0x00, // transaction descriptor
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TransactionDescriptor
	0x01, 0x00, 0x00, 0x00, // OutstandingRequestCount
}

func ucs2(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func mssqlNamedRPC(withAllHeaders bool, name string) []byte {
	var payload []byte
	if withAllHeaders {
		payload = append(payload, mssqlTestAllHeaders...)
	}
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(name)))
	payload = append(payload, ucs2(name)...)
	payload = append(payload, 0x00, 0x00) // OptionFlags
	return makeTDSPacket(kMSSQLRPC, 0x01, payload)
}

func TestParseMSSQLRPC(t *testing.T) {
	tests := []struct {
		name         string
		buf          []byte
		wantProcID   uint16
		wantProcName string
		wantErr      bool
	}{
		{
			name:       "proc id after ALL_HEADERS",
			buf:        mustHex(t, jdbcExecuteSQLRequest),
			wantProcID: kMSSQLProcIDExecuteSQL,
		},
		{
			name:       "proc id without ALL_HEADERS",
			buf:        makeTDSPacket(kMSSQLRPC, 0x01, []byte{0xFF, 0xFF, 0x0D, 0x00, 0x00, 0x00}),
			wantProcID: kMSSQLProcIDPrepExec,
		},
		{
			name:         "proc name after ALL_HEADERS",
			buf:          mssqlNamedRPC(true, "dbo.get_name"),
			wantProcName: "dbo.get_name",
		},
		{
			name:         "proc name without ALL_HEADERS",
			buf:          mssqlNamedRPC(false, "sp"),
			wantProcName: "sp",
		},
		{
			name: "header split across TDS packets",
			buf: append(
				makeTDSPacket(kMSSQLRPC, 0x00, append(append([]byte{}, mssqlTestAllHeaders...), 0xFF, 0xFF)),
				makeTDSPacket(kMSSQLRPC, 0x01, []byte{0x0C, 0x00, 0x00, 0x00})...,
			),
			wantProcID: kMSSQLProcIDExecute,
		},
		{
			name:    "truncated header",
			buf:     makeTDSPacket(kMSSQLRPC, 0x01, append(append([]byte{}, mssqlTestAllHeaders...), 0xFF, 0xFF)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpc, err := parseMSSQLRPC(largebuf.NewLargeBufferFrom(tt.buf))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantProcID, rpc.procID)
			assert.Equal(t, tt.wantProcName, rpc.procName)
		})
	}
}

func TestMSSQLReadParam(t *testing.T) {
	stmt := ucs2("SELECT 1")
	nvarchar := func(value []byte) []byte {
		p := []byte{0x00, 0x00, kMSSQLTypeNVarChar, 0x40, 0x1F, 0x09, 0x04, 0xD0, 0x00, 0x34}
		return append(binary.LittleEndian.AppendUint16(p, uint16(len(value))), value...)
	}
	plp := func(chunks ...[]byte) []byte {
		p := []byte{0x00, 0x00, kMSSQLTypeNVarChar, 0xFF, 0xFF, 0x09, 0x04, 0xD0, 0x00, 0x34}
		p = binary.LittleEndian.AppendUint64(p, uint64(len(stmt)))
		for _, c := range chunks {
			p = binary.LittleEndian.AppendUint32(p, uint32(len(c)))
			p = append(p, c...)
		}
		return binary.LittleEndian.AppendUint32(p, 0)
	}

	tests := []struct {
		name       string
		buf        []byte
		wantText   string
		wantHandle uint32
		wantErr    bool
	}{
		{name: "nvarchar", buf: nvarchar(stmt), wantText: "SELECT 1"},
		{name: "nvarchar truncated by capture", buf: nvarchar(stmt)[:len(nvarchar(stmt))-4], wantText: "SELECT"},
		{name: "nvarchar(max) chunks", buf: plp(stmt[:6], stmt[6:]), wantText: "SELECT 1"},
		{name: "named intn handle", buf: []byte{0x02, 'h', 0, 'd', 0, 0x00, kMSSQLTypeIntN, 4, 4, 7, 0, 0, 0}, wantHandle: 7},
		{name: "int4 handle", buf: []byte{0x00, 0x00, kMSSQLTypeInt4, 9, 0, 0, 0}, wantHandle: 9},
		{name: "unsupported type", buf: []byte{0x00, 0x00, 0x6D, 8}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.buf).NewReader()
			param, err := mssqlReadParam(&r)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantText, param.text())
			handle, _ := param.int32Value()
			assert.Equal(t, tt.wantHandle, handle)
		})
	}
}

func TestParseHandleFromPrepareResponse(t *testing.T) {
	handle, ok := parseHandleFromPrepareResponse(largebuf.NewLargeBufferFrom(mustHex(t, jdbcPrepExecResponse)))
	assert.True(t, ok)
	assert.Equal(t, uint32(1), handle)

	_, ok = parseHandleFromPrepareResponse(largebuf.NewLargeBufferFrom(mustHex(t, jdbcResultResponse)))
	assert.False(t, ok)
}

func TestMSSQLExecProcedureName(t *testing.T) {
	for stmt, want := range map[string]string{
		"EXEC noop ":                  "noop",
		"exec get_name  @P0 ":         "get_name",
		"  EXECUTE [dbo].[get_name];": "[dbo].[get_name]",
		"EXEC(@sql)":                  "",
		"EXEC @rc = noop":             "",
		"EXECUTED noop":               "",
		"SELECT 1":                    "",
		"EXEC":                        "",
	} {
		t.Run(stmt, func(t *testing.T) {
			assert.Equal(t, want, mssqlExecProcedureName(stmt))
		})
	}
}

func newMSSQLTestContext() *EBPFParseContext {
	return NewEBPFParseContext(&config.EBPFTracer{
		CouchbaseDBCacheSize:                16,
		MySQLPreparedStatementsCacheSize:    16,
		PostgresPreparedStatementsCacheSize: 16,
		MSSQLPreparedStatementsCacheSize:    16,
		KafkaTopicUUIDCacheSize:             16,
		MongoRequestsCacheSize:              16,
	}, nil, nil)
}

func handleMSSQLHex(t *testing.T, ctx *EBPFParseContext, req, resp string) (request.Span, error) {
	t.Helper()
	return handleMSSQL(ctx, &TCPRequestInfo{}, largebuf.NewLargeBufferFrom(mustHex(t, req)), largebuf.NewLargeBufferFrom(mustHex(t, resp)))
}

func TestHandleMSSQLRPC(t *testing.T) {
	t.Run("sp_executesql", func(t *testing.T) {
		span, err := handleMSSQLHex(t, newMSSQLTestContext(), jdbcExecuteSQLRequest, jdbcResultResponse)
		require.NoError(t, err)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, "t", span.Path)
		assert.Equal(t, jdbcSelectStatement, span.Statement)
		assert.Equal(t, "RPC", span.SQLCommand)
	})

	t.Run("sp_prepexec then sp_execute", func(t *testing.T) {
		ctx := newMSSQLTestContext()

		span, err := handleMSSQLHex(t, ctx, jdbcPrepExecRequest, jdbcPrepExecResponse)
		require.NoError(t, err)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, jdbcSelectStatement, span.Statement)

		span, err = handleMSSQLHex(t, ctx, jdbcExecuteRequest, jdbcResultResponse)
		require.NoError(t, err)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, "t", span.Path)
		assert.Equal(t, jdbcSelectStatement, span.Statement)
	})

	t.Run("sp_prepare caches without a span", func(t *testing.T) {
		ctx := newMSSQLTestContext()
		prepare := mustHex(t, jdbcPrepExecRequest)
		prepare[kMSSQLHeaderLen+len(mssqlTestAllHeaders)+2] = kMSSQLProcIDPrepare

		_, err := handleMSSQL(ctx, &TCPRequestInfo{}, largebuf.NewLargeBufferFrom(prepare), largebuf.NewLargeBufferFrom(mustHex(t, jdbcPrepExecResponse)))
		require.ErrorIs(t, err, errIgnore)

		span, err := handleMSSQLHex(t, ctx, jdbcExecuteRequest, jdbcResultResponse)
		require.NoError(t, err)
		assert.Equal(t, jdbcSelectStatement, span.Statement)
	})

	t.Run("sp_execute with unknown handle", func(t *testing.T) {
		_, err := handleMSSQLHex(t, newMSSQLTestContext(), jdbcExecuteRequest, jdbcResultResponse)
		require.ErrorIs(t, err, errFallback)
	})

	t.Run("procedure call through sp_executesql", func(t *testing.T) {
		span, err := handleMSSQLHex(t, newMSSQLTestContext(), jdbcCallNoopRequest, jdbcResultResponse)
		require.NoError(t, err)
		assert.Equal(t, "EXECUTE", span.Method)
		assert.Empty(t, span.Path)
		assert.Equal(t, "EXECUTE noop", span.DBQuerySummary)
		assert.Equal(t, "EXEC noop ", span.Statement)

		span, err = handleMSSQLHex(t, newMSSQLTestContext(), jdbcCallParamRequest, jdbcResultResponse)
		require.NoError(t, err)
		assert.Equal(t, "EXECUTE get_name", span.DBQuerySummary)
	})

	t.Run("procedure called by name", func(t *testing.T) {
		span, err := handleMSSQL(newMSSQLTestContext(), &TCPRequestInfo{}, largebuf.NewLargeBufferFrom(mssqlNamedRPC(true, "dbo.get_name")), largebuf.NewLargeBufferFrom(mustHex(t, jdbcResultResponse)))
		require.NoError(t, err)
		assert.Equal(t, "EXECUTE", span.Method)
		assert.Empty(t, span.Path)
		assert.Equal(t, "EXECUTE dbo.get_name", span.DBQuerySummary)
		assert.Empty(t, span.Statement)
	})
}
