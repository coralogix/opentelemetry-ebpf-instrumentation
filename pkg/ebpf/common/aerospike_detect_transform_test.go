// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// Fixtures are real frames captured from aerospike-server 8.1.2.3 CE driven by
// aerospike-client-go v7 (see testdata/aerospike/fixtures.json). Each request
// fixture's documented op/namespace/set/user_key fields are the ground-truth
// expectations.
type aerospikeFixtures struct {
	Requests []struct {
		Name       string `json:"name"`
		Op         string `json:"op"`
		Namespace  string `json:"namespace"`
		Set        string `json:"set"`
		UserKey    string `json:"user_key"`
		Truncated  bool   `json:"truncated"`
		RequestHex string `json:"request_hex"`
	} `json:"requests"`
	Responses []struct {
		Name        string `json:"name"`
		ResultCode  int    `json:"result_code"`
		ResponseHex string `json:"response_hex"`
	} `json:"responses"`
}

func loadAerospikeFixtures(t *testing.T) aerospikeFixtures {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "aerospike", "fixtures.json"))
	require.NoError(t, err)
	var fx aerospikeFixtures
	require.NoError(t, json.Unmarshal(data, &fx))
	require.NotEmpty(t, fx.Requests)
	return fx
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestParseAerospikeRequest(t *testing.T) {
	fx := loadAerospikeFixtures(t)
	for _, r := range fx.Requests {
		t.Run(r.Name, func(t *testing.T) {
			buf := mustHex(t, r.RequestHex)
			assert.True(t, isAerospikeProto(largebuf.NewLargeBufferFrom(buf)), "should be recognized as aerospike proto")

			info := parseAerospikeRequest(buf)
			require.NotNil(t, info, "request should parse as an AS_MSG data request")
			assert.Equal(t, r.Op, info.op, "operation")
			assert.Equal(t, r.Namespace, info.namespace, "namespace")
			assert.Equal(t, r.Set, info.set, "set")
			assert.Equal(t, r.UserKey, info.userKey, "user key")

			if r.Op == "BATCH" {
				assert.Positive(t, info.batchSize, "batch size should be extracted")
			}
		})
	}
}

func TestAerospikeStatus(t *testing.T) {
	fx := loadAerospikeFixtures(t)
	require.NotEmpty(t, fx.Responses)
	for _, r := range fx.Responses {
		t.Run(r.Name, func(t *testing.T) {
			buf := largebuf.NewLargeBufferFrom(mustHex(t, r.ResponseHex))
			status, dbErr := aerospikeStatus(buf)
			// All captured responses succeeded (result_code 0).
			assert.Equal(t, 0, status)
			assert.Empty(t, dbErr.ErrorCode)
		})
	}
}

func TestAerospikeStatusError(t *testing.T) {
	// Synthesize a KEY_EXISTS_ERROR (result_code 5) response: proto(type 3, size 22)
	// + as_msg header with result_code at body offset 5.
	body := make([]byte, 22)
	body[0] = 22 // header_sz
	body[5] = 5  // result_code = KEY_EXISTS_ERROR
	frame := append([]byte{2, 3, 0, 0, 0, 0, 0, 22}, body...)
	status, dbErr := aerospikeStatus(largebuf.NewLargeBufferFrom(frame))
	assert.Equal(t, 1, status)
	assert.Equal(t, "KEY_EXISTS_ERROR", dbErr.ErrorCode)

	// KEY_NOT_FOUND (2) is a normal miss, not an error.
	body[5] = 2
	frame = append([]byte{2, 3, 0, 0, 0, 0, 0, 22}, body...)
	status, _ = aerospikeStatus(largebuf.NewLargeBufferFrom(frame))
	assert.Equal(t, 0, status)
}

func findRequest(t *testing.T, fx aerospikeFixtures, name string) string {
	t.Helper()
	for _, r := range fx.Requests {
		if r.Name == name {
			return r.RequestHex
		}
	}
	t.Fatalf("request fixture %q not found", name)
	return ""
}

func findResponse(t *testing.T, fx aerospikeFixtures, name string) string {
	t.Helper()
	for _, r := range fx.Responses {
		if r.Name == name {
			return r.ResponseHex
		}
	}
	t.Fatalf("response fixture %q not found", name)
	return ""
}

func TestMatchAerospikeSpan(t *testing.T) {
	fx := loadAerospikeFixtures(t)
	req := largebuf.NewLargeBufferFrom(mustHex(t, findRequest(t, fx, "put")))
	resp := largebuf.NewLargeBufferFrom(mustHex(t, findResponse(t, fx, "write_ok")))

	event := &TCPRequestInfo{}
	span, ignore, matched, err := matchAerospike(event, req, resp)
	require.NoError(t, err)
	require.True(t, matched, "should match aerospike")
	assert.False(t, ignore)

	assert.Equal(t, request.EventTypeAerospikeClient, span.Type)
	assert.Equal(t, "PUT", span.Method)
	assert.Equal(t, "s_put", span.Path)
	assert.Equal(t, "test", span.DBNamespace)
	assert.Equal(t, "aerospike", span.DBSystem)
	assert.Equal(t, "k_put", span.Statement)
	assert.Equal(t, 0, span.Status)
	assert.Equal(t, "PUT test.s_put", span.TraceName())
}

func TestMatchAerospikeReversed(t *testing.T) {
	fx := loadAerospikeFixtures(t)
	// Buffers swapped, as if OBI attached mid-connection and saw the response first.
	resp := largebuf.NewLargeBufferFrom(mustHex(t, findResponse(t, fx, "get_ok")))
	req := largebuf.NewLargeBufferFrom(mustHex(t, findRequest(t, fx, "get")))

	event := &TCPRequestInfo{}
	span, _, matched, err := matchAerospike(event, resp, req)
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "s_get", span.Path)
}

func TestMatchAerospikeNonAerospike(t *testing.T) {
	event := &TCPRequestInfo{}
	_, _, matched, _ := matchAerospike(event,
		largebuf.NewLargeBufferFrom([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
		largebuf.NewLargeBufferFrom([]byte("HTTP/1.1 200 OK\r\n\r\n")))
	assert.False(t, matched, "HTTP must not be misclassified as Aerospike")
}
