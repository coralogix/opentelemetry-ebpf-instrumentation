// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"
)

// Helper functions to create Couchbase packets for testing

func makeCouchbaseRequestPacket(opcode couchbasekv.Opcode, key string, value string, extras []byte) []byte {
	keyLen := uint16(len(key))
	extrasLen := uint8(len(extras))
	valueLen := len(value)
	bodyLen := uint32(int(extrasLen) + int(keyLen) + valueLen)

	pkt := make([]byte, couchbasekv.HeaderLen)
	pkt[0] = byte(couchbasekv.MagicClientRequest)
	pkt[1] = byte(opcode)
	binary.BigEndian.PutUint16(pkt[2:4], keyLen)
	pkt[4] = extrasLen
	pkt[5] = byte(couchbasekv.DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], 0) // vbucket
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], 12345) // opaque
	binary.BigEndian.PutUint64(pkt[16:24], 0)     // cas

	pkt = append(pkt, extras...)
	pkt = append(pkt, []byte(key)...)
	pkt = append(pkt, []byte(value)...)

	return pkt
}

func makeCouchbaseResponsePacket(opcode couchbasekv.Opcode, status couchbasekv.Status, value string) []byte {
	valueLen := len(value)
	bodyLen := uint32(valueLen)

	pkt := make([]byte, couchbasekv.HeaderLen)
	pkt[0] = byte(couchbasekv.MagicServerResponse)
	pkt[1] = byte(opcode)
	binary.BigEndian.PutUint16(pkt[2:4], 0) // keyLen
	pkt[4] = 0                              // extrasLen
	pkt[5] = byte(couchbasekv.DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(status))
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], 12345) // opaque
	binary.BigEndian.PutUint64(pkt[16:24], 0)     // cas

	pkt = append(pkt, []byte(value)...)

	return pkt
}

func newTestConnInfo() BpfConnectionInfoT {
	return BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},
		S_port: 54321,
		D_port: 11210,
	}
}

func TestHandleSelectBucket(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo := newTestConnInfo()

	tests := []struct {
		name           string
		bucketName     string
		responseStatus couchbasekv.Status
		expectCached   bool
	}{
		{
			name:           "successful bucket selection",
			bucketName:     "mybucket",
			responseStatus: couchbasekv.StatusSuccess,
			expectCached:   true,
		},
		{
			name:           "failed bucket selection - not found",
			bucketName:     "nonexistent",
			responseStatus: couchbasekv.StatusKeyNotFound,
			expectCached:   false,
		},
		{
			name:           "failed bucket selection - auth error",
			bucketName:     "protected",
			responseStatus: couchbasekv.StatusAuthError,
			expectCached:   false,
		},
		{
			name:           "empty bucket name",
			bucketName:     "",
			responseStatus: couchbasekv.StatusSuccess,
			expectCached:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Purge()

			reqPacket, err := couchbasekv.ParsePacket(
				makeCouchbaseRequestPacket(couchbasekv.OpcodeSelectBucket, tt.bucketName, "", nil),
			)
			require.NoError(t, err)

			responseBuf := makeCouchbaseResponsePacket(couchbasekv.OpcodeSelectBucket, tt.responseStatus, "")

			handleSelectBucket(connInfo, reqPacket, responseBuf, cache)

			bucketInfo, found := cache.Get(connInfo)
			assert.Equal(t, tt.expectCached, found)

			if tt.expectCached {
				assert.Equal(t, tt.bucketName, bucketInfo.Bucket)
				assert.Empty(t, bucketInfo.Scope)
				assert.Empty(t, bucketInfo.Collection)
			}
		})
	}
}

func TestHandleSelectBucketNilCache(t *testing.T) {
	connInfo := newTestConnInfo()

	reqPacket, err := couchbasekv.ParsePacket(
		makeCouchbaseRequestPacket(couchbasekv.OpcodeSelectBucket, "mybucket", "", nil),
	)
	require.NoError(t, err)

	responseBuf := makeCouchbaseResponsePacket(couchbasekv.OpcodeSelectBucket, couchbasekv.StatusSuccess, "")

	// Should not panic with nil cache
	handleSelectBucket(connInfo, reqPacket, responseBuf, nil)
}

func TestHandleGetCollectionID(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo := newTestConnInfo()

	tests := []struct {
		name             string
		scopeCollection  string
		responseStatus   couchbasekv.Status
		preCachedBucket  string
		expectScope      string
		expectCollection string
		expectCached     bool
	}{
		{
			name:             "successful collection lookup",
			scopeCollection:  "myscope.mycollection",
			responseStatus:   couchbasekv.StatusSuccess,
			preCachedBucket:  "mybucket",
			expectScope:      "myscope",
			expectCollection: "mycollection",
			expectCached:     true,
		},
		{
			name:             "collection lookup without pre-cached bucket",
			scopeCollection:  "scope1.collection1",
			responseStatus:   couchbasekv.StatusSuccess,
			preCachedBucket:  "",
			expectScope:      "scope1",
			expectCollection: "collection1",
			expectCached:     true,
		},
		{
			name:             "failed collection lookup",
			scopeCollection:  "badscope.badcollection",
			responseStatus:   couchbasekv.StatusKeyNotFound,
			preCachedBucket:  "mybucket",
			expectScope:      "",
			expectCollection: "",
			expectCached:     false,
		},
		{
			name:             "invalid scope.collection format - no dot",
			scopeCollection:  "invalidformat",
			responseStatus:   couchbasekv.StatusSuccess,
			preCachedBucket:  "mybucket",
			expectScope:      "",
			expectCollection: "",
			expectCached:     false,
		},
		{
			name:             "empty scope.collection",
			scopeCollection:  "",
			responseStatus:   couchbasekv.StatusSuccess,
			preCachedBucket:  "mybucket",
			expectScope:      "",
			expectCollection: "",
			expectCached:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Purge()

			// Pre-cache bucket info if specified
			if tt.preCachedBucket != "" {
				cache.Add(connInfo, CouchbaseBucketInfo{Bucket: tt.preCachedBucket})
			}

			reqPacket, err := couchbasekv.ParsePacket(
				makeCouchbaseRequestPacket(couchbasekv.OpcodeGetCollectionID, "", tt.scopeCollection, nil),
			)
			require.NoError(t, err)

			responseBuf := makeCouchbaseResponsePacket(couchbasekv.OpcodeGetCollectionID, tt.responseStatus, "")

			handleGetCollectionID(connInfo, reqPacket, responseBuf, cache)

			bucketInfo, found := cache.Get(connInfo)

			if tt.expectCached || tt.preCachedBucket != "" {
				assert.True(t, found)
				if tt.expectCached {
					assert.Equal(t, tt.expectScope, bucketInfo.Scope)
					assert.Equal(t, tt.expectCollection, bucketInfo.Collection)
				}
				if tt.preCachedBucket != "" && !tt.expectCached {
					// Should preserve the original bucket
					assert.Equal(t, tt.preCachedBucket, bucketInfo.Bucket)
				}
			} else {
				assert.False(t, found)
			}
		})
	}
}

func TestProcessCouchbaseEvent(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo := newTestConnInfo()

	tests := []struct {
		name           string
		opcode         couchbasekv.Opcode
		key            string
		value          string
		responseStatus couchbasekv.Status
		preCachedInfo  *CouchbaseBucketInfo
		expectIgnore   bool
		expectError    bool
		expectInfo     *CouchbaseInfo
	}{
		{
			name:           "GET request with cached bucket info",
			opcode:         couchbasekv.OpcodeGet,
			key:            "mykey",
			responseStatus: couchbasekv.StatusSuccess,
			preCachedInfo:  &CouchbaseBucketInfo{Bucket: "mybucket", Scope: "myscope", Collection: "mycollection"},
			expectIgnore:   false,
			expectError:    false,
			expectInfo: &CouchbaseInfo{
				Operation:  "GET",
				Key:        "mykey",
				Bucket:     "mybucket",
				Scope:      "myscope",
				Collection: "mycollection",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
		},
		{
			name:           "SET request without cached info",
			opcode:         couchbasekv.OpcodeSet,
			key:            "newkey",
			responseStatus: couchbasekv.StatusSuccess,
			preCachedInfo:  nil,
			expectIgnore:   false,
			expectError:    false,
			expectInfo: &CouchbaseInfo{
				Operation:  "SET",
				Key:        "newkey",
				Bucket:     "",
				Scope:      "",
				Collection: "",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
		},
		{
			name:           "GET request with error response",
			opcode:         couchbasekv.OpcodeGet,
			key:            "missingkey",
			responseStatus: couchbasekv.StatusKeyNotFound,
			preCachedInfo:  &CouchbaseBucketInfo{Bucket: "mybucket"},
			expectIgnore:   false,
			expectError:    false,
			expectInfo: &CouchbaseInfo{
				Operation:  "GET",
				Key:        "missingkey",
				Bucket:     "mybucket",
				Scope:      "",
				Collection: "",
				Status:     couchbasekv.StatusKeyNotFound,
				IsError:    true,
			},
		},
		{
			name:           "SELECT_BUCKET is ignored",
			opcode:         couchbasekv.OpcodeSelectBucket,
			key:            "mybucket",
			responseStatus: couchbasekv.StatusSuccess,
			preCachedInfo:  nil,
			expectIgnore:   true,
			expectError:    false,
			expectInfo:     nil,
		},
		{
			name:           "GET_COLLECTION_ID is ignored",
			opcode:         couchbasekv.OpcodeGetCollectionID,
			key:            "",
			value:          "scope.collection",
			responseStatus: couchbasekv.StatusSuccess,
			preCachedInfo:  nil,
			expectIgnore:   true,
			expectError:    false,
			expectInfo:     nil,
		},
		{
			name:           "DELETE request",
			opcode:         couchbasekv.OpcodeDelete,
			key:            "deletekey",
			responseStatus: couchbasekv.StatusSuccess,
			preCachedInfo:  &CouchbaseBucketInfo{Bucket: "bucket1", Scope: "scope1", Collection: "coll1"},
			expectIgnore:   false,
			expectError:    false,
			expectInfo: &CouchbaseInfo{
				Operation:  "DELETE",
				Key:        "deletekey",
				Bucket:     "bucket1",
				Scope:      "scope1",
				Collection: "coll1",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.Purge()

			if tt.preCachedInfo != nil {
				cache.Add(connInfo, *tt.preCachedInfo)
			}

			var extras []byte
			if tt.opcode == couchbasekv.OpcodeSet {
				extras = make([]byte, 8) // SET requires 8 bytes of extras (flags + expiration)
			}

			requestBuf := makeCouchbaseRequestPacket(tt.opcode, tt.key, tt.value, extras)
			responseBuf := makeCouchbaseResponsePacket(tt.opcode, tt.responseStatus, "")

			info, ignore, err := processCouchbaseEvent(connInfo, requestBuf, responseBuf, cache)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectIgnore, ignore)

			if tt.expectInfo != nil {
				require.NotNil(t, info)
				assert.Equal(t, tt.expectInfo.Operation, info.Operation)
				assert.Equal(t, tt.expectInfo.Key, info.Key)
				assert.Equal(t, tt.expectInfo.Bucket, info.Bucket)
				assert.Equal(t, tt.expectInfo.Scope, info.Scope)
				assert.Equal(t, tt.expectInfo.Collection, info.Collection)
				assert.Equal(t, tt.expectInfo.Status, info.Status)
				assert.Equal(t, tt.expectInfo.IsError, info.IsError)
			} else {
				assert.Nil(t, info)
			}
		})
	}
}

func TestProcessCouchbaseEventInvalidPacket(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo := newTestConnInfo()

	// Test with invalid/too short buffer
	info, ignore, err := processCouchbaseEvent(connInfo, []byte{0x80}, nil, cache)
	require.Error(t, err)
	assert.True(t, ignore)
	assert.Nil(t, info)

	// Test with response packet as request (should be ignored)
	responseBuf := makeCouchbaseResponsePacket(couchbasekv.OpcodeGet, couchbasekv.StatusSuccess, "")
	info, ignore, err = processCouchbaseEvent(connInfo, responseBuf, nil, cache)
	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Nil(t, info)
}

func TestTCPToCouchbaseToSpan(t *testing.T) {
	tests := []struct {
		name         string
		info         *CouchbaseInfo
		expectMethod string
		expectPath   string
		expectNS     string
		expectStatus int
	}{
		{
			name: "successful GET with full namespace",
			info: &CouchbaseInfo{
				Operation:  "GET",
				Key:        "mykey",
				Bucket:     "mybucket",
				Scope:      "myscope",
				Collection: "mycollection",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
			expectMethod: "GET",
			expectPath:   "mycollection",
			expectNS:     "mybucket.myscope",
			expectStatus: 0,
		},
		{
			name: "SET with bucket only",
			info: &CouchbaseInfo{
				Operation:  "SET",
				Key:        "newkey",
				Bucket:     "mybucket",
				Scope:      "",
				Collection: "",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
			expectMethod: "SET",
			expectPath:   "",
			expectNS:     "mybucket",
			expectStatus: 0,
		},
		{
			name: "GET with error",
			info: &CouchbaseInfo{
				Operation:  "GET",
				Key:        "missing",
				Bucket:     "mybucket",
				Scope:      "myscope",
				Collection: "mycollection",
				Status:     couchbasekv.StatusKeyNotFound,
				IsError:    true,
			},
			expectMethod: "GET",
			expectPath:   "mycollection",
			expectNS:     "mybucket.myscope",
			expectStatus: int(couchbasekv.StatusKeyNotFound),
		},
		{
			name: "no bucket info",
			info: &CouchbaseInfo{
				Operation:  "GET",
				Key:        "somekey",
				Bucket:     "",
				Scope:      "",
				Collection: "",
				Status:     couchbasekv.StatusSuccess,
				IsError:    false,
			},
			expectMethod: "GET",
			expectPath:   "",
			expectNS:     "",
			expectStatus: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := &TCPRequestInfo{
				ConnInfo:        newTestConnInfo(),
				StartMonotimeNs: 1000000000,
				EndMonotimeNs:   1000500000,
			}
			trace.Pid.HostPid = 1234
			trace.Pid.UserPid = 1234
			trace.Pid.Ns = 4026531840

			span := TCPToCouchbaseToSpan(trace, tt.info)

			assert.Equal(t, request.EventTypeCouchbaseClient, span.Type)
			assert.Equal(t, tt.expectMethod, span.Method)
			assert.Equal(t, tt.expectPath, span.Path)
			assert.Equal(t, tt.expectNS, span.DBNamespace)
			assert.Equal(t, tt.expectStatus, span.Status)
			assert.Equal(t, int64(1000000000), span.Start)
			assert.Equal(t, int64(1000500000), span.End)
			assert.Equal(t, uint32(1234), span.Pid.HostPID)

			if tt.info.IsError {
				assert.NotEmpty(t, span.DBError.ErrorCode)
				assert.NotEmpty(t, span.DBError.Description)
			}
		})
	}
}

func TestProcessPossibleCouchbaseEventReversedBuffers(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo := newTestConnInfo()
	cache.Add(connInfo, CouchbaseBucketInfo{Bucket: "mybucket"})

	// Create request and response
	requestBuf := makeCouchbaseRequestPacket(couchbasekv.OpcodeGet, "mykey", "", nil)
	responseBuf := makeCouchbaseResponsePacket(couchbasekv.OpcodeGet, couchbasekv.StatusSuccess, "value")

	event := &TCPRequestInfo{
		ConnInfo:  connInfo,
		Direction: 1, // client
	}

	// Test with buffers in correct order
	info, ignore, err := ProcessPossibleCouchbaseEvent(event, requestBuf, responseBuf, cache)
	require.NoError(t, err)
	assert.False(t, ignore)
	require.NotNil(t, info)
	assert.Equal(t, "GET", info.Operation)
	assert.Equal(t, "mykey", info.Key)

	// Test with invalid/garbage in request position - should try reversed and succeed
	garbageBuf := []byte{0x00, 0x01, 0x02, 0x03} // Not a valid Couchbase packet
	event2 := &TCPRequestInfo{
		ConnInfo:  connInfo,
		Direction: 1,
	}
	info, ignore, err = ProcessPossibleCouchbaseEvent(event2, garbageBuf, requestBuf, cache)
	require.NoError(t, err)
	assert.False(t, ignore)
	require.NotNil(t, info)
	assert.Equal(t, "GET", info.Operation)
	assert.Equal(t, "mykey", info.Key)
}

func TestProcessPossibleCouchbaseEventConnectionIsolation(t *testing.T) {
	cache, err := simplelru.NewLRU[BpfConnectionInfoT, CouchbaseBucketInfo](100, nil)
	require.NoError(t, err)

	connInfo1 := BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},
		S_port: 54321,
		D_port: 11210,
	}

	connInfo2 := BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 2},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1},
		S_port: 54322,
		D_port: 11210,
	}

	// Connection 1 selects bucket1
	selectBucket1Req := makeCouchbaseRequestPacket(couchbasekv.OpcodeSelectBucket, "bucket1", "", nil)
	selectBucket1Resp := makeCouchbaseResponsePacket(couchbasekv.OpcodeSelectBucket, couchbasekv.StatusSuccess, "")

	event1 := &TCPRequestInfo{ConnInfo: connInfo1, Direction: 1}
	_, ignore, err := ProcessPossibleCouchbaseEvent(event1, selectBucket1Req, selectBucket1Resp, cache)
	require.NoError(t, err)
	assert.True(t, ignore) // SELECT_BUCKET is ignored

	// Connection 2 selects bucket2
	selectBucket2Req := makeCouchbaseRequestPacket(couchbasekv.OpcodeSelectBucket, "bucket2", "", nil)
	selectBucket2Resp := makeCouchbaseResponsePacket(couchbasekv.OpcodeSelectBucket, couchbasekv.StatusSuccess, "")

	event2 := &TCPRequestInfo{ConnInfo: connInfo2, Direction: 1}
	_, ignore, err = ProcessPossibleCouchbaseEvent(event2, selectBucket2Req, selectBucket2Resp, cache)
	require.NoError(t, err)
	assert.True(t, ignore)

	// Connection 1 sets scope/collection
	getCollID1Req := makeCouchbaseRequestPacket(couchbasekv.OpcodeGetCollectionID, "", "scope1.coll1", nil)
	getCollID1Resp := makeCouchbaseResponsePacket(couchbasekv.OpcodeGetCollectionID, couchbasekv.StatusSuccess, "")

	event1 = &TCPRequestInfo{ConnInfo: connInfo1, Direction: 1}
	_, ignore, err = ProcessPossibleCouchbaseEvent(event1, getCollID1Req, getCollID1Resp, cache)
	require.NoError(t, err)
	assert.True(t, ignore)

	// Connection 2 sets different scope/collection
	getCollID2Req := makeCouchbaseRequestPacket(couchbasekv.OpcodeGetCollectionID, "", "scope2.coll2", nil)
	getCollID2Resp := makeCouchbaseResponsePacket(couchbasekv.OpcodeGetCollectionID, couchbasekv.StatusSuccess, "")

	event2 = &TCPRequestInfo{ConnInfo: connInfo2, Direction: 1}
	_, ignore, err = ProcessPossibleCouchbaseEvent(event2, getCollID2Req, getCollID2Resp, cache)
	require.NoError(t, err)
	assert.True(t, ignore)

	// Now make GET requests on both connections and verify isolation
	getReq := makeCouchbaseRequestPacket(couchbasekv.OpcodeGet, "mykey", "", nil)
	getResp := makeCouchbaseResponsePacket(couchbasekv.OpcodeGet, couchbasekv.StatusSuccess, "value")

	// GET on connection 1 should have bucket1/scope1/coll1
	event1 = &TCPRequestInfo{ConnInfo: connInfo1, Direction: 1}
	info1, ignore, err := ProcessPossibleCouchbaseEvent(event1, getReq, getResp, cache)
	require.NoError(t, err)
	assert.False(t, ignore)
	require.NotNil(t, info1)
	assert.Equal(t, "bucket1", info1.Bucket)
	assert.Equal(t, "scope1", info1.Scope)
	assert.Equal(t, "coll1", info1.Collection)

	// GET on connection 2 should have bucket2/scope2/coll2
	event2 = &TCPRequestInfo{ConnInfo: connInfo2, Direction: 1}
	info2, ignore, err := ProcessPossibleCouchbaseEvent(event2, getReq, getResp, cache)
	require.NoError(t, err)
	assert.False(t, ignore)
	require.NotNil(t, info2)
	assert.Equal(t, "bucket2", info2.Bucket)
	assert.Equal(t, "scope2", info2.Scope)
	assert.Equal(t, "coll2", info2.Collection)
}
