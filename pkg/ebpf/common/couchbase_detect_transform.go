// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"strconv"
	"strings"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"
)

// CouchbaseInfo holds parsed Couchbase memcached binary protocol information.
type CouchbaseInfo struct {
	Operation  string
	Key        string
	Bucket     string
	Scope      string
	Collection string
	Status     couchbasekv.Status
	IsError    bool
}

// ProcessPossibleCouchbaseEvent attempts to parse the event as a Couchbase memcached binary protocol event.
// Returns the CouchbaseInfo if successful, along with a boolean indicating if the event should be ignored,
// and an error if parsing failed.
func ProcessPossibleCouchbaseEvent(event *TCPRequestInfo, requestBuf []byte, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	info, ignore, err := processCouchbaseEvent(event.ConnInfo, requestBuf, responseBuf, bucketCache)
	if err != nil {
		// Try with buffers reversed - we might have captured it backwards
		info, ignore, err = processCouchbaseEvent(event.ConnInfo, responseBuf, requestBuf, bucketCache)
		if err == nil && !ignore {
			reverseTCPEvent(event)
		}
	}
	return info, ignore, err
}

// handleSelectBucket processes the SELECT_BUCKET command and updates the bucket cache.
func handleSelectBucket(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	bucketName := reqPacket.KeyString()
	if bucketCache == nil || bucketName == "" {
		return
	}

	// Parse response to check if bucket selection was successful
	respPacket, respErr := couchbasekv.ParsePacket(responseBuf)
	if respErr != nil || !respPacket.IsResponse() || !respPacket.Header.Status.IsSuccess() {
		return
	}

	bucketCache.Add(connInfo, CouchbaseBucketInfo{
		Bucket:     bucketName,
		Scope:      "",
		Collection: "",
	})
}

// handleGetCollectionID processes the GET_COLLECTION_ID command and updates the bucket cache with scope/collection.
func handleGetCollectionID(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	scopeCollection := reqPacket.ValueString()
	if bucketCache == nil || scopeCollection == "" {
		return
	}

	// Parse response to check if collection lookup was successful
	respPacket, respErr := couchbasekv.ParsePacket(responseBuf)
	if respErr != nil || !respPacket.IsResponse() || !respPacket.Header.Status.IsSuccess() {
		return
	}

	// Parse scope.collection from the value
	parts := strings.SplitN(scopeCollection, ".", 2)
	if len(parts) != 2 {
		return
	}

	// Get existing bucket info or create new one
	bucketInfo, found := bucketCache.Get(connInfo)
	if !found {
		bucketInfo = CouchbaseBucketInfo{}
	}
	bucketInfo.Scope = parts[0]
	bucketInfo.Collection = parts[1]
	bucketCache.Add(connInfo, bucketInfo)
}

// processCouchbaseEvent parses Couchbase packets from request and response buffers.
func processCouchbaseEvent(connInfo BpfConnectionInfoT, requestBuf []byte, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	// Try to parse the request
	reqPacket, err := couchbasekv.ParsePacket(requestBuf)
	if err != nil {
		return nil, true, err
	}

	// We need a request packet
	if !reqPacket.IsRequest() {
		return nil, true, nil
	}

	// Handle SELECT_BUCKET command - this sets the bucket for the connection
	if reqPacket.Header.Opcode == couchbasekv.OpcodeSelectBucket {
		handleSelectBucket(connInfo, reqPacket, responseBuf, bucketCache)
		// Don't create a span for SELECT_BUCKET - it's a connection setup command
		return nil, true, nil
	}

	// Handle GET_COLLECTION_ID command - this resolves scope.collection to a CID
	if reqPacket.Header.Opcode == couchbasekv.OpcodeGetCollectionID {
		handleGetCollectionID(connInfo, reqPacket, responseBuf, bucketCache)
		// Don't create a span for GET_COLLECTION_ID - it's a setup command
		return nil, true, nil
	}

	info := &CouchbaseInfo{
		Operation: reqPacket.Header.Opcode.String(),
		Key:       reqPacket.KeyString(),
	}

	// Get bucket info from cache
	if bucketCache != nil {
		if bucketInfo, found := bucketCache.Get(connInfo); found {
			info.Bucket = bucketInfo.Bucket
			info.Scope = bucketInfo.Scope
			info.Collection = bucketInfo.Collection
		}
	}

	// Try to parse the response to get status
	respPacket, respErr := couchbasekv.ParsePacket(responseBuf)
	if respErr == nil && respPacket.IsResponse() {
		info.Status = respPacket.Header.Status
		info.IsError = respPacket.Header.Status.IsError()
	}

	return info, false, nil
}

// TCPToCouchbaseToSpan converts a TCP event with Couchbase data to a request.Span.
func TCPToCouchbaseToSpan(trace *TCPRequestInfo, data *CouchbaseInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeCouchbaseClient

	status := 0
	var dbError request.DBError
	if data.IsError {
		status = int(data.Status)
		dbError = request.DBError{
			ErrorCode:   strconv.Itoa(status),
			Description: data.Status.String(),
		}
	}

	// Build the database namespace: bucket.scope
	dbNamespace := data.Bucket
	if dbNamespace == "" {
		dbNamespace = data.Scope
	} else if data.Scope != "" {
		dbNamespace += "." + data.Scope
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation,
		Path:          data.Collection,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		DBError:     dbError,
		DBNamespace: dbNamespace,
	}
}
