// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMagicIsRequest(t *testing.T) {
	assert.True(t, MagicClientRequest.IsRequest())
	assert.True(t, MagicServerRequest.IsRequest())
	assert.False(t, MagicServerResponse.IsRequest())
	assert.False(t, MagicClientResponse.IsRequest())
}

func TestMagicIsResponse(t *testing.T) {
	assert.True(t, MagicServerResponse.IsResponse())
	assert.True(t, MagicClientResponse.IsResponse())
	assert.False(t, MagicClientRequest.IsResponse())
	assert.False(t, MagicServerRequest.IsResponse())
}

func TestMagicIsValid(t *testing.T) {
	assert.True(t, MagicClientRequest.IsValid())
	assert.True(t, MagicServerResponse.IsValid())
	assert.True(t, MagicServerRequest.IsValid())
	assert.True(t, MagicClientResponse.IsValid())
	assert.False(t, Magic(0x00).IsValid())
	assert.False(t, Magic(0xFF).IsValid())
}

func TestMagicString(t *testing.T) {
	assert.Equal(t, "ClientRequest", MagicClientRequest.String())
	assert.Equal(t, "ServerResponse", MagicServerResponse.String())
	assert.Equal(t, "ServerRequest", MagicServerRequest.String())
	assert.Equal(t, "ClientResponse", MagicClientResponse.String())
	assert.Equal(t, "Unknown", Magic(0xFF).String())
}

func TestOpcodeString(t *testing.T) {
	tests := []struct {
		opcode   Opcode
		expected string
	}{
		{OpcodeGet, "GET"},
		{OpcodeSet, "SET"},
		{OpcodeAdd, "ADD"},
		{OpcodeReplace, "REPLACE"},
		{OpcodeDelete, "DELETE"},
		{OpcodeIncrement, "INCREMENT"},
		{OpcodeDecrement, "DECREMENT"},
		{OpcodeQuit, "QUIT"},
		{OpcodeFlush, "FLUSH"},
		{OpcodeGetQ, "GETQ"},
		{OpcodeNoop, "NOOP"},
		{OpcodeVersion, "VERSION"},
		{OpcodeGetK, "GETK"},
		{OpcodeGetKQ, "GETKQ"},
		{OpcodeAppend, "APPEND"},
		{OpcodePrepend, "PREPEND"},
		{OpcodeStat, "STAT"},
		{OpcodeSetQ, "SETQ"},
		{OpcodeAddQ, "ADDQ"},
		{OpcodeReplaceQ, "REPLACEQ"},
		{OpcodeDeleteQ, "DELETEQ"},
		{OpcodeIncrementQ, "INCREMENTQ"},
		{OpcodeDecrementQ, "DECREMENTQ"},
		{OpcodeQuitQ, "QUITQ"},
		{OpcodeFlushQ, "FLUSHQ"},
		{OpcodeAppendQ, "APPENDQ"},
		{OpcodePrependQ, "PREPENDQ"},
		{OpcodeVerbosity, "VERBOSITY"},
		{OpcodeTouch, "TOUCH"},
		{OpcodeGAT, "GAT"},
		{OpcodeGATQ, "GATQ"},
		{OpcodeHello, "HELLO"},
		{OpcodeSASLListMechs, "SASL_LIST_MECHS"},
		{OpcodeSASLAuth, "SASL_AUTH"},
		{OpcodeSASLStep, "SASL_STEP"},
		{OpcodeSetVBucket, "SET_VBUCKET"},
		{OpcodeGetVBucket, "GET_VBUCKET"},
		{OpcodeDelVBucket, "DEL_VBUCKET"},
		{OpcodeListBuckets, "LIST_BUCKETS"},
		{OpcodeSelectBucket, "SELECT_BUCKET"},
		{Opcode(0xFE), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.opcode.String())
		})
	}
}

func TestOpcodeIsQuiet(t *testing.T) {
	quietOpcodes := []Opcode{
		OpcodeGetQ, OpcodeGetKQ, OpcodeSetQ, OpcodeAddQ, OpcodeReplaceQ,
		OpcodeDeleteQ, OpcodeIncrementQ, OpcodeDecrementQ, OpcodeQuitQ,
		OpcodeFlushQ, OpcodeAppendQ, OpcodePrependQ, OpcodeGATQ,
	}

	for _, op := range quietOpcodes {
		assert.True(t, op.IsQuiet(), "expected %s to be quiet", op.String())
	}

	nonQuietOpcodes := []Opcode{
		OpcodeGet, OpcodeSet, OpcodeAdd, OpcodeReplace, OpcodeDelete,
		OpcodeIncrement, OpcodeDecrement, OpcodeQuit, OpcodeFlush,
		OpcodeNoop, OpcodeVersion, OpcodeGetK, OpcodeAppend,
		OpcodePrepend, OpcodeStat, OpcodeTouch, OpcodeGAT, OpcodeHello,
	}

	for _, op := range nonQuietOpcodes {
		assert.False(t, op.IsQuiet(), "expected %s to not be quiet", op.String())
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusSuccess, "Success"},
		{StatusKeyNotFound, "KeyNotFound"},
		{StatusKeyExists, "KeyExists"},
		{StatusValueTooLarge, "ValueTooLarge"},
		{StatusInvalidArguments, "InvalidArguments"},
		{StatusItemNotStored, "ItemNotStored"},
		{StatusNonNumeric, "NonNumeric"},
		{StatusVBucketNotHere, "VBucketNotHere"},
		{StatusNotConnected, "NotConnected"},
		{StatusStaleAuthContext, "StaleAuthContext"},
		{StatusAuthError, "AuthError"},
		{StatusAuthContinue, "AuthContinue"},
		{StatusOutOfRange, "OutOfRange"},
		{StatusNoAccess, "NoAccess"},
		{StatusUnknownCommand, "UnknownCommand"},
		{StatusOutOfMemory, "OutOfMemory"},
		{StatusNotSupported, "NotSupported"},
		{StatusInternalError, "InternalError"},
		{StatusBusy, "Busy"},
		{StatusTemporaryFailure, "TemporaryFailure"},
		{Status(0xFFFF), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestStatusIsSuccess(t *testing.T) {
	assert.True(t, StatusSuccess.IsSuccess())
	assert.False(t, StatusKeyNotFound.IsSuccess())
	assert.False(t, StatusAuthContinue.IsSuccess())
}

func TestStatusIsError(t *testing.T) {
	assert.False(t, StatusSuccess.IsError())
	assert.False(t, StatusAuthContinue.IsError())
	assert.True(t, StatusKeyNotFound.IsError())
	assert.True(t, StatusAuthError.IsError())
	assert.True(t, StatusInternalError.IsError())
}

func TestDataTypeFlags(t *testing.T) {
	tests := []struct {
		name      string
		dataType  DataType
		hasJSON   bool
		hasSnappy bool
		hasXattr  bool
	}{
		{"raw", DataTypeRaw, false, false, false},
		{"json only", DataTypeJSON, true, false, false},
		{"snappy only", DataTypeSnappy, false, true, false},
		{"xattr only", DataTypeXattr, false, false, true},
		{"json + snappy", DataTypeJSON | DataTypeSnappy, true, true, false},
		{"json + xattr", DataTypeJSON | DataTypeXattr, true, false, true},
		{"all flags", DataTypeJSON | DataTypeSnappy | DataTypeXattr, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.hasJSON, tt.dataType.HasJSON())
			assert.Equal(t, tt.hasSnappy, tt.dataType.HasSnappy())
			assert.Equal(t, tt.hasXattr, tt.dataType.HasXattr())
		})
	}
}
