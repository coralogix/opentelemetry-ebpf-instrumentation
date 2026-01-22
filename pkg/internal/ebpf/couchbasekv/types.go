// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv // import "go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"

// Header sizes
const (
	HeaderLen = 24 // All packets have a 24-byte header
)

// Magic bytes identify packet direction
type Magic uint8

const (
	MagicClientRequest  Magic = 0x80 // Client → Server request
	MagicServerResponse Magic = 0x81 // Server → Client response
	MagicServerRequest  Magic = 0x82 // Server → Client request (e.g., for replication)
	MagicClientResponse Magic = 0x83 // Client → Server response
)

// IsRequest returns true if this magic byte indicates a request packet.
func (m Magic) IsRequest() bool {
	return m == MagicClientRequest || m == MagicServerRequest
}

// IsResponse returns true if this magic byte indicates a response packet.
func (m Magic) IsResponse() bool {
	return m == MagicServerResponse || m == MagicClientResponse
}

// IsValid returns true if this is a valid magic byte.
func (m Magic) IsValid() bool {
	return m == MagicClientRequest || m == MagicServerResponse ||
		m == MagicServerRequest || m == MagicClientResponse
}

func (m Magic) String() string {
	switch m {
	case MagicClientRequest:
		return "ClientRequest"
	case MagicServerResponse:
		return "ServerResponse"
	case MagicServerRequest:
		return "ServerRequest"
	case MagicClientResponse:
		return "ClientResponse"
	default:
		return "Unknown"
	}
}

// Opcode identifies the command type
type Opcode uint8

const (
	OpcodeGet              Opcode = 0x00
	OpcodeSet              Opcode = 0x01
	OpcodeAdd              Opcode = 0x02
	OpcodeReplace          Opcode = 0x03
	OpcodeDelete           Opcode = 0x04
	OpcodeIncrement        Opcode = 0x05
	OpcodeDecrement        Opcode = 0x06
	OpcodeQuit             Opcode = 0x07
	OpcodeFlush            Opcode = 0x08
	OpcodeGetQ             Opcode = 0x09 // Get quietly (no response on miss)
	OpcodeNoop             Opcode = 0x0a
	OpcodeVersion          Opcode = 0x0b
	OpcodeGetK             Opcode = 0x0c // Get with key in response
	OpcodeGetKQ            Opcode = 0x0d // Get with key, quietly
	OpcodeAppend           Opcode = 0x0e
	OpcodePrepend          Opcode = 0x0f
	OpcodeStat             Opcode = 0x10
	OpcodeSetQ             Opcode = 0x11 // Set quietly
	OpcodeAddQ             Opcode = 0x12 // Add quietly
	OpcodeReplaceQ         Opcode = 0x13 // Replace quietly
	OpcodeDeleteQ          Opcode = 0x14 // Delete quietly
	OpcodeIncrementQ       Opcode = 0x15 // Increment quietly
	OpcodeDecrementQ       Opcode = 0x16 // Decrement quietly
	OpcodeQuitQ            Opcode = 0x17 // Quit quietly
	OpcodeFlushQ           Opcode = 0x18 // Flush quietly
	OpcodeAppendQ          Opcode = 0x19 // Append quietly
	OpcodePrependQ         Opcode = 0x1a // Prepend quietly
	OpcodeVerbosity        Opcode = 0x1b
	OpcodeTouch            Opcode = 0x1c
	OpcodeGAT              Opcode = 0x1d // Get and touch
	OpcodeGATQ             Opcode = 0x1e // Get and touch quietly
	OpcodeHello            Opcode = 0x1f // Feature negotiation
	OpcodeSASLListMechs    Opcode = 0x20
	OpcodeSASLAuth         Opcode = 0x21
	OpcodeSASLStep         Opcode = 0x22
	OpcodeSetVBucket       Opcode = 0x3d
	OpcodeGetVBucket       Opcode = 0x3e
	OpcodeDelVBucket       Opcode = 0x3f
	OpcodeListBuckets      Opcode = 0x87
	OpcodeSelectBucket     Opcode = 0x89
	OpcodeGetCollectionID  Opcode = 0xbb
	OpcodeGetScopeID       Opcode = 0xbc
	OpcodeGetCollectionMan Opcode = 0xba // Get Collection Manifest
)

func (o Opcode) String() string {
	switch o {
	case OpcodeGet:
		return "GET"
	case OpcodeSet:
		return "SET"
	case OpcodeAdd:
		return "ADD"
	case OpcodeReplace:
		return "REPLACE"
	case OpcodeDelete:
		return "DELETE"
	case OpcodeIncrement:
		return "INCREMENT"
	case OpcodeDecrement:
		return "DECREMENT"
	case OpcodeQuit:
		return "QUIT"
	case OpcodeFlush:
		return "FLUSH"
	case OpcodeGetQ:
		return "GETQ"
	case OpcodeNoop:
		return "NOOP"
	case OpcodeVersion:
		return "VERSION"
	case OpcodeGetK:
		return "GETK"
	case OpcodeGetKQ:
		return "GETKQ"
	case OpcodeAppend:
		return "APPEND"
	case OpcodePrepend:
		return "PREPEND"
	case OpcodeStat:
		return "STAT"
	case OpcodeSetQ:
		return "SETQ"
	case OpcodeAddQ:
		return "ADDQ"
	case OpcodeReplaceQ:
		return "REPLACEQ"
	case OpcodeDeleteQ:
		return "DELETEQ"
	case OpcodeIncrementQ:
		return "INCREMENTQ"
	case OpcodeDecrementQ:
		return "DECREMENTQ"
	case OpcodeQuitQ:
		return "QUITQ"
	case OpcodeFlushQ:
		return "FLUSHQ"
	case OpcodeAppendQ:
		return "APPENDQ"
	case OpcodePrependQ:
		return "PREPENDQ"
	case OpcodeVerbosity:
		return "VERBOSITY"
	case OpcodeTouch:
		return "TOUCH"
	case OpcodeGAT:
		return "GAT"
	case OpcodeGATQ:
		return "GATQ"
	case OpcodeHello:
		return "HELLO"
	case OpcodeSASLListMechs:
		return "SASL_LIST_MECHS"
	case OpcodeSASLAuth:
		return "SASL_AUTH"
	case OpcodeSASLStep:
		return "SASL_STEP"
	case OpcodeSetVBucket:
		return "SET_VBUCKET"
	case OpcodeGetVBucket:
		return "GET_VBUCKET"
	case OpcodeDelVBucket:
		return "DEL_VBUCKET"
	case OpcodeListBuckets:
		return "LIST_BUCKETS"
	case OpcodeSelectBucket:
		return "SELECT_BUCKET"
	case OpcodeGetCollectionID:
		return "GET_COLLECTION_ID"
	case OpcodeGetScopeID:
		return "GET_SCOPE_ID"
	case OpcodeGetCollectionMan:
		return "GET_COLLECTION_MANIFEST"
	default:
		return "UNKNOWN"
	}
}

// IsQuiet returns true if this opcode is a "quiet" variant that doesn't
// send a response on cache miss or success.
func (o Opcode) IsQuiet() bool {
	switch o {
	case OpcodeGetQ, OpcodeGetKQ, OpcodeSetQ, OpcodeAddQ, OpcodeReplaceQ,
		OpcodeDeleteQ, OpcodeIncrementQ, OpcodeDecrementQ, OpcodeQuitQ,
		OpcodeFlushQ, OpcodeAppendQ, OpcodePrependQ, OpcodeGATQ:
		return true
	default:
		return false
	}
}

// Status codes for response packets
type Status uint16

const (
	StatusSuccess          Status = 0x0000
	StatusKeyNotFound      Status = 0x0001
	StatusKeyExists        Status = 0x0002
	StatusValueTooLarge    Status = 0x0003
	StatusInvalidArguments Status = 0x0004
	StatusItemNotStored    Status = 0x0005
	StatusNonNumeric       Status = 0x0006 // Incr/decr on non-numeric value
	StatusVBucketNotHere   Status = 0x0007 // VBucket belongs to another server
	StatusNotConnected     Status = 0x0008 // Not connected to bucket
	StatusStaleAuthContext Status = 0x001f
	StatusAuthError        Status = 0x0020
	StatusAuthContinue     Status = 0x0021
	StatusOutOfRange       Status = 0x0022 // Value outside legal ranges
	StatusNoAccess         Status = 0x0024
	StatusUnknownCommand   Status = 0x0081
	StatusOutOfMemory      Status = 0x0082
	StatusNotSupported     Status = 0x0083
	StatusInternalError    Status = 0x0084
	StatusBusy             Status = 0x0085
	StatusTemporaryFailure Status = 0x0086
)

func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "Success"
	case StatusKeyNotFound:
		return "KeyNotFound"
	case StatusKeyExists:
		return "KeyExists"
	case StatusValueTooLarge:
		return "ValueTooLarge"
	case StatusInvalidArguments:
		return "InvalidArguments"
	case StatusItemNotStored:
		return "ItemNotStored"
	case StatusNonNumeric:
		return "NonNumeric"
	case StatusVBucketNotHere:
		return "VBucketNotHere"
	case StatusNotConnected:
		return "NotConnected"
	case StatusStaleAuthContext:
		return "StaleAuthContext"
	case StatusAuthError:
		return "AuthError"
	case StatusAuthContinue:
		return "AuthContinue"
	case StatusOutOfRange:
		return "OutOfRange"
	case StatusNoAccess:
		return "NoAccess"
	case StatusUnknownCommand:
		return "UnknownCommand"
	case StatusOutOfMemory:
		return "OutOfMemory"
	case StatusNotSupported:
		return "NotSupported"
	case StatusInternalError:
		return "InternalError"
	case StatusBusy:
		return "Busy"
	case StatusTemporaryFailure:
		return "TemporaryFailure"
	default:
		return "Unknown"
	}
}

// IsSuccess returns true if this status indicates success.
func (s Status) IsSuccess() bool {
	return s == StatusSuccess
}

// IsError returns true if this status indicates an error.
func (s Status) IsError() bool {
	return s != StatusSuccess && s != StatusAuthContinue
}

// DataType is a bitfield describing the value format
type DataType uint8

const (
	DataTypeRaw    DataType = 0x00
	DataTypeJSON   DataType = 0x01
	DataTypeSnappy DataType = 0x02 // Snappy compressed
	DataTypeXattr  DataType = 0x04 // Extended attributes present
)

// HasJSON returns true if the data is JSON formatted.
func (d DataType) HasJSON() bool {
	return d&DataTypeJSON != 0
}

// HasSnappy returns true if the data is Snappy compressed.
func (d DataType) HasSnappy() bool {
	return d&DataTypeSnappy != 0
}

// HasXattr returns true if extended attributes are present.
func (d DataType) HasXattr() bool {
	return d&DataTypeXattr != 0
}
