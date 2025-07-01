package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var requests PendingMongoDBRequests = expirable.NewLRU[MongoRequestKey, *MongoRequestValue](1000, nil, 0)

const (
	StartTime     = 1000
	EndTime       = 2000
	MessageLength = 65
	PreBodyLength = 21 // 16 for header + 5 for flags and section type
	RequestID     = 1
)

func getConnInfo() BpfConnectionInfoT {
	return BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		S_port: 27017,
		D_port: 27017,
	}
}

// func getRequestPayload(hdr *msgHeader, flags uint32, section SectionType, data *bson.D) []byte {
func getRequestPayload(hdr *msgHeader, flags uint32, section SectionType) []byte {
	// if data == nil {
	// 	data := &bson.D{bson.E{Key: "find", Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}}
	// }
	data := &bson.D{bson.E{Key: "find", Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}}
	bsonBytes, _ := bson.Marshal(*data)
	if hdr == nil {
		hdr = &msgHeader{
			MessageLength: PreBodyLength + int32(len(bsonBytes)),
			RequestID:     RequestID,
			ResponseTo:    0,
			OpCode:        opMsg,
		}
	}
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)
	_ = binary.Write(byteBuffer, binary.LittleEndian, flags) // empty flags
	_ = binary.Write(byteBuffer, binary.LittleEndian, section)
	_ = binary.Write(byteBuffer, binary.LittleEndian, bsonBytes)
	return byteBuffer.Bytes()
}

func getResponsePayload(hdr *msgHeader, flags uint32, section SectionType, data *bson.D) []byte {
	if data == nil {
		data = &bson.D{bson.E{Key: "ok", Value: "1"}}
	}
	bsonBytes, _ := bson.Marshal(*data)
	if hdr == nil {
		hdr = &msgHeader{
			MessageLength: PreBodyLength + int32(len(bsonBytes)),
			RequestID:     RequestID + 1,
			ResponseTo:    RequestID,
			OpCode:        opMsg,
		}
	}
	byteBuffer := new(bytes.Buffer)
	_ = binary.Write(byteBuffer, binary.LittleEndian, hdr)
	_ = binary.Write(byteBuffer, binary.LittleEndian, flags) // empty flags
	_ = binary.Write(byteBuffer, binary.LittleEndian, section)
	_ = binary.Write(byteBuffer, binary.LittleEndian, bsonBytes)
	return byteBuffer.Bytes()
}

func TestProcessMongoEventShorterThenHeader(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	_, _, err := ProcessMongoEvent([]uint8{0x00, 0x00, 0x00, 0x00}, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for short buffer")
}

func TestProcessMongoEventHdrMessageLengthLessThenHeaderLength(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	shortHdr := msgHeader{
		MessageLength: 3,
		RequestID:     RequestID,
		ResponseTo:    0,
		OpCode:        opMsg,
	}
	payload := getRequestPayload(&shortHdr, 0, sectionTypeBody)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for message length less than header length")
}

func TestProcessMongoEventUnknownOp(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	invalidOpHdr := msgHeader{
		MessageLength: MessageLength,
		RequestID:     RequestID,
		ResponseTo:    0,
		OpCode:        42,
	}
	payload := getRequestPayload(&invalidOpHdr, 0, sectionTypeBody)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for unknown opcode")
}

func TestProcessMongoEventInvalidFlags(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0|0x08, sectionTypeBody)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for invalid flags")
}

func TestProcessMongoEventInvalidSectionType(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0|0x08, 6)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for invalid section type")
}

func TestProcessMongoEventFailIfNoChecksumButItsExpected(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	payload := getRequestPayload(nil, 0|flagCheckSumPreset, sectionTypeBody)
	_, _, err := ProcessMongoEvent(payload, StartTime, EndTime, connInfo, requests)
	assert.Error(t, err, "Expected error for missing checksum when expected")
}

// func TestProcessMongoEventNoAdditionalRequestIfNoMoreToComeInRequest(t *testing.T) {
//	defer requests.Purge()
//	connInfo := getConnInfo()
//	payload := getRequestPayload(nil, 0, sectionTypeBody)
//	_, moreToCome, err := ProcessMongoEvent(payload, START_TIME, END_TIME, connInfo, requests)
//	assert.Nil(t, err, "Expected no error for valid MongoDB event")
//	assert.True(t, moreToCome)
//
//	// send the same request again, the connection should be expecting a response
//	_, _, err = ProcessMongoEvent(payload, START_TIME, END_TIME, connInfo, requests)
//	assert.Error(t, err, "Expected error when not expecting more request data but receiving it")
//}
//
// func TestProcessMongoEventExpectsMoreRequestToComeButGotResponse(t *testing.T) {
//	defer requests.Purge()
//	connInfo := getConnInfo()
//	requestPayload := getRequestPayload(nil, 0|flagMoreToCome, sectionTypeBody)
//	_, moreToCome, err := ProcessMongoEvent(requestPayload, START_TIME, END_TIME, connInfo, requests)
//	assert.Nil(t, err, "Expected no error for valid MongoDB event")
//	assert.True(t, moreToCome)
//
//	responsePayload := getRequestPayload(nil, 0, sectionTypeBody)
//	// send the same request again, the connection should be expecting a response
//	_, _, err = ProcessMongoEvent(responsePayload, START_TIME, END_TIME, connInfo, requests)
//	assert.Error(t, err, "Expected error when not expecting more request data but receiving it")
//}

func TestProcessMongoEventShouldBeFine(t *testing.T) {
	defer requests.Purge()
	connInfo := getConnInfo()
	requestPayload := getRequestPayload(nil, 0, sectionTypeBody)
	_, moreToCome, err := ProcessMongoEvent(requestPayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.True(t, moreToCome)

	responsePayload := getResponsePayload(nil, 0, sectionTypeBody, nil)
	// send the same request again, the connection should be expecting a response
	mongoRequestValue, moreToCome, err := ProcessMongoEvent(responsePayload, StartTime, EndTime, connInfo, requests)
	require.NoError(t, err, "Expected no error for valid MongoDB event")
	assert.False(t, moreToCome, "Expected no more data to come after response")
	assert.NotNil(t, mongoRequestValue, "Expected MongoRequestValue to be returned")
}

// getMongoInfo

func TestGetMongoInfoFindRequest(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "find", Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}},
			},
		},
		ResponseSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "ok", Value: float64(1)}},
			},
		},
	}
	res, err := getMongoInfo(&mongoRequest)
	if err != nil {
		t.Fatalf("getMongoInfo failed: %v", err)
	}
	assert.Equal(t, "my_db", res.DB, "Expected DB to be 'my_db'")
	assert.Equal(t, "my_collection", res.Collection, "Expected Collection to be 'my_collection'")
	assert.Equal(t, "find", res.OpName, "Expected Operation to be 'find'")
	assert.True(t, res.Success, "Expected Response to be 'ok'")
	assert.Empty(t, res.Error, "Expected Error to be empty in successful request")
	assert.Empty(t, res.ErrorCode, "Expected ErrorCode to be empty in successful request")
	assert.Empty(t, res.ErrorCodeName, "Expected ErrorCodeName to be empty in successful request")
}

func TestGetMongoInfoErrorRequest(t *testing.T) {
	mongoRequest := MongoRequestValue{
		RequestSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "find", Value: "my_collection"}, bson.E{Key: "$db", Value: "my_db"}},
			},
		},
		ResponseSections: []mongoSection{
			{
				Type: sectionTypeBody,
				Body: bson.D{bson.E{Key: "ok", Value: float64(0)}, bson.E{Key: "errmsg", Value: "some error"}, bson.E{Key: "code", Value: 12345}, bson.E{Key: "codeName", Value: "SomeError"}},
			},
		},
	}
	res, err := getMongoInfo(&mongoRequest)
	if err != nil {
		t.Fatalf("getMongoInfo failed: %v", err)
	}
	assert.Equal(t, "my_db", res.DB, "Expected DB to be 'my_db'")
	assert.Equal(t, "my_collection", res.Collection, "Expected Collection to be 'my_collection'")
	assert.Equal(t, "find", res.OpName, "Expected Operation to be 'find'")
	assert.False(t, res.Success, "Expected Response to not be 'ok'")
	assert.Equal(t, "some error", res.Error, "Expected Error to be 'some error'")
	assert.Equal(t, 12345, res.ErrorCode, "Expected ErrorCode to be 12345")
	assert.Equal(t, "SomeError", res.ErrorCodeName, "Expected ErrorCodeName to be 'SomeError'")
}
