package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.mongodb.org/mongo-driver/v2/bson"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
)

type MongoSpanInfo struct {
	OpName        string
	Collection    string
	DB            string
	Success       bool
	Error         string
	ErrorCode     int
	ErrorCodeName string
}

func newMongoSpanInfo() *MongoSpanInfo {
	return &MongoSpanInfo{
		OpName:        "",
		Collection:    "",
		DB:            "",
		Success:       true,
		Error:         "",
		ErrorCode:     0,
		ErrorCodeName: "",
	}
}

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#standard-message-header
type MsgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#sections
type SectionType uint8

const (
	SectionTypeBody SectionType = iota
	SectionTypeDocumentSequence
)

type Section struct {
	Type SectionType
	Body bson.D // in case of SectionTypeBody, this will contain the BSON document
}

const (
	MsgHeaderSize = 16
	Int32Size     = 4
	// Flags https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#flag-bits

	FlagCheckSumPreset = 0x1 // indicates that the checksum is present
	FlagMoreToCome     = 0x2 // indicates that there are more sections to come in the message
	AllowedFlags       = FlagCheckSumPreset | FlagMoreToCome
	FlagExhaustAllowed = 0x10000 // indicates that the request is allowed to be sent with moreToCome set

	// OpCodes https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#opcodes
	OpMsg = 2013
	// TODO (mongo) support compressed messages (OP_COMPRESSED)
	// TODO (mongo) support legacy messages (OP_QUERY, OP_GET_MORE, OP_INSERT, OP_UPDATE, OP_DELETE, OP_REPLY)

	// TODO (mongo) maybe set?
	CommHello             = "hello"
	CommIsMaster          = "isMaster"
	CommPing              = "ping"
	CommIsWritablePrimary = "isWritablePrimary"
)

func isHeartbeat(comm string) bool {
	return comm == CommHello || comm == CommIsMaster || comm == CommPing || comm == CommIsWritablePrimary
}

type MongoRequestKey struct {
	connInfo  BpfConnectionInfoT
	requestID int32
}

type MongoRequestValue struct {
	RequestSections  []Section
	ResponseSections []Section
	StartTime        int64 // timestamp when the request was received
	EndTime          int64 // timestamp when the response was received
	Flags            byte  // Flags to indicate the state of the request
}

type PendingMongoDBRequests = *expirable.LRU[MongoRequestKey, *MongoRequestValue]

func ProcessMongoEvent(buf []uint8, startTime int64, endTime int64, connInfo BpfConnectionInfoT, requests PendingMongoDBRequests) (*MongoRequestValue, bool, error) {
	if len(buf) < MsgHeaderSize {
		return nil, false, errors.New("packet too short for MongoDB header")
	}

	header, err := parseMongoHeader(buf)
	if err != nil {
		return nil, false, err
	}

	isRequest := header.ResponseTo == 0
	var pendingRequest *MongoRequestValue
	var moreToCome bool
	var time int64
	var key MongoRequestKey
	if !isRequest {
		key = MongoRequestKey{
			connInfo:  connInfo,
			requestID: header.ResponseTo,
		}
		time = endTime
	} else {
		key = MongoRequestKey{
			connInfo:  connInfo,
			requestID: header.RequestID,
		}
		time = startTime
	}
	inFlightRequest, ok := requests.Get(key)
	if !ok && !isRequest {
		return nil, false, fmt.Errorf("no in-flight MongoDB request found for key %d", header.ResponseTo)
	}
	if !isRequest && len(buf) == MsgHeaderSize {
		// TODO (mongo) currently the response is only the header, since the client sends only the first 16 bytes at first,
		// we need to fix the tcp path to send the response body as well
		// for now we just dont add response section
		requests.Remove(key)
		// If this is a response and there are no more sections to come, we can finalize the request
		return inFlightRequest, false, nil
	}
	pendingRequest, moreToCome, err = parseMongoMessage(buf, *header, time, isRequest, inFlightRequest)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse MongoDB response: %w", err)
	}
	if pendingRequest == nil {
		return nil, false, errors.New("no MongoDB request or response found in the message")
	}
	requests.Add(key, pendingRequest)
	if !moreToCome && !isRequest {
		requests.Remove(key)
		// If this is a response and there are no more sections to come, we can finalize the request
		return pendingRequest, false, nil
	}
	return nil, true, nil
}

func parseMongoMessage(buf []uint8, hdr MsgHeader, time int64, isRequest bool, pendingRequest *MongoRequestValue) (*MongoRequestValue, bool, error) {
	switch hdr.OpCode {
	case OpMsg:
		return parseOpMessage(buf, hdr, time, isRequest, pendingRequest)
	default:
		return nil, false, fmt.Errorf("unsupported MongoDB operation code %d", hdr.OpCode)
	}
}

func parseOpMessage(buf []uint8, hdr MsgHeader, time int64, isRequest bool, pendingRequest *MongoRequestValue) (*MongoRequestValue, bool, error) {
	// MONGODB_OP_MSG packet structure:
	// +------------+-------------+------------------+
	// | header      | flagBits    | sections  | checksum |
	// +------------+-------------+------------------+
	// |    16B      |     4B      |     ?     | optional 4B |
	// +------------+-------------+------------------+
	// TODO (mongo): plus checksum validation to avoid false positives? (only if we have the full packet)
	flagBits := int32(binary.LittleEndian.Uint32(buf[MsgHeaderSize : MsgHeaderSize+Int32Size]))
	err := validateFlagBits(flagBits)
	if err != nil {
		return nil, false, err
	}

	moreToCome := flagBits&FlagMoreToCome != 0
	exhaustAllowed := flagBits&FlagExhaustAllowed != 0
	// TODO (mongo) validations on moreToCome and exhaustAllowed Flags
	if !isRequest && moreToCome && !exhaustAllowed {
		return nil, false, errors.New("MongoDB response with moreToCome flag set but exhaustAllowed is not set")
	}
	if pendingRequest != nil && pendingRequest.Flags&FlagMoreToCome != 0 {
		if pendingRequest.ResponseSections == nil && !isRequest {
			return nil, false, errors.New("MongoDB request expects more sections but response is sent")
		}
	}

	checkSumPreset := flagBits&FlagCheckSumPreset != 0
	sectionsSize := hdr.MessageLength - MsgHeaderSize - Int32Size
	if checkSumPreset {
		sectionsSize -= Int32Size // subtract checksum size if present
	}
	if sectionsSize < 0 {
		return nil, false, errors.New("invalid MongoDB message length, sections size is negative")
	}
	sections, err := parseSections(buf[MsgHeaderSize+Int32Size : MsgHeaderSize+Int32Size+sectionsSize])
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse MongoDB sections: %w", err)
	}
	if len(sections) == 0 {
		return nil, false, errors.New("no MongoDB sections found in the message")
	}

	if isRequest {
		if pendingRequest == nil {
			pendingRequest = &MongoRequestValue{
				RequestSections: sections,
				StartTime:       time,
				Flags:           byte(flagBits),
			}
		} else {
			pendingRequest.RequestSections = append(pendingRequest.RequestSections, sections...)
			pendingRequest.Flags = byte(flagBits)
			if pendingRequest.StartTime > time {
				pendingRequest.StartTime = time
			} else if pendingRequest.EndTime < time {
				pendingRequest.EndTime = time
			}
		}
	} else {
		if pendingRequest == nil {
			return nil, false, errors.New("MongoDB response received but no pending request found")
		}
		if pendingRequest.ResponseSections != nil {
			pendingRequest.ResponseSections = append(pendingRequest.ResponseSections, sections...)
		} else {
			pendingRequest.ResponseSections = sections
		}
	}
	return pendingRequest, moreToCome, nil
}

func parseSections(buf []uint8) ([]Section, error) {
	offSet := 0
	sections := []Section{}
	for offSet >= len(buf) {

		if len(buf[offSet:]) < Int32Size {
			return nil, errors.New("not enough data for section header")
		}

		sectionType := SectionType(buf[offSet])
		offSet++

		switch sectionType {
		// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#kind-0--body
		case SectionTypeBody:
			if len(buf[offSet:]) < Int32Size {
				return nil, errors.New("not enough data for section body length")
			}
			bodyLength := int(binary.LittleEndian.Uint32(buf[offSet : offSet+Int32Size]))

			if len(buf[offSet:]) < bodyLength {
				return nil, errors.New("not enough data for section body")
			}

			bodyData := buf[offSet : offSet+bodyLength]
			// TODO (mongo) we need to parse partial bson parsing, we won't always get the full tcp payload, so we want to extract as many fields as we can
			var doc bson.D
			err := bson.Unmarshal(bodyData, &doc)
			if err != nil {
				return nil, err
			}
			sections = append(sections, Section{
				Type: sectionType,
				Body: doc,
			})
			offSet += bodyLength
		// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#kind-1--document-sequence
		case SectionTypeDocumentSequence:
			length := int(binary.LittleEndian.Uint32(buf[offSet : offSet+Int32Size]))
			offSet += length
			// TODO (mongo) actually read documents? for now we just skip them
		default:
			return nil, errors.New("unsupported MongoDB section type: " + string(sectionType))
		}
	}
	if len(sections) == 0 {
		return nil, errors.New("no MongoDB sections found in the message")
	}
	return sections, nil
}

func parseMongoHeader(pkt []byte) (*MsgHeader, error) {
	header := &MsgHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(pkt[0:Int32Size])),
		RequestID:     int32(binary.LittleEndian.Uint32(pkt[Int32Size : 2*Int32Size])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(pkt[2*Int32Size : 3*Int32Size])),
		OpCode:        int32(binary.LittleEndian.Uint32(pkt[3*Int32Size : 4*Int32Size])),
	}
	err := validateMsgHeader(header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func validateMsgHeader(header *MsgHeader) error {
	if header.MessageLength < MsgHeaderSize {
		return errors.New("invalid MongoDB message length")
	}
	if header.RequestID < 0 {
		return errors.New("invalid MongoDB request ID")
	}
	if header.ResponseTo < 0 {
		return errors.New("invalid MongoDB response ID")
	}
	return nil
}

/*
The first 16 bits (0-15) are required and parsers MUST Error if an unknown bit is set.
*/
func validateFlagBits(flagBits int32) error {
	if flagBits&^AllowedFlags != 0 {
		return fmt.Errorf("invalid MongoDB flag bits: %d, allowed bits are: %d", flagBits, AllowedFlags)
	}
	return nil
}

func GetMongoInfo(request *MongoRequestValue) (*MongoSpanInfo, error) {
	spanInfo := newMongoSpanInfo()
	if request == nil || len(request.RequestSections) == 0 {
		return nil, errors.New("no MongoDB request sections found")
	}

	// For simplicity, we assume the first section is the main one.
	// In a real-world scenario, you might want to handle multiple sections.
	requestSection := request.RequestSections[0]
	if len(requestSection.Body) == 0 {
		return nil, errors.New("no MongoDB body found in the main section")
	}
	// first element in the request body is the operation name
	opE := requestSection.Body[0]
	// TODO (mongo) do we want heartbeat configuration to be configurable?, or operation filtering?, or would this be done on the global filtering level?
	if isHeartbeat(opE.Key) {
		return nil, fmt.Errorf("MongoDB heartbeat operation '%s' is ignored", opE.Key)
	}
	spanInfo.OpName = opE.Key
	/*
		TODO (mongo): right now we decide that the value of the first element is the collection name
		in most cases this is true, but it might not be the case for some operations like "listCollections" and "createUser"
		we might want to have a list of known operations and their expected collection names
	*/
	collectionStr, ok := opE.Value.(string)
	if !ok {
		return nil, fmt.Errorf("expected string for Collection name, got %T", opE.Value)
	}
	spanInfo.Collection = collectionStr
	db, ok := findStringInBson(requestSection.Body, "$db")
	if ok {
		spanInfo.DB = db
	}

	if len(request.ResponseSections) == 0 {
		// TODO (mongo) no response sections, we assume the operation was successful, even tho this is bad
		spanInfo.Success = true
	} else {
		responseSection := request.ResponseSections[0]
		if len(responseSection.Body) == 0 {
			return nil, errors.New("no MongoDB body found in the response section")
		}
		success, ok := findDoubleInBson(responseSection.Body, "ok")
		if !ok {
			return nil, errors.New("no 'ok' field found in MongoDB response")
		}
		spanInfo.Success = success == float64(1)
		if spanInfo.Success {
			// If the operation was successful, we can skip Error handling.
			return spanInfo, nil
		}
		errorMsg, ok := findStringInBson(responseSection.Body, "errmsg")
		if ok {
			spanInfo.Error = errorMsg
		}
		errorCode, ok := findIntInBson(responseSection.Body, "code")
		if ok {
			spanInfo.ErrorCode = errorCode
		}
		errorCodeName, ok := findStringInBson(responseSection.Body, "codeName")
		if ok {
			spanInfo.ErrorCodeName = errorCodeName
		}
	}

	return spanInfo, nil
}

func TCPToMongoToSpan(trace *TCPRequestInfo, info *MongoSpanInfo) request.Span {
	peer := ""
	peerPort := 0
	hostname := ""
	hostPort := 0

	reqType := request.EventTypeMongoClient
	if trace.Direction == 0 {
		reqType = request.EventTypeMongoServer
	}

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	var dbError request.DBError
	if !info.Success {
		dbError = request.DBError{
			ErrorCode:   strconv.Itoa(info.ErrorCode),
			Description: info.ErrorCodeName + ": " + info.Error,
		}
	}

	var status int
	if info.Success {
		status = 0
	} else {
		status = 1
	}

	return request.Span{
		Type:          reqType,
		Method:        info.OpName,
		Path:          info.Collection,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		DBError:       dbError,
		DBNamespace:   info.DB,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func findInBson(doc bson.D, key string) (any, bool) {
	for _, elem := range doc {
		if elem.Key == key {
			return elem.Value, true
		}
	}
	return nil, false
}

func findStringInBson(doc bson.D, key string) (string, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return "", false
	}
	strValue, ok := value.(string)
	if !ok {
		return "", false
	}
	return strValue, true
}

func findIntInBson(doc bson.D, key string) (int, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return 0, false
	}
	intValue, ok := value.(int) // MongoDB uses int32 for integer values
	if !ok {
		return 0, false
	}
	return intValue, true
}

func findDoubleInBson(doc bson.D, key string) (float64, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return 0, false
	}
	doubleValue, ok := value.(float64) // MongoDB uses int32 for integer values
	if !ok {
		return 0, false
	}
	return doubleValue, true
}
