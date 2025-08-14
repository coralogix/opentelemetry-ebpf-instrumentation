// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.opentelemetry.io/obi/pkg/components/ebpf/common/kafka_parser"
	"regexp"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/app/request"
)

type Operation int8

const (
	Produce Operation = 0
	Fetch   Operation = 1
)

type Header struct {
	MessageSize   int32
	APIKey        int16
	APIVersion    int16
	CorrelationID int32
	ClientIDSize  int16
}

type KafkaInfo struct {
	Operation   Operation
	Topic       string
	ClientID    string
	TopicOffset int
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return request.MessagingPublish
	case Fetch:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

const (
	KafkaMinLength  = 14
	KafkaMaxPayload = 20 * 1024 * 1024 // 20 MB max, 1MB is default for most Kafka installations
)

var topicRegex = regexp.MustCompile("\x02\t(.*)\x02")

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return kafka.Info with the processed data.
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte, kafkaTopicUUIDToName *simplelru.LRU[kafka_parser.UUID, string]) (*KafkaInfo, bool, error) {
	k, ok, err := ProcessKafkaEvent(pkt, rpkt, kafkaTopicUUIDToName)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		k, ok, err = ProcessKafkaEvent(rpkt, pkt, kafkaTopicUUIDToName)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, ok, err
}

func ProcessKafkaEvent(pkt []byte, rpkt []byte, kafkaTopicUUIDToName *simplelru.LRU[kafka_parser.UUID, string]) (*KafkaInfo, bool, error) {
	hdr, offset, err := kafka_parser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafka_parser.ApiKeyProduce:
		return processProduceRequest(pkt, hdr, offset)
	case kafka_parser.ApiKeyFetch:
		return processFetchRequest(pkt, hdr, offset, kafkaTopicUUIDToName)
	case kafka_parser.ApiKeyMetadata:
		return processMetadataResponse(rpkt, hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func processProduceRequest(pkt []byte, hdr *kafka_parser.KafkaRequestHeader, offset kafka_parser.Offset) (*KafkaInfo, bool, error) {
	produceReq, err := kafka_parser.ParseProduceRequest(pkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}
	return &KafkaInfo{
		ClientID:  hdr.ClientID,
		Operation: Produce,
		// TODO: handle multiple topics
		Topic: produceReq.Topics[0].Name,
	}, false, nil
}

func processFetchRequest(pkt []byte, hdr *kafka_parser.KafkaRequestHeader, offset kafka_parser.Offset, kafkaTopicUUIDToName *simplelru.LRU[kafka_parser.UUID, string]) (*KafkaInfo, bool, error) {
	fetchReq, err := kafka_parser.ParseFetchRequest(pkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}
	firstTopic := fetchReq.Topics[0]
	var topicName = firstTopic.Name
	// get topic name from UUID if available
	if firstTopic.UUID != nil {
		var found bool
		topicName, found = kafkaTopicUUIDToName.Get(*firstTopic.UUID)
		if !found {
			topicName = "*"
		}
	}
	return &KafkaInfo{
		ClientID:  hdr.ClientID,
		Operation: Fetch,
		// TODO: handle multiple topics
		Topic: topicName,
	}, false, nil
}

func processMetadataResponse(rpkt []byte, hdr *kafka_parser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafka_parser.UUID, string]) (*KafkaInfo, bool, error) {
	// only interested in response
	_, offset, err := kafka_parser.ParseKafkaResponseHeader(rpkt, hdr)
	if err != nil {
		return nil, true, err
	}
	metadataResponse, err := kafka_parser.ParseMetadataResponse(rpkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}
	for _, topic := range metadataResponse.Topics {
		kafkaTopicUUIDToName.Add(topic.UUID, topic.Name)
	}
	return nil, true, nil
}

func ProcessKafkaRequest(pkt []byte) (*KafkaInfo, bool, error) {
	hdr, offset, err := kafka_parser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafka_parser.ApiKeyProduce:
		return processProduceRequest(pkt, hdr, offset)
	case kafka_parser.ApiKeyFetch:
		return processFetchRequest(pkt, hdr, offset, nil)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeKafkaClient
	if trace.Direction == 0 {
		reqType = request.EventTypeKafkaServer
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          data.Topic,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
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
