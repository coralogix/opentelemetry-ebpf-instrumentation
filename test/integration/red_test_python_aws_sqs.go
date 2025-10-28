// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/test/integration/components/jaeger"
)

type (
	sqsQueueURL struct {
		QueueURL string `json:"QueueURL"`
	}
	sqsMessages struct {
		Messages []struct {
			MessageID     string `json:"MessageId"`
			ReceiptHandle string `json:"ReceiptHandle"`
			Body          string `json:"Body"`
		} `json:"Messages"`
	}
)

func testPythonAWSSQS(t *testing.T) {
	waitAWSProxy(t)
	waitForTestComponentsNoMetrics(t, localstackAddress)

	// Create SQS Queue
	qr := sqsRequestWithData[sqsQueueURL](t, awsProxyAddress+"/createqueue")

	// Send 3 messages
	awsReq(t, awsProxyAddress+"/sendmessage?queue_url="+qr.QueueURL)
	awsReq(t, awsProxyAddress+"/sendmessage?queue_url="+qr.QueueURL)
	awsReq(t, awsProxyAddress+"/sendmessage?queue_url="+qr.QueueURL)

	// Receive messages
	mr := sqsRequestWithData[sqsMessages](t, awsProxyAddress+"/receivemessages?queue_url="+qr.QueueURL)
	require.Len(t, mr.Messages, 3)

	// Delete one message
	awsReq(t, awsProxyAddress+"/deletemessage?queue_url="+qr.QueueURL+"&receipt_handle="+mr.Messages[0].ReceiptHandle)

	// Get Queue Attributes
	awsReq(t, awsProxyAddress+"/getqueueattributes?queue_url="+qr.QueueURL)

	// Delete Queue
	awsReq(t, awsProxyAddress+"/deletequeue?queue_url="+qr.QueueURL)

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assertSQSOperation(t, "CreateQueue", qr.QueueURL, "", "")
		assertSQSOperation(t, "SendMessage", qr.QueueURL, mr.Messages[0].MessageID, "send")
		assertSQSOperation(t, "SendMessage", qr.QueueURL, mr.Messages[1].MessageID, "send")
		assertSQSOperation(t, "SendMessage", qr.QueueURL, mr.Messages[2].MessageID, "send")
		assertSQSOperation(t, "ReceiveMessage", qr.QueueURL, "", "receive")
		assertSQSOperation(t, "DeleteMessage", qr.QueueURL, mr.Messages[0].MessageID, "")
		assertSQSOperation(t, "GetQueueAttributes", qr.QueueURL, "", "")
		assertSQSOperation(t, "DeleteQueue", qr.QueueURL, "", "")
	}, test.Interval(time.Second))
}

func sqsRequestWithData[T sqsQueueURL | sqsMessages](t *testing.T, url string) T {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 204)

	var data T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	return data
}

func assertSQSOperation(t require.TestingT, op, expectedQueueURL, expectedMessageID, expectedOperationType string) {
	opName := "sqs." + op

	spans := fetchAWSSpansByOP(t, opName)
	require.GreaterOrEqual(t, len(spans), 1)

	var span jaeger.Span
	if expectedMessageID != "" {
		var found bool
		for _, s := range spans {
			tag, _ := jaeger.FindIn(s.Tags, "messaging.message.id")
			if tag.Value == expectedMessageID {
				span = s
				found = true
			}
		}
		require.True(t, found, "Span with message ID %s not found", expectedMessageID)
	} else {
		span = spans[0]
	}
	require.Equal(t, opName, span.OperationName)

	tag, found := jaeger.FindIn(span.Tags, "aws.request_id")
	require.True(t, found)
	require.NotEmpty(t, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "cloud.region")
	require.True(t, found)
	require.Empty(t, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.sqs.queue_url")
	require.True(t, found)
	require.Equal(t, expectedQueueURL, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.message.id")
	require.True(t, found)
	require.Equal(t, expectedMessageID, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.destination.name")
	require.True(t, found)
	require.Equal(t, "obi-queue", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.operation.type")
	require.True(t, found)
	require.Equal(t, expectedOperationType, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.operation.name")
	require.True(t, found)
	require.Equal(t, op, tag.Value)
}
