// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"strconv"

	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
)

// ErrorTypeOther is the semconv fallback for an error that carries no
// lower-cardinality classification of its own.
const ErrorTypeOther = "_OTHER"

// SpanErrorType returns the semconv error.type value for a failed span, or ""
// when the span did not fail or its protocol cannot report failure. Every value
// comes from a closed set: semconv requires error.type to stay low cardinality,
// so a free-text server message is never used here.
//
// Callers that already derived a more specific error.type from protocol detail
// should keep theirs; this is the generic status-derived fallback.
func SpanErrorType(span *Span) string {
	if SpanStatusCode(span) != StatusCodeError {
		return ""
	}

	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		if span.Status >= 400 {
			return strconv.Itoa(span.Status)
		}
		return ErrorTypeOther
	case EventTypeGRPC, EventTypeGRPCClient:
		if code := GRPCStatusCodeString(span.Status); code != "" {
			return code
		}
		return ErrorTypeOther
	case EventTypeRedisClient, EventTypeRedisServer,
		EventTypeMongoClient, EventTypeCouchbaseClient,
		EventTypeMemcachedClient, EventTypeMemcachedServer,
		EventTypeAerospikeClient:
		if span.DBError.ErrorCode != "" {
			return span.DBError.ErrorCode
		}
		return ErrorTypeOther
	case EventTypeDNS:
		return dnsparser.RCode(span.Status).String()
	case EventTypeSQLClient, EventTypeSQLServer,
		EventTypeSunRPCServer, EventTypeSunRPCClient,
		EventTypeFailedConnect:
		return ErrorTypeOther
	}

	return ""
}
