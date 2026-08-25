// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import "bytes"

// ProtoVersion is the wire protocol version of a span, reported as semconv
// network.protocol.version. It is a uint8 rather than a string so it fits in
// the padding Span already carries.
type ProtoVersion uint8

const (
	ProtoVersionUnknown ProtoVersion = iota
	ProtoVersionHTTP10
	ProtoVersionHTTP11
	ProtoVersionHTTP2
)

// String returns the semconv network.protocol.version value, or "" when the
// version was never determined so callers omit the attribute.
func (v ProtoVersion) String() string {
	switch v {
	case ProtoVersionHTTP10:
		return "1.0"
	case ProtoVersionHTTP11:
		return "1.1"
	case ProtoVersionHTTP2:
		return "2"
	}

	return ""
}

// HTTPProtoVersionFromRequestLine reads the version from an HTTP/1 request
// line ("GET /path HTTP/1.1"), whose third token is the only place the wire
// carries it.
func HTTPProtoVersionFromRequestLine(req []byte) ProtoVersion {
	if end := bytes.IndexByte(req, 0); end >= 0 {
		req = req[:end]
	}
	if end := bytes.IndexAny(req, "\r\n"); end >= 0 {
		req = req[:end]
	}

	idx := bytes.LastIndex(req, []byte(" HTTP/"))
	if idx < 0 {
		return ProtoVersionUnknown
	}

	switch string(req[idx+len(" HTTP/"):]) {
	case "1.0":
		return ProtoVersionHTTP10
	case "1.1":
		return ProtoVersionHTTP11
	case "2", "2.0":
		return ProtoVersionHTTP2
	}

	return ProtoVersionUnknown
}
