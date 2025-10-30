// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// elasticsearchOperation contains only fields related to elasticsearch
type elasticsearchOperation struct {
	NodeName         string
	DBQueryText      string
	DBOperationName  string
	DBCollectionName string
}

var supportedOperationMethods = map[string]map[string]struct{}{
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search
	"_search": {http.MethodPost: {}, http.MethodGet: {}},
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-msearch
	"_msearch": {http.MethodPost: {}, http.MethodGet: {}},
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk
	"_bulk": {http.MethodPost: {}, http.MethodPut: {}},
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-get
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-index
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-delete
	// https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-exists
	"_doc": {http.MethodGet: {}, http.MethodPost: {}, http.MethodPut: {}, http.MethodHead: {}, http.MethodDelete: {}},
}

func ElasticsearchSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	if !isElasticsearchResponse(resp) {
		return *baseSpan, false
	}
	if err := isSupportedRequest(req); err != nil {
		slog.Debug(err.Error())
		return *baseSpan, false
	}
	op, err := parseElasticsearchRequest(req)
	if err != nil {
		slog.Debug("parse Elasticsearch request", "error", err)
		return *baseSpan, false
	}
	if resp != nil {
		if v := resp.Header.Get("X-Found-Handling-Instance"); v != "" {
			op.NodeName = v
		}
	} else {
		op.NodeName = req.URL.Host
	}

	baseSpan.SubType = request.HTTPSubtypeElasticsearch
	baseSpan.Elasticsearch = &request.Elasticsearch{
		NodeName:         op.NodeName,
		DBOperationName:  op.DBOperationName,
		DBCollectionName: op.DBCollectionName,
		DBQueryText:      op.DBQueryText,
	}
	return *baseSpan, true
}

func parseElasticsearchRequest(req *http.Request) (elasticsearchOperation, error) {
	var op elasticsearchOperation
	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return op, fmt.Errorf("failed to read Elasticsearch request body %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))
	operationName := extractOperationName(req)
	op.DBQueryText = string(reqB)
	op.DBOperationName = operationName
	op.DBCollectionName = extractDBCollectionName(req)
	return op, nil
}

func isSupportedRequest(req *http.Request) error {
	urlPath := req.URL.Path

	for operation, methods := range supportedOperationMethods {
		if strings.Contains(urlPath, operation) {

			_, supported := methods[req.Method]
			if supported {
				return nil
			}
			return fmt.Errorf("parse Elasticsearch %s request: unsupported method %s", operation, req.Method)
		}
	}

	return errors.New("parse Elasticsearch request: unsupported endpoint")
}

// isElasticsearchResponse checks if X-Elastic-Product HTTP header is present.
// Note: this header was introduced in Elasticsearch version 7.14
// For older versions, we just classify it as HTTP
func isElasticsearchResponse(resp *http.Response) bool {
	headerValue := resp.Header.Get("X-Elastic-Product")
	expectedValue := "Elasticsearch"
	return headerValue == expectedValue
}

// extractOperationName is a generic function used to extract the operation name
// that is the endpoint identifier provided in the request
func extractOperationName(req *http.Request) string {
	path := strings.Trim(req.URL.Path, "/")
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")

	for _, part := range parts {
		if part != "" && strings.HasPrefix(part, "_") {
			return strings.TrimPrefix(part, "_")
		}
	}
	return ""
}

// extractDBCollectionName takes into account this rule from semconv
// The query may target multiple indices or data streams,
// in which case it SHOULD be a comma separated list of those.
// If the query doesn’t target a specific index, this field MUST NOT be set.
func extractDBCollectionName(req *http.Request) string {
	path := strings.Trim(req.URL.Path, "/")
	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	first := parts[0]
	if strings.HasPrefix(first, "_") {
		return ""
	}
	return first
}
