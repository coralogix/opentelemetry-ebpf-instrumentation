// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func TestSuiteGRPCMetadataEnrichment(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-metadata.yml", path.Join(pathOutput, "test-suite-grpc-metadata.log"))
	require.NoError(t, err)

	require.NoError(t, compose.Up())

	t.Run("gRPC metadata extraction", func(t *testing.T) {
		testGRPCMetadataExtraction(t)
	})

	require.NoError(t, compose.Close())
}

func testGRPCMetadataExtraction(t *testing.T) {
	// Wait for services to be ready by polling the HTTP endpoint
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(instrumentedServiceStdURL + "/query")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		assert.Equal(ct, http.StatusOK, resp.StatusCode)
	}, 2*time.Minute, time.Second)

	// Send requests to /query_with_metadata (which sends gRPC with custom metadata)
	for i := 0; i < 4; i++ {
		resp, err := http.Get(instrumentedServiceStdURL + "/query_with_metadata")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Query Jaeger for gRPC traces
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=grpcsrv&limit=100")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/GetFeature"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// Find the server span
	res := trace.FindByOperationName("/routeguide.RouteGuide/GetFeature", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify included request metadata: x-custom-request-id should be present
	tag, ok := jaeger.FindIn(span.Tags, "rpc.request.metadata.x-custom-request-id")
	require.True(t, ok, "expected x-custom-request-id request metadata on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "test-req-123", val)

	// Verify obfuscated request metadata: x-session-token should be obfuscated
	tag, ok = jaeger.FindIn(span.Tags, "rpc.request.metadata.x-session-token")
	require.True(t, ok, "expected x-session-token request metadata on span (obfuscated)")
	val, valOk = jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "***", val, "x-session-token should be obfuscated")

	// Verify response trailing metadata: x-custom-response-id should be present
	tag, ok = jaeger.FindIn(span.Tags, "rpc.response.metadata.x-custom-response-id")
	require.True(t, ok, "expected x-custom-response-id response metadata on span")
	val, valOk = jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Equal(t, "test-resp-456", val)
}
