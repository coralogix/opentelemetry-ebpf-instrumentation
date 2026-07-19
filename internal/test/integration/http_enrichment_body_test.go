// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

// testBodyExtractionObfuscate verifies that the body extraction rules correctly
// capture the request body with sensitive fields obfuscated.
func testBodyExtractionObfuscate(t *testing.T) {
	// Send POST requests with a JSON body containing sensitive fields.
	// The config obfuscates $.password and $.secret with "***", credit-card
	// fields with "PCI", and social/insurance numbers with "PII" on POST requests.
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/50", 200,
			[]byte(`{"username":"alice","password":"secret123","secret":"my-api-key","email":"alice@test.com","credit-card":"4111-1111-1111-1111","creditcard":"5555555555554444","cc":"378282246310005","sin":"046454286","ssn":"123-45-6789"}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/50"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify the request body content attribute is present.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	require.True(t, ok, "expected http.request.body.content on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)

	// Verify sensitive fields are obfuscated with the default obfuscation string.
	assert.NotContains(t, val, "secret123", "password should be obfuscated")
	assert.NotContains(t, val, "my-api-key", "secret should be obfuscated")
	assert.Contains(t, val, "***", "default obfuscation string should be present")

	// Verify credit-card fields are obfuscated with the per-rule "PCI" string.
	assert.NotContains(t, val, "4111-1111-1111-1111", "credit-card should be obfuscated")
	assert.NotContains(t, val, "5555555555554444", "creditcard should be obfuscated")
	assert.NotContains(t, val, "378282246310005", "cc should be obfuscated")
	assert.Contains(t, val, "PCI", "credit-card obfuscation string should be present")

	// Verify social/insurance numbers are obfuscated with the per-rule "PII" string.
	assert.NotContains(t, val, "046454286", "sin should be obfuscated")
	assert.NotContains(t, val, "123-45-6789", "ssn should be obfuscated")
	assert.Contains(t, val, "PII", "sin/ssn obfuscation string should be present")
}

// testBodyExtractionInclude verifies that body include rules capture the raw body
// without obfuscation when only an include rule matches.
func testBodyExtractionInclude(t *testing.T) {
	// The config has an include rule for POST /rolldice/* which also matches,
	// but the obfuscate rule also matches POST requests.
	// Since body rules merge, both rules apply: obfuscate paths are applied
	// to the included body.

	// Send a POST without the sensitive fields to test pure include behavior.
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/51", 200,
			[]byte(`{"action":"roll","sides":6}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/51"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify the request body content is present with original values.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	require.True(t, ok, "expected http.request.body.content on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Contains(t, val, "roll", "action field should be present")
	assert.Contains(t, val, "6", "sides field should be present")
}

// testBodyExtractionExcludedByDefault verifies that GET requests (which don't match
// any body rules) have no body content on the span.
func testBodyExtractionExcludedByDefault(t *testing.T) {
	for i := 0; i < 4; i++ {
		doHTTPGetWithHeaders(t, instrumentedServiceStdURL+"/rolldice/52", 200, nil)
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/52"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("GET /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify no body content is present (default_action for body is exclude).
	_, ok := jaeger.FindIn(span.Tags, "http.request.body.content")
	assert.False(t, ok, "GET request should not have body content")
	_, ok = jaeger.FindIn(span.Tags, "http.response.body.content")
	assert.False(t, ok, "response body should not be present")
}

// testBodyExtractionContentTypeHeader verifies that the Content-Type header
// is also included on the span (configured via a header include rule).
func testBodyExtractionContentTypeHeader(t *testing.T) {
	for i := 0; i < 4; i++ {
		doHTTPPost(t, instrumentedServiceStdURL+"/rolldice/53", 200,
			[]byte(`{"test":"header-check"}`))
	}

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=POST%20%2Frolldice%2F%3Aid")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/rolldice/53"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	res := trace.FindByOperationName("POST /rolldice/:id", "server")
	require.NotEmpty(t, res)
	span := res[0]

	// Verify Content-Type header is included alongside body content.
	tag, ok := jaeger.FindIn(span.Tags, "http.request.header.content-type")
	require.True(t, ok, "expected Content-Type header on span")
	val, valOk := jaeger.TagFirstStringValue(tag)
	require.True(t, valOk)
	assert.Contains(t, val, "application/json")

	// Body should also be present.
	_, ok = jaeger.FindIn(span.Tags, "http.request.body.content")
	assert.True(t, ok, "expected body content alongside headers")
}

func TestSuiteBodyExtraction(t *testing.T) {
	vOtelcol := docker.StdServices()["otelcol"]
	vOtelcol.DependsOn = map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"}
	compose := docker.SuiteStackServices(t, docker.StdStack(map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			Pid:     "host",
			Command: []string{"--config=/configs/obi-config${INSTRUMENTER_CONFIG_SUFFIX}.yml"},
			Ports:   []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
			},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH":                           "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_EXTRA_SPAN_RESOURCE_ATTRIBUTES":            "service.version",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT":          "8999",
				"OTEL_EBPF_LOG_FORMAT":                                "json",
				"OTEL_EBPF_METRICS_FEATURES":                          featuresFull,
				"OTEL_EBPF_PROCESSES_INTERVAL":                        "100ms",
				"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES": "service.version",
				"OTEL_EBPF_PROMETHEUS_FEATURES":                       featuresFull,
				"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS":                   "",
				"OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS":                  "${OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS}",
				"OTEL_EBPF_TRACE_PRINTER":                             "json",
			},
		}),
		"pingclient": &docker.ServiceDef{
			Image:           "hatest-pingclient",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pingclient/Dockerfile${PINGSERVER_DOCKERFILE_SUFFIX}",
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile${TESTSERVER_DOCKERFILE_SUFFIX}",
			Ports:           []string{"8080:8080", "8081:8081", "8082:8082", "8083:8083", "8087:8087", "8088:8088", "8383:8383", "5051:5051", "50051:50051"},
			Env: map[string]string{
				"LOG_LEVEL":                "DEBUG",
				"OTEL_RESOURCE_ATTRIBUTES": "service.version=1.0.0",
			},
		},
		"otelcol": vOtelcol,
	}))
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-http-enrichment-body")
	compose.Env = append(compose.Env, "OTEL_EBPF_SKIP_GO_SPECIFIC_TRACERS=true")
	require.NoError(t, compose.Up())

	t.Run("Body extraction obfuscate", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testBodyExtractionObfuscate(t)
	})
	t.Run("Body extraction include", func(t *testing.T) {
		testBodyExtractionInclude(t)
	})
	t.Run("Body excluded by default", func(t *testing.T) {
		testBodyExtractionExcludedByDefault(t)
	})
	t.Run("Body with Content-Type header", func(t *testing.T) {
		testBodyExtractionContentTypeHeader(t)
	})

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
