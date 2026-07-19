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
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testREDMetricsTracesForOldGRPCLibrary(t *testing.T, svcNs string) {
	url := "http://localhost:8080"

	waitForTestComponentsSub(t, url, "/factorial/1")

	path := "/factorial/2"

	for i := 0; i < 4; i++ {
		doHTTPGetIgnoreStatus(t, url+path)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="backend",` +
			`url_path="` + path + `"}`)
		require.NoError(ct, err)
		// check duration_count has 3 calls and all the arguments
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(ct, addr)
		}
	}, 1*time.Minute, 100*time.Millisecond)

	// Eventually, Prometheus would make this query visible
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`rpc_server_call_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="worker",` +
			`rpc_method="/fib.Multiplier/Loop"}`)
		require.NoError(ct, err)
		// check duration_count has at least 3 calls and all the arguments
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 3, val)
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			assert.NotNil(ct, addr)
		}
	}, testTimeout, 100*time.Millisecond)

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=backend&operation=GET%20%2Ffactorial%2F")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, 1*time.Minute, 100*time.Millisecond)

	// Check the information of the python parent span
	res := trace.FindByOperationName("GET /factorial/", "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "url.path", Type: "string", Value: path},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/factorial/"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}

func testGRPCGoClientFailsToConnect(t *testing.T) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	// Eventually, Prometheus would make this query visible
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`rpc_client_call_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="grpcpinger",` +
			`rpc_response_status_code="UNKNOWN",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		val := totalPromCount(ct, results)
		assert.LessOrEqual(ct, 1, val)
	}, testTimeout, 100*time.Millisecond)
}

func TestSuiteOtherGRPCGo(t *testing.T) {
	vOtelcol := docker.StdServices()["otelcol"]
	vOtelcol.DependsOn = map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"}
	compose := docker.SuiteStackServices(t, docker.StdStack(map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML: obiConfigOtherGrpc,
			Pid:        "host",
			Ports:      []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-other-grpc:/var/run/obi",
			},
			Env: map[string]string{
				"OTEL_EBPF_EXECUTABLE_PATH":                  "${OTEL_EBPF_EXECUTABLE_PATH}",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresAppSpan,
				"OTEL_EBPF_PROMETHEUS_FEATURES":              "application,application_span",
			},
		}),
		"backend": &docker.ServiceDef{
			Image:           "hatest-backend",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/old_grpc/backend/Dockerfile",
			Ports:           []string{"8080:8080"},
			Env: map[string]string{
				"WORKERS": "worker:5000",
			},
		},
		"grpcpinger": &docker.ServiceDef{
			Image:           "hatest-grpcpinger",
			BuildContext:    "../../../",
			BuildDockerfile: "internal/test/integration/components/grpcpinger/Dockerfile",
			Env: map[string]string{
				"TARGET_URL": "localhost:12345",
			},
		},
		"worker": &docker.ServiceDef{
			Image:           "hatest-worker",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/old_grpc/worker/Dockerfile",
			Ports:           []string{"5000:5000"},
		},
		"otelcol": vOtelcol,
	}))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`, `PROM_CONFIG_SUFFIX=`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics and traces: old grpc service", func(t *testing.T) {
		testREDMetricsTracesForOldGRPCLibrary(t, "integration-test")
	})

	t.Run("Go RED metrics and traces: grpc client fails to connect", func(t *testing.T) {
		testGRPCGoClientFailsToConnect(t)
	})

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
