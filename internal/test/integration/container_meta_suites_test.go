// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exec provides the utilities to analyze the executable code

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestSuite_DockerMetadata(t *testing.T) {
	vOtelcol := docker.StdServices()["otelcol"]
	vOtelcol.DependsOn = map[string]string{"jaeger": "service_started", "obi": "service_started", "prometheus": "service_started", "weaver": "service_healthy"}
	vPrometheus := docker.StdServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config-perapp.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"}
	compose := docker.SuiteStackServices(t, docker.StdStack(map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML: obiConfigContainerMeta,
			Pid:        "host",
			Ports:      []string{"8999:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security${SECURITY_CONFIG_SUFFIX}:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-base${TESTSERVER_DOCKERFILE_SUFFIX}:/var/run/obi",
				"/var/run/docker.sock:/var/run/docker.sock",
			},
			Env: map[string]string{
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_METRICS_FEATURES":                 featuresFull,
				"OTEL_EBPF_PROCESSES_INTERVAL":               "100ms",
				"OTEL_EBPF_PROMETHEUS_FEATURES":              featuresFull,
				"OTEL_EBPF_PROMETHEUS_PORT":                  "8999",
				"OTEL_EBPF_TRACE_PRINTER":                    "json",
			},
		}),
		"testserver-as-in-compose": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile",
			Ports:           []string{"8080:8080"},
			Env: map[string]string{
				"LOG_LEVEL":                "DEBUG",
				"OTEL_RESOURCE_ATTRIBUTES": "service.version=1.0.0",
			},
		},
		"otelcol":    vOtelcol,
		"prometheus": vPrometheus,
	}))
	require.NoError(t, compose.Up())

	t.Run("OTEL metrics are decorated with container metadata", func(t *testing.T) {
		testContainerMetaMetrics(t, "otel")
	})
	t.Run("Prometheus metrics are decorated with container metadata", func(t *testing.T) {
		testContainerMetaMetrics(t, "prometheus")
	})
	t.Run("traces are decorated with container metadata", testContainerMetaTraces)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func testContainerMetaMetrics(t *testing.T, exporter string) {
	waitForTestComponents(t, instrumentedServiceStdURL)

	// directly checking the "/smoke" path from the waitForTestComponents function
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`container_id=~"[0-9a-fA-F]{12}",` +
			`container_name="integration-testserver-as-in-compose-1",` +
			`service_name="testserver-as-in-compose",` +
			`exported="` + exporter + `",` +
			`http_route="/smoke"}`)
		require.NoError(ct, err)
		assert.NotEmpty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	// check correctness of target_info attributes
	results, err := pq.Query(`target_info{` +
		`exported="` + exporter + `",` +
		`container_id=~"[0-9a-fA-F]{12}",` +
		`container_name="integration-testserver-as-in-compose-1",` +
		`service_name="testserver-as-in-compose",` +
		`instance="testserver-as-in-compose.integration-testserver-as-in-compose-1"` +
		`}`)
	require.NoError(t, err)
	assert.NotEmpty(t, results)
}

func testContainerMetaTraces(t *testing.T) {
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver-as-in-compose&operation=GET%20%2Fsmoke")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/smoke"})
		require.NotEmpty(ct, traces)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /smoke", "server")
	require.NotEmpty(t, res)

	proc := trace.Processes[res[0].ProcessID]
	assert.Equal(t, "testserver-as-in-compose", proc.ServiceName)
	tags := map[string]string{}
	for _, tag := range proc.Tags {
		tags[tag.Key] = fmt.Sprintf("%v", tag.Value)
	}
	assert.Regexp(t, "^[0-9a-fA-F]{12}$", tags["container.id"])
	assert.Equal(t, "integration-testserver-as-in-compose-1", tags["container.name"])
}
