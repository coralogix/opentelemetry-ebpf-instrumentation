// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestPerAppFeatures(t *testing.T) {
	vPrometheus := docker.StdServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config-perapp.yml", "--web.enable-lifecycle", "--web.route-prefix=/", "--log.level=debug"}
	compose := docker.SuiteStackServices(t, docker.StdStack(map[string]*docker.ServiceDef{
		"obi": docker.StdOBI(docker.OBI{
			ConfigYAML: obiConfigPerapp,
			Pid:        "host",
			Ports:      []string{"8999:8999"},
			RunDir:     "run-multi",
			Env: map[string]string{
				"OTEL_EBPF_BPF_CONTEXT_PROPAGATION":          "${OTEL_EBPF_BPF_CONTEXT_PROPAGATION}",
				"OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP":         "${OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP}",
				"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS":        "${OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS}",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH": "/metrics",
				"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT": "8999",
				"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT":        "0ms",
			},
		}),
		"jtestserver": &docker.ServiceDef{
			Image: "ghcr.io/open-telemetry/obi-testimg:java-jar-0.1.0@sha256:92d325a0a7aadcce2559de70ef66d39fa07075b57d8fa33b4244ada4dde3787e",
			Ports: []string{"8086:8085"},
		},
		"ntestserver": &docker.ServiceDef{
			Image:           "hatest-testserver-node",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/nodejsserver/Dockerfile",
			Command:         []string{"node", "app.js"},
			Ports:           []string{"3031:3030"},
		},
		"pytestserver": &docker.ServiceDef{
			Image:           "hatest-testserver-python",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/pythonserver/Dockerfile_7773",
			Ports:           []string{"7773:7773"},
		},
		"rtestserver": &docker.ServiceDef{
			Image: "ghcr.io/open-telemetry/obi-testimg:rust-0.1.0@sha256:3989aa18c1e23cbb5a4c511ae1ad3456f94a9b967fd916bc21ee10c1d940a95d",
			Ports: []string{"8091:8090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "hatest-testserver",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/testserver/Dockerfile",
			Ports:           []string{"8080:8080", "8088:8088"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
		},
		"utestserver": &docker.ServiceDef{
			Image: "ghcr.io/open-telemetry/obi-testimg:rails-0.1.0@sha256:7a72159a113b9044378c42f7ea27ab00673c6a0ebfe3ac205cc006f46606b36c",
			Ports: []string{"3041:3040"},
		},
		"prometheus": vPrometheus,
		"jaeger":     nil,
	}))
	require.NoError(t, compose.Up())

	t.Run("OTEL exporter", func(t *testing.T) {
		testPerAppFeatures(t, "otel")
	})
	t.Run("Prometheus exporter", func(t *testing.T) {
		testPerAppFeatures(t, "prometheus")
	})

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}

func testPerAppFeatures(t *testing.T, exportedSource string) {
	t.Run("all the services have span metrics", func(t *testing.T) {
		checkSpanMetric(t, 3*time.Minute, exportedSource, "node", 3031, "/testing-node")
		checkSpanMetric(t, time.Minute, exportedSource, "ruby", 3041, "/testing-rails")
		checkSpanMetric(t, time.Minute, exportedSource, "pytestserver", 7773, "/testing-python")
		checkSpanMetric(t, time.Minute, exportedSource, "testserver", 8080, "/testing-go")
		checkSpanMetric(t, time.Minute, exportedSource, "jtestserver", 8086, "/testing-java")
		checkSpanMetric(t, time.Minute, exportedSource, "rtestserver", 8091, "/testing-rust")
	})
	t.Run("node, rails and python have RED metrics", func(t *testing.T) {
		hasREDMetrics(t, exportedSource, "node", "/testing-node")
		hasREDMetrics(t, exportedSource, "ruby", "/testing-rails")
		hasREDMetrics(t, exportedSource, "pytestserver", "/testing-python")
	})
	t.Run("rest of services don't have RED metrics", func(t *testing.T) {
		hasNotREDMetrics(t, "testserver")
		hasNotREDMetrics(t, "jtestserver")
		hasNotREDMetrics(t, "rtestserver")
	})
}

var pq = promtest.Client{HostPort: prometheusHostPort}

func checkSpanMetric(t *testing.T, timeout time.Duration, exportedSource, serviceName string, port int, path string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d%s", port, path), nil)
		require.NoError(ct, err)
		_, err = testHTTPClient.Do(req)
		require.NoError(ct, err)

		results, err := pq.Query(`traces_span_metrics_duration_seconds_sum{exported="` + exportedSource +
			`",service_name="` + serviceName + `",span_name="GET ` + path + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, timeout, time.Second)
}

func hasREDMetrics(t *testing.T, exportedSource, serviceName string, path string) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_body_size_bytes_sum{exported="` + exportedSource +
			`",service_name="` + serviceName + `",http_route="` + path + `"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, time.Minute, time.Second)
}

func hasNotREDMetrics(t *testing.T, serviceName string) {
	results, err := pq.Query(`http_server_request_body_size_bytes_sum{service_name="` + serviceName + `"}`)
	require.NoError(t, err)
	require.Empty(t, results)
}
