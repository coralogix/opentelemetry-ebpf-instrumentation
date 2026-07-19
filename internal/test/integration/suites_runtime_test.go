// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestRuntimeMetricsProm(t *testing.T) {
	vPrometheus := docker.NewServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config-promscrape${PROM_CONFIG_SUFFIX:-}.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"}
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NoDefaultEnv: true,
			Pid:          "host",
			Ports:        []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
			RunDir:       "run-go-runtime-metrics",
			ExtraVolumes: []string{"/sys/kernel/tracing:/sys/kernel/tracing:rw"},
			DependsOn:    map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"GOCOVERDIR":                        "/coverage",
				"OTEL_EBPF_BPF_DEBUG":               "TRUE",
				"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
				"OTEL_EBPF_HOSTNAME":                "obi",
				"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
				"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
				"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics-prom.yml",
				"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
				"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
				"OTEL_EBPF_OPEN_PORT":               "8080",
				"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
			},
		}),
		"otelcol":    docker.OtelcolNoJaeger(),
		"prometheus": vPrometheus,
		"jaeger":     nil,
	}), "docker-compose-go-runtime-metrics.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with Prometheus export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsOTel(t *testing.T) {
	vPrometheus := docker.NewServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config-promscrape${PROM_CONFIG_SUFFIX:-}.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"}
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NoDefaultEnv: true,
			Pid:          "host",
			Ports:        []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
			RunDir:       "run-go-runtime-metrics",
			ExtraVolumes: []string{"/sys/kernel/tracing:/sys/kernel/tracing:rw"},
			DependsOn:    map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"GOCOVERDIR":                        "/coverage",
				"OTEL_EBPF_BPF_DEBUG":               "TRUE",
				"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
				"OTEL_EBPF_HOSTNAME":                "obi",
				"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
				"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
				"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics-otel.yml",
				"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
				"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
				"OTEL_EBPF_OPEN_PORT":               "8080",
				"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
			},
		}),
		"otelcol":    docker.OtelcolNoJaeger(),
		"prometheus": vPrometheus,
		"jaeger":     nil,
	}), "docker-compose-go-runtime-metrics.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
		`PROM_CONFIG_SUFFIX=-otel`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with OTel export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsPromGo117(t *testing.T) {
	vPrometheus := docker.NewServices()["prometheus"]
	vPrometheus.Command = []string{"--config.file=/etc/prometheus/prometheus-config-promscrape${PROM_CONFIG_SUFFIX:-}.yml", "--web.enable-lifecycle", "--enable-feature=exemplar-storage", "--web.route-prefix=/"}
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NoDefaultEnv: true,
			Pid:          "host",
			Ports:        []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
			RunDir:       "run-go-runtime-metrics",
			ExtraVolumes: []string{"/sys/kernel/tracing:/sys/kernel/tracing:rw"},
			DependsOn:    map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"GOCOVERDIR":                        "/coverage",
				"OTEL_EBPF_BPF_DEBUG":               "TRUE",
				"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
				"OTEL_EBPF_HOSTNAME":                "obi",
				"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
				"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
				"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics-prom.yml",
				"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
				"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
				"OTEL_EBPF_OPEN_PORT":               "8080",
				"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
			},
		}),
		"otelcol":    docker.OtelcolNoJaeger(),
		"prometheus": vPrometheus,
		"jaeger":     nil,
	}), "docker-compose-go-runtime-metrics.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsGo117HostPort+`:8080`,
		`RUNTIME_METRICS_TESTSERVER_DOCKERFILE=./internal/test/integration/components/go-runtime-metrics-server/Dockerfile_1.17`,
		`RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-go-runtime-metrics-1-17`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go 1.17 runtime metrics with Prometheus export", testRuntimeMetricsGo117)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
