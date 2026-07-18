// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestRuntimeMetricsProm(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			Pid:   "host",
			Ports: []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
			Volumes: []string{
				"./configs/:/configs",
				"./system/sys/kernel/security:/sys/kernel/security",
				"../../../testoutput:/coverage",
				"../../../testoutput/run-go-runtime-metrics:/var/run/obi",
				"/sys/kernel/tracing:/sys/kernel/tracing:rw",
			},
			DependsOn: map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"GOCOVERDIR":                        "/coverage",
				"OTEL_EBPF_BPF_DEBUG":               "TRUE",
				"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics${INSTRUMENTER_CONFIG_SUFFIX}.yml",
				"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
				"OTEL_EBPF_HOSTNAME":                "obi",
				"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
				"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
				"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
				"OTEL_EBPF_OPEN_PORT":               "8080",
				"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
				"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
				"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
			},
		},
		"otelcol": &docker.ServiceDef{
			Command:   []string{"--config=/etc/otelcol-config/otelcol-config-weaver-no-jaeger.yml"},
			Ports:     []string{"4317", "4318:4318", "9464", "8888"},
			DependsOn: map[string]string{"prometheus": "service_started", "weaver": "service_healthy"},
		},
		"prometheus": &docker.ServiceDef{
			Command: []string{"--config.file=/etc/prometheus/prometheus-config-promscrape${PROM_CONFIG_SUFFIX}.yml", "--web.enable-lifecycle", "--web.route-prefix=/"},
			Ports:   []string{"9090:9090"},
		},
		"testserver": &docker.ServiceDef{
			Image:           "${RUNTIME_METRICS_TESTSERVER_IMAGE:-hatest-testserver-go-runtime-metrics}",
			BuildContext:    "../../..",
			BuildDockerfile: "${RUNTIME_METRICS_TESTSERVER_DOCKERFILE:-./internal/test/integration/components/go-runtime-metrics-server/Dockerfile}",
			Ports:           []string{"${TEST_SERVICE_PORTS}"},
			DependsOn:       map[string]string{"otelcol": "service_started"},
			Env: map[string]string{
				"GOMEMLIMIT": "512MiB",
			},
		},
	}}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-prom`,
		`PROM_CONFIG_SUFFIX=`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with Prometheus export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsOTel(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		Pid:   "host",
		Ports: []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-go-runtime-metrics:/var/run/obi",
			"/sys/kernel/tracing:/sys/kernel/tracing:rw",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"GOCOVERDIR":                        "/coverage",
			"OTEL_EBPF_BPF_DEBUG":               "TRUE",
			"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics${INSTRUMENTER_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
			"OTEL_EBPF_HOSTNAME":                "obi",
			"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
			"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
			"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
			"OTEL_EBPF_OPEN_PORT":               "8080",
			"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
			"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
			"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-go-runtime-metrics.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-otel`,
		`PROM_CONFIG_SUFFIX=-otel`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with OTel export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsPromGo117(t *testing.T) {
	compose := docker.SuiteStack(t, &docker.OBI{
		Pid:   "host",
		Ports: []string{"${OTEL_EBPF_PROMETHEUS_HOST_PORT:-8999}:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-go-runtime-metrics:/var/run/obi",
			"/sys/kernel/tracing:/sys/kernel/tracing:rw",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"GOCOVERDIR":                        "/coverage",
			"OTEL_EBPF_BPF_DEBUG":               "TRUE",
			"OTEL_EBPF_CONFIG_PATH":             "/configs/obi-config-go-runtime-metrics${INSTRUMENTER_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_DISCOVERY_POLL_INTERVAL": "500ms",
			"OTEL_EBPF_HOSTNAME":                "obi",
			"OTEL_EBPF_LOG_LEVEL":               "DEBUG",
			"OTEL_EBPF_METRICS_FEATURES":        "application_runtime",
			"OTEL_EBPF_METRICS_INTERVAL":        "10ms",
			"OTEL_EBPF_OPEN_PORT":               "8080",
			"OTEL_EBPF_PROCESSES_INTERVAL":      "100ms",
			"OTEL_EBPF_PROMETHEUS_TTL":          "250ms",
			"OTEL_EBPF_SERVICE_NAMESPACE":       "integration-test",
		},
	}, "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-go-runtime-metrics.yml")
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsGo117HostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-prom`,
		`PROM_CONFIG_SUFFIX=`,
		`RUNTIME_METRICS_TESTSERVER_DOCKERFILE=./internal/test/integration/components/go-runtime-metrics-server/Dockerfile_1.17`,
		`RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-go-runtime-metrics-1-17`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go 1.17 runtime metrics with Prometheus export", testRuntimeMetricsGo117)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
