// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_GoStatMetrics(t *testing.T) {
	runSuite(t, docker.SuiteStack(t, docker.StdOBI(docker.OBI{
		Pid:   "host",
		Ports: []string{"8999:8999"},
		Volumes: []string{
			"./configs/:/configs",
			"./system/sys/kernel/security:/sys/kernel/security",
			"../../../testoutput:/coverage",
			"../../../testoutput/run-go-stat-metrics:/var/run/obi",
			"/sys/kernel/tracing:/sys/kernel/tracing:rw",
		},
		DependsOn: map[string]string{"testserver": "service_started"},
		Env: map[string]string{
			"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT": "5s",
			"OTEL_EBPF_CONFIG_PATH":              "/configs/obi-config${OTEL_EBPF_CONFIG_SUFFIX}.yml",
			"OTEL_EBPF_METRICS_FEATURES":         "stats",
			"OTEL_EBPF_PROCESSES_INTERVAL":       "100ms",
			"OTEL_EBPF_PROMETHEUS_PORT":          "8999",
			"OTEL_EBPF_PROTOCOL_DEBUG_PRINT":     "true",
			"OTEL_EBPF_TRACE_PRINTER":            "json",
		},
	}), "compose-base.yml", "compose-frag-otelcol.yml", "compose-frag-prometheus.yml", "compose-frag-weaver.yml", "compose-suite-go-stat-metrics.yml"), []string{`TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-runtime-metrics-otel`, `PROM_CONFIG_SUFFIX=-promscrape-otel`}, true,
		st("Go Stat Metrics TCP RTT tests", testStatMetricsTCPRttGo),
		st("Go Stat Metrics TCP Failed Connection tests", testStatMetricsTCPFailedConnectionsGo),
		st("Go Stat Metrics TCP Retransmits tests", testStatMetricsTCPRetransmitsGo),
		st("Go Stat Metrics TCP IO tests", testStatMetricsTCPIoGo))
}
