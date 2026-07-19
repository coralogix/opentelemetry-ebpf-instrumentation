// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_GoStatMetrics(t *testing.T) {
	runSuite(t, docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			Pid:          "host",
			Ports:        []string{"8999:8999"},
			RunDir:       "run-go-stat-metrics",
			ExtraVolumes: []string{"/sys/kernel/tracing:/sys/kernel/tracing:rw"},
			DependsOn:    map[string]string{"testserver": "service_started"},
			Env: map[string]string{
				"OTEL_EBPF_CONFIG_PATH":          "/configs/obi-config-go-runtime-metrics-otel.yml",
				"OTEL_EBPF_METRICS_FEATURES":     "stats",
				"OTEL_EBPF_OPEN_PORT":            "",
				"OTEL_EBPF_PROMETHEUS_PORT":      "8999",
				"OTEL_EBPF_PROTOCOL_DEBUG_PRINT": "true",
			},
		}),
		"otelcol": docker.OtelcolNoJaeger(),
		"jaeger":  nil,
	}), "docker-compose-go-stat-metrics.yml"), []string{`PROM_CONFIG_SUFFIX=-promscrape-otel`}, true,
		st("Go Stat Metrics TCP RTT tests", testStatMetricsTCPRttGo),
		st("Go Stat Metrics TCP Failed Connection tests", testStatMetricsTCPFailedConnectionsGo),
		st("Go Stat Metrics TCP Retransmits tests", testStatMetricsTCPRetransmitsGo),
		st("Go Stat Metrics TCP IO tests", testStatMetricsTCPIoGo))
}
