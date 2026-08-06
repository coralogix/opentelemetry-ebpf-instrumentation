// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const internalMetricsMetricErrorsHostPort = "8399"

// TestInternalOTelMetricsMetricErrors holds the collector down for a fixed
// window (a gate container) while OBI, which does not wait for it, keeps trying
// to export metrics and fails. instrumentedMetricsExporter.Export observes each
// failure and records obi.otel.metric.export.errors. Once the collector comes
// up, the now-non-zero counter is exported over the same otel internal-metrics
// path to Prometheus (asserted present here) and to weaver for
// semantic-convention live-check. This makes the metric-export-error metric
// deterministically covered rather than relying on an incidental startup race.
func TestInternalOTelMetricsMetricErrors(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-internal-metrics-metric-errors.yml", path.Join(pathOutput, "test-suite-internal-metrics-metric-errors.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+internalMetricsMetricErrorsHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// Cleanups run LIFO: register compose.Close() first so it runs LAST, after
	// runWeaverValidation has /stopped the still-running weaver container.
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	t.Run("obi.otel.metric.export.errors exported over OTLP and weaver-validated", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}

		require.Eventually(t, func() bool {
			return pokeInternalMetricsMetricErrorsServer() == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")

		// Drive continuous HTTP traffic so OBI keeps producing application
		// metrics it then tries (and, while the collector is gated down, fails)
		// to export, incrementing obi.otel.metric.export.errors.
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = pokeInternalMetricsMetricErrorsServer()
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
		defer close(stop)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			results, err := pq.Query("obi_otel_metric_export_errors_total")
			if !assert.NoError(ct, err, "querying obi_otel_metric_export_errors_total") {
				return
			}
			assert.NotEmpty(ct, results, "obi_otel_metric_export_errors_total should be present")
		}, testTimeout, 500*time.Millisecond)
	})
}

func pokeInternalMetricsMetricErrorsServer() error {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:" + internalMetricsMetricErrorsHostPort + "/ping")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
