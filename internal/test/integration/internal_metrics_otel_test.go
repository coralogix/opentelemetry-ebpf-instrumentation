// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"net"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const internalMetricsHostPort = "8393"

// TestInternalOTelMetrics brings OBI up with `internal_metrics.exporter: otel`
// so its own self-telemetry (obi.bpf.*, obi.queue.*, obi.avoided.services, …)
// is exported over OTLP and flows through the collector's weaver tap. Until now
// the internal metrics were only ever validated via the Prometheus self-scrape
// (TestSuite_PrometheusScrape / testPrometheusBPFMetrics); the OTLP variant had
// no coverage and never reached weaver.
//
// Runs in OBSERVE mode: the OTLP internal-metric names/attributes are not yet
// declared in schemas/obi, so weaver logs which advisories WOULD fail enforce
// without failing the suite. Flip to runWeaverValidation once obi_internal.yaml
// declares the obi.bpf.* metric family.
func TestInternalOTelMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-internal-metrics.yml", path.Join(pathOutput, "test-suite-internal-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+internalMetricsHostPort+`:8080`)
	require.NoError(t, compose.Up())

	// Exercise the instrumented process so OBI's eBPF probes fire and its
	// internal maps populate, making the obi.bpf.* self-metrics non-trivial
	// before weaver reads the report. The testserver is a line-based TCP server
	// (see components/go-runtime-metrics-server); "FORCE_GC" is answered with a
	// line we can read back. Traffic is sustained for a while so OBI has time to
	// discover + instrument the process and flush its (internal) metrics to the
	// collector's weaver tap before runWeaverValidationObserve stops weaver and
	// reads the report — otherwise weaver sees zero samples.
	t.Run("generate probe activity", func(t *testing.T) {
		require.Eventually(t, func() bool {
			return pokeInternalMetricsServer(t) == nil
		}, testTimeout, 500*time.Millisecond, "testserver never became reachable")
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			assert.NoError(t, pokeInternalMetricsServer(t))
			time.Sleep(200 * time.Millisecond)
		}
	})

	runWeaverValidationObserve(t)
	require.NoError(t, compose.Close())
}

func pokeInternalMetricsServer(t require.TestingT) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", internalMetricsHostPort), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("FORCE_GC\n")); err != nil {
		return err
	}
	_, err = bufio.NewReader(conn).ReadString('\n')
	return err
}
