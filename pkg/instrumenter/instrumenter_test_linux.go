//go:build linux

package instrumenter

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/obi"
)

// TestRunDontPanic tests the fix for https://github.com/grafana/beyla/issues/926
func TestRunDontPanic(t *testing.T) {
	type testCase struct {
		description    string
		configProvider func() obi.Config
	}
	testCases := []testCase{{
		description: "otel endpoint but feature excluded",
		configProvider: func() obi.Config {
			cfg := obi.DefaultConfig
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			return cfg
		},
	}, {
		description: "prom endpoint but feature excluded",
		configProvider: func() obi.Config {
			cfg := obi.DefaultConfig
			cfg.Prometheus.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "otel endpoint, otel feature excluded, but prom enabled",
		configProvider: func() obi.Config {
			cfg := obi.DefaultConfig
			cfg.Metrics.Features = []string{"application"}
			cfg.NetworkFlows.Enable = true
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Prometheus.Port = 9090
			return cfg
		},
	}, {
		description: "all endpoints, all features excluded",
		configProvider: func() obi.Config {
			cfg := obi.DefaultConfig
			cfg.NetworkFlows.Enable = true
			cfg.Prometheus.Port = 9090
			cfg.Prometheus.Features = []string{"application"}
			cfg.Metrics.CommonEndpoint = "http://localhost"
			cfg.Metrics.Features = []string{"application"}
			return cfg
		},
	}}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			cfg := tc.configProvider()
			require.NoError(t, cfg.Validate())

			require.NotPanics(t, func() {
				_ = Run(t.Context(), &cfg)
			})
		})
	}
}

func TestNetworkEnabled(t *testing.T) {
	t.Setenv("BEYLA_NETWORK_METRICS", "true")
	cfg, err := obi.LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(obi.FeatureNetO11y))
}
