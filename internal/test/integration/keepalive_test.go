// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestExistingSocketsDetection(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.NewStack(map[string]*docker.ServiceDef{
		"obi": docker.NewOBI(docker.OBI{
			NoDefaultEnv: true,
			ConfigYAML:   obiConfigKeepalive,
			NetworkMode:  "service:keepaliveclient",
			Pid:          "host",
			RunDir:       "run-keepalive",
			DependsOn:    map[string]string{"keepaliveclient": "service_healthy"},
			Env:          map[string]string{"GOCOVERDIR": "/coverage"},
		}),
		"otelcol":    nil,
		"prometheus": nil,
		"jaeger":     nil,
		"weaver":     nil,
	}), "docker-compose-keepalive.yml")
	require.NoError(t, compose.Up())

	waitForTestComponentsNoMetrics(t, "http://localhost:8080/smoke")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:9091/status")
		require.NoError(ct, err)
		resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, time.Second)

	require.NoError(t, compose.Close())
}
