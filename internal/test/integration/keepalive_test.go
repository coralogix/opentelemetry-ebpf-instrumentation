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
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			ConfigYAML:  obiConfigKeepalive,
			NetworkMode: "service:keepaliveclient",
			Pid:         "host",
			RunDir:      "run-keepalive",
			DependsOn:   map[string]string{"keepaliveclient": "service_healthy"},
			Env: map[string]string{
				"GOCOVERDIR": "/coverage",
			},
		},
		"keepaliveclient": &docker.ServiceDef{
			Image:           "hatest-keepaliveclient",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/keepaliveclient/Dockerfile",
			Ports:           []string{"9091:9091"},
			Healthcheck:     &docker.Healthcheck{Test: []string{"CMD", "test", "-f", "/tmp/connected"}, Interval: "1s", Retries: 15},
			DependsOn:       map[string]string{"tpinjector-server": "service_started"},
		},
		"tpinjector-server": &docker.ServiceDef{
			Image:           "hatest-tpinjector-server",
			BuildContext:    "../../..",
			BuildDockerfile: "internal/test/integration/components/tpinjector-server/Dockerfile",
			Ports:           []string{"8080:8080"},
		},
	}}, "compose-base.yml")
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
