// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestJVMRuntimeEventsLive(t *testing.T) {
	compose := docker.SuiteStackServices(t, docker.Stack{Services: map[string]*docker.ServiceDef{
		"obi": &docker.OBI{
			Image:           "hatest-jvm-runtime-event-test",
			BuildContext:    "../../..",
			BuildDockerfile: "./internal/test/integration/components/jvm-runtime-event-test/Dockerfile",
			WorkingDir:      "/src",
			Command:         []string{"go", "test", "-tags=jvm_live", "./pkg/internal/ebpf/generictracer", "-run", "^TestJVMRuntimeEventsLiveFromHotSpotProbes$", "-count=1", "-v", "-timeout=2m"},
			Volumes: []string{
				"../../..:/src",
				"./system/sys/kernel/security:/sys/kernel/security",
				"/sys/kernel/tracing:/sys/kernel/tracing:rw",
			},
			Env: map[string]string{
				"GOCACHE":    "/tmp/go-build-cache",
				"GOMODCACHE": "/tmp/go-mod-cache",
			},
		},
	}}, "compose-base.yml")
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	require.NoError(t, compose.Run("obi"))
}
