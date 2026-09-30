// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const nodejsUninjectHostPort = "8397"

type nodejsAgentState struct {
	StorePresent         bool `json:"store_present"`
	Installed            bool `json:"installed"`
	ServerEmitWrapped    bool `json:"server_emit_wrapped"`
	SocketConnectWrapped bool `json:"socket_connect_wrapped"`
	SocketWriteWrapped   bool `json:"socket_write_wrapped"`
	InspectorOpen        bool `json:"inspector_open"`
}

func nodejsAgent(t require.TestingT) nodejsAgentState {
	resp, err := http.Get("http://localhost:" + nodejsUninjectHostPort + "/agent")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var state nodejsAgentState
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&state))

	return state
}

func TestNodejsUninjectOnShutdown(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs-uninject.yml",
		path.Join(pathOutput, "test-suite-nodejs-uninject.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+nodejsUninjectHostPort+`:3030`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://localhost:" + nodejsUninjectHostPort + "/smoke")
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	}, 2*time.Minute, time.Second, "the test application never became reachable")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, nodejsAgent(ct).Installed)
	}, 2*time.Minute, time.Second, "OBI never injected the agent")

	injected := nodejsAgent(t)
	require.True(t, injected.ServerEmitWrapped, "the agent should have wrapped net.Server.prototype.emit")
	require.True(t, injected.SocketWriteWrapped, "the agent should have wrapped net.Socket.prototype.write")
	require.False(t, injected.InspectorOpen,
		"the injection closes the inspector again, so it must not be listening while injected")

	require.NoError(t, compose.StopService("obi"))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.False(ct, nodejsAgent(ct).Installed)
	}, time.Minute, time.Second, "the agent was still installed after OBI shut down")

	after := nodejsAgent(t)
	assert.False(t, after.ServerEmitWrapped, "net.Server.prototype.emit should be restored")
	assert.False(t, after.SocketConnectWrapped, "net.Socket.prototype.connect should be restored")
	assert.False(t, after.SocketWriteWrapped, "net.Socket.prototype.write should be restored")
	assert.False(t, after.InspectorOpen,
		"the debugger port SIGUSR1 reopened must be closed again, or it stays open for the life of the process")
}
