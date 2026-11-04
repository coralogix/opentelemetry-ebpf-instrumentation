// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opamp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	servertypes "github.com/open-telemetry/opamp-go/server/types"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/obi"
)

const waitTimeout = 10 * time.Second

func localConfig(endpoint, stateDir string) []byte {
	return fmt.Appendf(nil, `file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    capture:
      policy:
        default_action: exclude
      rules:
        - action: include
          match:
            process:
              open_ports: 8080
    daemon:
      logging:
        debug_trace_output: text
      opamp:
        endpoint: %s
        state_dir: %s
        headers:
          Authorization: Bearer agent-token
`, endpoint, stateDir)
}

func portOverlay(port int) []byte {
	return fmt.Appendf(nil, `extensions:
  obi:
    capture:
      rules:
        - action: include
          match:
            process:
              open_ports: %d
`, port)
}

type fakeServer struct {
	url       string
	headers   chan http.Header
	statuses  chan *protobufs.RemoteConfigStatus
	effective chan string
	agents    chan *protobufs.AgentToServer

	mu   sync.Mutex
	conn servertypes.Connection
	uid  []byte
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{
		headers:   make(chan http.Header, 10),
		statuses:  make(chan *protobufs.RemoteConfigStatus, 100),
		effective: make(chan string, 100),
		agents:    make(chan *protobufs.AgentToServer, 100),
	}
	handler, connContext, err := server.New(nil).Attach(server.Settings{
		Callbacks: servertypes.Callbacks{
			OnConnecting: func(r *http.Request) servertypes.ConnectionResponse {
				f.headers <- r.Header.Clone()
				return servertypes.ConnectionResponse{
					Accept: true,
					ConnectionCallbacks: servertypes.ConnectionCallbacks{
						OnMessage: f.onMessage,
					},
				}
			},
		},
	})
	require.NoError(t, err)
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	httpServer.Config.ConnContext = connContext
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	f.url = "ws" + strings.TrimPrefix(httpServer.URL, "http")
	return f
}

func (f *fakeServer) onMessage(_ context.Context, conn servertypes.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
	f.mu.Lock()
	f.conn, f.uid = conn, msg.GetInstanceUid()
	f.mu.Unlock()
	f.agents <- msg
	if status := msg.GetRemoteConfigStatus(); status != nil {
		f.statuses <- status
	}
	if file := msg.GetEffectiveConfig().GetConfigMap().GetConfigMap()[configName]; file != nil {
		f.effective <- string(file.GetBody())
	}
	return &protobufs.ServerToAgent{InstanceUid: msg.GetInstanceUid()}
}

func (f *fakeServer) push(t *testing.T, hash string, overlay []byte) {
	t.Helper()
	require.Eventually(t, func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.conn != nil
	}, waitTimeout, 10*time.Millisecond)
	f.mu.Lock()
	conn, uid := f.conn, f.uid
	f.mu.Unlock()
	require.NoError(t, conn.Send(t.Context(), &protobufs.ServerToAgent{
		InstanceUid: uid,
		RemoteConfig: &protobufs.AgentRemoteConfig{
			ConfigHash: []byte(hash),
			Config: &protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigObject{
				configName: {Body: overlay, ContentType: "text/yaml"},
			}},
		},
	}))
}

func (f *fakeServer) waitStatus(t *testing.T, hash string, status protobufs.RemoteConfigStatuses) *protobufs.RemoteConfigStatus {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case got := <-f.statuses:
			if string(got.GetLastRemoteConfigHash()) == hash && got.GetStatus() == status {
				return got
			}
		case <-deadline:
			t.Fatalf("timed out waiting for status %s of %q", status, hash)
		}
	}
}

func (f *fakeServer) waitEffective(t *testing.T, contains string) string {
	t.Helper()
	deadline := time.After(waitTimeout)
	for {
		select {
		case got := <-f.effective:
			if strings.Contains(got, contains) {
				return got
			}
		case <-deadline:
			t.Fatalf("timed out waiting for an effective configuration containing %q", contains)
		}
	}
}

type recordingApplier struct {
	mu      sync.Mutex
	configs []*obi.Config
	err     error
}

func (r *recordingApplier) apply(_ context.Context, cfg *obi.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configs = append(r.configs, cfg)
	return r.err
}

func (r *recordingApplier) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *recordingApplier) applied() []*obi.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*obi.Config(nil), r.configs...)
}

func startAgent(t *testing.T, base []byte, apply Applier) *Agent {
	t.Helper()
	settings, err := SettingsFromConfig(base)
	require.NoError(t, err)
	require.NotNil(t, settings)
	agent, err := New(settings, base)
	require.NoError(t, err)
	startedAgent(t, agent, apply)
	return agent
}

func startedAgent(t *testing.T, agent *Agent, apply Applier) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, apply) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitTimeout):
			t.Error("agent did not stop")
		}
	})
}

func TestSettingsFromConfig(t *testing.T) {
	settings, err := SettingsFromConfig(localConfig("ws://server/v1/opamp", "/var/lib/obi"))
	require.NoError(t, err)
	require.Equal(t, &Settings{
		Endpoint: "ws://server/v1/opamp",
		Headers:  map[string]string{"Authorization": "Bearer agent-token"},
		StateDir: "/var/lib/obi",
	}, settings)

	settings, err = SettingsFromConfig([]byte("file_format: \"1.0\"\nextensions:\n  obi:\n    version: \"2.0\"\n"))
	require.NoError(t, err)
	require.Nil(t, settings)

	_, err = SettingsFromConfig([]byte("file_format: \"1.0\"\nextensions:\n  obi:\n    version: \"2.0\"\n    daemon:\n      opamp:\n        state_dir: /tmp\n"))
	require.ErrorContains(t, err, "endpoint is required")
}

func TestAgentAppliesRemoteDiscovery(t *testing.T) {
	srv := newFakeServer(t)
	stateDir := t.TempDir()
	applier := &recordingApplier{}
	startAgent(t, localConfig(srv.url, stateDir), applier.apply)

	require.Equal(t, "Bearer agent-token", (<-srv.headers).Get("Authorization"))
	first := <-srv.agents
	require.NotEmpty(t, first.GetInstanceUid())
	require.NotZero(t, first.GetCapabilities()&uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig))

	srv.push(t, "v1", portOverlay(9090))
	srv.waitStatus(t, "v1", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED)

	applied := applier.applied()
	require.Len(t, applied, 1)
	criteria := discover.FindingCriteria(applied[0])
	require.True(t, criteria[0].GetOpenPorts().Matches(9090))
	require.False(t, criteria[0].GetOpenPorts().Matches(8080))

	effective := srv.waitEffective(t, "9090")
	require.NotContains(t, effective, "agent-token")
	require.Contains(t, effective, redacted)

	saved, err := os.ReadFile(filepath.Join(stateDir, remoteConfigFile))
	require.NoError(t, err)
	require.Equal(t, portOverlay(9090), saved)

	srv.push(t, "v1", portOverlay(9090))
	srv.push(t, "v2", portOverlay(7070))
	srv.waitStatus(t, "v2", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED)
	require.Len(t, applier.applied(), 2)
}

func TestAgentRejectsInvalidRemoteConfig(t *testing.T) {
	srv := newFakeServer(t)
	stateDir := t.TempDir()
	applier := &recordingApplier{}
	startAgent(t, localConfig(srv.url, stateDir), applier.apply)

	srv.push(t, "takeover", []byte("extensions:\n  obi:\n    daemon:\n      opamp:\n        endpoint: ws://elsewhere\n"))
	status := srv.waitStatus(t, "takeover", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED)
	require.Contains(t, status.GetErrorMessage(), "extensions.obi.daemon.opamp")

	srv.push(t, "bad-rule", []byte("extensions:\n  obi:\n    capture:\n      rules: 42\n"))
	srv.waitStatus(t, "bad-rule", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED)
	require.Empty(t, applier.applied())

	applier.fail(errors.New("matcher stopped"))
	srv.push(t, "unprocessed", portOverlay(9090))
	status = srv.waitStatus(t, "unprocessed", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED)
	require.Equal(t, "matcher stopped", status.GetErrorMessage())

	_, err := os.Stat(filepath.Join(stateDir, remoteConfigFile))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestAgentSavesRestartRequiredConfigForNextStart(t *testing.T) {
	srv := newFakeServer(t)
	stateDir := t.TempDir()
	base := localConfig(srv.url, stateDir)
	applier := &recordingApplier{err: discover.RestartRequiredf("service settings would change for PID 10; restart OBI to apply this configuration")}
	startAgent(t, base, applier.apply)

	srv.push(t, "needs-restart", portOverlay(9090))
	status := srv.waitStatus(t, "needs-restart", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED)
	require.Contains(t, status.GetErrorMessage(), "restart OBI")
	require.Contains(t, status.GetErrorMessage(), "saved for the next start")

	settings, err := SettingsFromConfig(base)
	require.NoError(t, err)
	restarted, err := New(settings, base)
	require.NoError(t, err)
	cfg, ok := restarted.StartupConfig()
	require.True(t, ok)
	require.True(t, discover.FindingCriteria(cfg)[0].GetOpenPorts().Matches(9090))

	nextServer := newFakeServer(t)
	restarted.settings.Endpoint = nextServer.url
	startedAgent(t, restarted, (&recordingApplier{}).apply)
	nextServer.waitStatus(t, "needs-restart", protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED)
	nextServer.waitEffective(t, "9090")
}

func TestAgentKeepsInstanceUIDAcrossStarts(t *testing.T) {
	stateDir := t.TempDir()
	base := localConfig("ws://127.0.0.1:1/v1/opamp", stateDir)
	settings, err := SettingsFromConfig(base)
	require.NoError(t, err)

	first, err := New(settings, base)
	require.NoError(t, err)
	second, err := New(settings, base)
	require.NoError(t, err)
	require.Equal(t, first.uid, second.uid)

	settings.InstanceUID = "0193a7a0-7c3b-7d4e-8f00-000000000001"
	explicit, err := New(settings, base)
	require.NoError(t, err)
	require.NotEqual(t, first.uid, explicit.uid)
}

func TestStartupConfigDiscardsInvalidSavedOverlay(t *testing.T) {
	stateDir := t.TempDir()
	base := localConfig("ws://127.0.0.1:1/v1/opamp", stateDir)
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, remoteConfigFile), []byte("extensions:\n  obi:\n    capture:\n      rules: 42\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, remoteHashFile), []byte("broken"), 0o600))

	settings, err := SettingsFromConfig(base)
	require.NoError(t, err)
	agent, err := New(settings, base)
	require.NoError(t, err)
	_, ok := agent.StartupConfig()
	require.False(t, ok)
	require.Nil(t, agent.startStatus())
	_, err = os.Stat(filepath.Join(stateDir, remoteConfigFile))
	require.ErrorIs(t, err, os.ErrNotExist)
}
