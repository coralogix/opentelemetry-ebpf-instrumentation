// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opamp // import "go.opentelemetry.io/obi/cmd/obi/internal/opamp"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"

	"go.opentelemetry.io/obi/cmd/obi/internal/configload"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	configName  = "obi"
	serviceName = "opentelemetry-ebpf-instrumentation"
	stopTimeout = 5 * time.Second
)

type Applier func(context.Context, *obi.Config) error

type Settings struct {
	Endpoint    string
	Headers     map[string]string
	InstanceUID string
	StateDir    string
}

func SettingsFromConfig(data []byte) (*Settings, error) {
	_, ext, err := schema.ParseStandaloneYAML(obicfg.ReplaceEnv(data))
	if err != nil {
		return nil, err
	}
	if ext == nil || ext.Daemon == nil || ext.Daemon.OpAMP == nil {
		return nil, nil
	}
	src := ext.Daemon.OpAMP
	if src.Endpoint == "" {
		return nil, errors.New("extensions.obi.daemon.opamp.endpoint is required")
	}
	return &Settings{
		Endpoint:    src.Endpoint,
		Headers:     src.Headers,
		InstanceUID: src.InstanceUID,
		StateDir:    src.StateDir,
	}, nil
}

type Agent struct {
	settings Settings
	base     []byte
	state    stateDir
	uid      types.InstanceUid
	pending  chan *protobufs.AgentRemoteConfig

	savedOverlay []byte
	savedHash    []byte
	appliedHash  []byte

	mu        sync.Mutex
	effective []byte
}

func New(settings *Settings, base []byte) (*Agent, error) {
	a := &Agent{
		settings:  *settings,
		base:      base,
		state:     stateDir(settings.StateDir),
		pending:   make(chan *protobufs.AgentRemoteConfig, 1),
		effective: base,
	}
	uid, err := a.instanceUID()
	if err != nil {
		return nil, err
	}
	a.uid = uid
	if a.savedOverlay, err = a.state.read(remoteConfigFile); err != nil {
		return nil, fmt.Errorf("reading saved remote configuration: %w", err)
	}
	if a.savedHash, err = a.state.read(remoteHashFile); err != nil {
		return nil, fmt.Errorf("reading saved remote configuration hash: %w", err)
	}
	if len(a.savedHash) == 0 {
		a.savedOverlay = nil
	}
	return a, nil
}

func (a *Agent) StartupConfig() (*obi.Config, bool) {
	if a.savedOverlay == nil {
		return nil, false
	}
	merged, err := mergeOverlay(a.base, a.savedOverlay)
	var cfg *obi.Config
	if err == nil {
		cfg, err = configload.LoadV2(merged)
	}
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		a.logger().Warn("discarding the saved remote configuration; starting with the local configuration", "error", err)
		if err := a.state.remove(remoteConfigFile, remoteHashFile); err != nil {
			a.logger().Warn("can't remove the saved remote configuration", "error", err)
		}
		a.savedOverlay, a.savedHash = nil, nil
		return nil, false
	}
	a.effective = merged
	a.appliedHash = a.savedHash
	a.logger().Info("started with the saved remote configuration")
	return cfg, true
}

func (a *Agent) Run(ctx context.Context, apply Applier) error {
	c := newClient(a.settings.Endpoint, a.logger())
	if err := c.SetAgentDescription(a.description()); err != nil {
		return err
	}
	capabilities := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus |
		protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth |
		protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat
	if err := c.SetCapabilities(&capabilities); err != nil {
		return err
	}
	if err := c.SetHealth(&protobufs.ComponentHealth{
		Healthy:           true,
		StartTimeUnixNano: uint64(time.Now().UnixNano()),
		Status:            "running",
	}); err != nil {
		return err
	}

	header := http.Header{}
	for name, value := range a.settings.Headers {
		header.Set(name, value)
	}
	if err := c.Start(ctx, types.StartSettings{
		OpAMPServerURL:     a.settings.Endpoint,
		Header:             header,
		InstanceUid:        a.uid,
		RemoteConfigStatus: a.startStatus(),
		Callbacks: types.Callbacks{
			OnConnect: func(context.Context) {
				a.logger().Info("connected to the OpAMP server", "endpoint", a.settings.Endpoint)
			},
			OnConnectFailed: func(_ context.Context, err error) {
				a.logger().Warn("can't connect to the OpAMP server", "endpoint", a.settings.Endpoint, "error", err)
			},
			OnError: func(_ context.Context, err *protobufs.ServerErrorResponse) {
				a.logger().Warn("OpAMP server returned an error", "error", err.GetErrorMessage())
			},
			OnMessage:          a.onMessage,
			GetEffectiveConfig: a.effectiveConfig,
		},
	}); err != nil {
		return fmt.Errorf("starting OpAMP client: %w", err)
	}

	a.processRemoteConfigs(ctx, c, apply)

	stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	return c.Stop(stopCtx)
}

func (a *Agent) logger() *slog.Logger {
	return slog.With("component", "opamp.Agent")
}

func newClient(endpoint string, log *slog.Logger) client.OpAMPClient {
	logger := clientLogger{log: log}
	if strings.HasPrefix(endpoint, "ws://") || strings.HasPrefix(endpoint, "wss://") {
		return client.NewWebSocket(logger)
	}
	return client.NewHTTP(logger)
}

func (a *Agent) onMessage(_ context.Context, msg *types.MessageData) {
	if id := msg.AgentIdentification; id != nil && a.settings.InstanceUID == "" {
		if uid, err := uuid.FromBytes(id.NewInstanceUid); err == nil {
			if err := a.state.write(instanceUIDFile, []byte(uid.String())); err != nil {
				a.logger().Warn("can't save the instance UID assigned by the OpAMP server", "error", err)
			}
		}
	}
	if msg.RemoteConfig == nil {
		return
	}
	select {
	case <-a.pending:
	default:
	}
	a.pending <- msg.RemoteConfig
}

func (a *Agent) processRemoteConfigs(ctx context.Context, c client.OpAMPClient, apply Applier) {
	for {
		select {
		case <-ctx.Done():
			return
		case remote := <-a.pending:
			a.applyRemoteConfig(ctx, c, apply, remote)
		}
	}
}

func (a *Agent) applyRemoteConfig(ctx context.Context, c client.OpAMPClient, apply Applier, remote *protobufs.AgentRemoteConfig) {
	hash := remote.GetConfigHash()
	if bytes.Equal(hash, a.appliedHash) {
		return
	}
	a.appliedHash = hash
	a.setStatus(c, hash, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLYING, "")

	overlay, merged, err := a.prepare(remote)
	if err == nil {
		var cfg *obi.Config
		if cfg, err = configload.LoadV2(merged); err == nil {
			if err = cfg.ValidateStaticForApplicationRefresh(); err == nil {
				err = apply(ctx, cfg)
			}
		}
	}

	switch {
	case err == nil:
		a.save(overlay, hash)
		a.mu.Lock()
		a.effective = merged
		a.mu.Unlock()
		if err := c.UpdateEffectiveConfig(ctx); err != nil {
			a.logger().Warn("can't report the effective configuration", "error", err)
		}
		a.setStatus(c, hash, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, "")
		a.logger().Info("remote configuration applied")
	case errors.Is(err, discover.ErrRestartRequired):
		message := err.Error()
		if a.save(overlay, hash) {
			message += "; saved for the next start"
		}
		a.setStatus(c, hash, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, message)
		a.logger().Warn("remote configuration requires a restart", "error", err)
	default:
		a.setStatus(c, hash, protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, err.Error())
		a.logger().Error("can't apply the remote configuration; continuing with the running configuration", "error", err)
	}
}

func (a *Agent) prepare(remote *protobufs.AgentRemoteConfig) ([]byte, []byte, error) {
	overlay, err := remoteOverlay(remote.GetConfig())
	if err != nil {
		return nil, nil, err
	}
	merged, err := mergeOverlay(a.base, overlay)
	if err != nil {
		return nil, nil, err
	}
	return overlay, merged, nil
}

func remoteOverlay(configs *protobufs.AgentConfigMap) ([]byte, error) {
	files := configs.GetConfigMap()
	if file, ok := files[configName]; ok {
		return file.GetBody(), nil
	}
	switch len(files) {
	case 0:
		return nil, nil
	case 1:
		for _, file := range files {
			return file.GetBody(), nil
		}
	}
	return nil, fmt.Errorf("remote configuration has %d entries and none is named %q", len(files), configName)
}

func (a *Agent) save(overlay, hash []byte) bool {
	if !a.state.enabled() {
		return false
	}
	if err := a.state.write(remoteConfigFile, overlay); err != nil {
		a.logger().Warn("can't save the remote configuration", "error", err)
		return false
	}
	if err := a.state.write(remoteHashFile, hash); err != nil {
		a.logger().Warn("can't save the remote configuration hash", "error", err)
		return false
	}
	return true
}

func (a *Agent) setStatus(c client.OpAMPClient, hash []byte, status protobufs.RemoteConfigStatuses, message string) {
	if err := c.SetRemoteConfigStatus(&protobufs.RemoteConfigStatus{
		LastRemoteConfigHash: hash,
		Status:               status,
		ErrorMessage:         message,
	}); err != nil {
		a.logger().Warn("can't report the remote configuration status", "error", err)
	}
}

func (a *Agent) startStatus() *protobufs.RemoteConfigStatus {
	if a.appliedHash == nil {
		return nil
	}
	return &protobufs.RemoteConfigStatus{
		LastRemoteConfigHash: a.appliedHash,
		Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
	}
}

func (a *Agent) effectiveConfig(context.Context) (*protobufs.EffectiveConfig, error) {
	a.mu.Lock()
	data := a.effective
	a.mu.Unlock()
	body, err := redactedConfig(data)
	if err != nil {
		return nil, err
	}
	return &protobufs.EffectiveConfig{
		ConfigMap: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigObject{
				configName: {Body: body, ContentType: "text/yaml"},
			},
		},
	}, nil
}

func (a *Agent) instanceUID() (types.InstanceUid, error) {
	if a.settings.InstanceUID != "" {
		uid, err := uuid.Parse(a.settings.InstanceUID)
		if err != nil {
			return types.InstanceUid{}, fmt.Errorf("extensions.obi.daemon.opamp.instance_uid: %w", err)
		}
		return types.InstanceUid(uid), nil
	}
	stored, err := a.state.read(instanceUIDFile)
	if err != nil {
		return types.InstanceUid{}, fmt.Errorf("reading the saved instance UID: %w", err)
	}
	if len(stored) > 0 {
		if uid, err := uuid.ParseBytes(bytes.TrimSpace(stored)); err == nil {
			return types.InstanceUid(uid), nil
		}
		a.logger().Warn("ignoring an invalid saved instance UID")
	}
	uid, err := uuid.NewV7()
	if err != nil {
		return types.InstanceUid{}, err
	}
	if err := a.state.write(instanceUIDFile, []byte(uid.String())); err != nil {
		a.logger().Warn("can't save the instance UID; a new one is generated on every start", "error", err)
	}
	return types.InstanceUid(uid), nil
}

func (a *Agent) description() *protobufs.AgentDescription {
	host, _ := os.Hostname()
	return &protobufs.AgentDescription{
		IdentifyingAttributes: []*protobufs.KeyValue{
			stringAttr("service.name", serviceName),
			stringAttr("service.version", buildinfo.Version),
			stringAttr("service.instance.id", uuid.UUID(a.uid).String()),
		},
		NonIdentifyingAttributes: []*protobufs.KeyValue{
			stringAttr("host.name", host),
			stringAttr("os.type", runtime.GOOS),
			stringAttr("host.arch", runtime.GOARCH),
		},
	}
}

func stringAttr(key, value string) *protobufs.KeyValue {
	return &protobufs.KeyValue{
		Key:   key,
		Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: value}},
	}
}

type clientLogger struct {
	log *slog.Logger
}

func (l clientLogger) Debugf(ctx context.Context, format string, v ...any) {
	l.log.DebugContext(ctx, fmt.Sprintf(format, v...))
}

func (l clientLogger) Errorf(ctx context.Context, format string, v ...any) {
	l.log.ErrorContext(ctx, fmt.Sprintf(format, v...))
}
