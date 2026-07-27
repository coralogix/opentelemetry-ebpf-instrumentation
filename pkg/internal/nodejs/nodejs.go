// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	inspectorHost         = "127.0.0.1"
	inspectorOpenTimeout  = 5 * time.Second
	inspectorPollInterval = 200 * time.Millisecond
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	return &NodeInjector{
		cfg: cfg,
		log: slog.With("component", "nodejs.Injector"),
	}
}

func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled && (i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled())
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return
	}

	i.log.Info("loading NodeJS instrumentation", "pid", ie.FileInfo.Pid())

	if err := i.attachAgent(int(ie.FileInfo.Pid()), ie.FileInfo.ELF()); err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", ie.FileInfo.Pid(), "error", err)
		i.log.Error("trace-context propagation will not work for NodeJS services!")
	}
}

func (i *NodeInjector) attachAgent(pid int, elfFile *elf.File) error {
	return netns.WithNetNS(pid, func() error {
		return i.injectFile(pid, elfFile)
	})
}

// injectFile attempts to connect to the Node.js inspector and inject the
// agent. It first looks for an inspector that is already open (e.g. the app was
// started with --inspect), validating with /json/version, and injects into it
// without closing it afterwards. Otherwise it checks for a custom SIGUSR1
// handler and either signals the process to open its inspector - discovering
// the port that appears for this specific pid - or bails out.
func (i *NodeInjector) injectFile(pid int, elfFile *elf.File) error {
	portsBefore, err := listeningTCPPorts(pid)
	if err != nil {
		i.log.Debug("couldn't enumerate listening ports, falling back to probing the default inspector port",
			"pid", pid, "error", err)

		portsBefore = map[int]struct{}{}
	}

	if conn, port, ok := i.findOpenInspector(pid, portsBefore); ok {
		i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid, "port", port)
		return i.injectViaConn(conn, false)
	}

	if elfFile != nil {
		switch hasUserSIGUSR1Handler(pid, elfFile) {
		case signalCheckFound:
			i.log.Warn("Node.js process has a custom SIGUSR1 handler, skipping agent injection. "+
				"Node.js trace correlation will not work", "pid", pid)
			return nil
		case signalCheckFailed:
			// Symbol-based detection failed (e.g. stripped binary with dynamic libuv).
			// Fall back to scanning the application's source files for quoted SIGUSR1 references.
			if sourceHasSIGUSR1Reference(pid) {
				i.log.Warn("Node.js source files reference SIGUSR1, skipping agent injection. "+
					"Node.js trace correlation will not work", "pid", pid)
				return nil
			}
		case signalCheckNotFound:
			// No handler detected, safe to proceed.
		}
	}

	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		return fmt.Errorf("error enabling node inspector: %w", err)
	}

	conn, port, err := i.waitForOpenedInspector(pid, portsBefore, inspectorOpenTimeout, inspectorPollInterval)
	if err != nil {
		return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
	}

	i.log.Debug("opened Node.js inspector", "pid", pid, "port", port)

	return i.injectViaConn(conn, true)
}

// findOpenInspector looks for an inspector already listening for this pid,
// probing only ports it listens on that an --inspect flag could have configured.
func (i *NodeInjector) findOpenInspector(pid int, listening map[int]struct{}) (net.Conn, int, bool) {
	for _, port := range candidateInspectorPorts(pid) {
		if len(listening) > 0 {
			if _, ok := listening[port]; !ok {
				continue
			}
		}

		conn, err := connect(inspectorHost, port)
		if err != nil {
			continue
		}

		if i.isNodeInspector(conn) {
			return conn, port, true
		}

		conn.Close()
	}

	return nil, 0, false
}

// waitForOpenedInspector waits for the inspector opened by SIGUSR1 to appear as
// a new listening port of this pid, which copes with --inspect-port (including
// port 0) and confirms the inspector belongs to the pid that was signalled.
func (i *NodeInjector) waitForOpenedInspector(
	pid int,
	before map[int]struct{},
	timeout time.Duration,
	interval time.Duration,
) (net.Conn, int, error) {
	deadline := time.Now().Add(timeout)

	for {
		current, err := listeningTCPPorts(pid)
		if err != nil {
			if conn, ok := i.dialInspector(defaultInspectorPort); ok {
				return conn, defaultInspectorPort, nil
			}
		}

		for port := range current {
			if _, existed := before[port]; existed {
				continue
			}

			if conn, ok := i.dialInspector(port); ok {
				return conn, port, nil
			}
		}

		if time.Now().After(deadline) {
			return nil, 0, fmt.Errorf("timed out waiting for the inspector of pid %d", pid)
		}

		time.Sleep(interval)
	}
}

func (i *NodeInjector) dialInspector(port int) (net.Conn, bool) {
	conn, err := connect(inspectorHost, port)
	if err != nil {
		return nil, false
	}

	if i.isNodeInspector(conn) {
		return conn, true
	}

	conn.Close()

	return nil, false
}

// isNodeInspector validates that a connection is actually a Node.js inspector
// by requesting /json/version and checking for a valid JSON response.
func (i *NodeInjector) isNodeInspector(conn net.Conn) bool {
	resp, err := httpGet(conn, "/json/version")
	if err != nil {
		return false
	}

	// The Node.js inspector responds with a JSON object containing
	// "Browser" and "Protocol-Version" fields.
	return len(resp) > 0 && resp[0] == '{'
}

//go:embed fdextractor.js
var _extractorBytes []byte
