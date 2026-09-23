// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"context"
	"debug/elf"
	_ "embed"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config

	// Bound once, so a shutdown pass already in flight cannot observe it
	// change. Tests swap the package variable to stand in for a real process.
	openHandle func(app.PID, uint64) (*procs.ProcessHandle, error)

	mu       sync.Mutex
	injected map[app.PID]uint64
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	log := slog.With("component", "nodejs.Injector")

	if !cfg.NodeJS.Enabled && cfg.AppRuntimeMetricsEnabled() {
		log.Warn("application_runtime is enabled but the Node.js injector is disabled " +
			"(nodejs.enabled=false): Node.js runtime metrics will not be collected")
	}

	return &NodeInjector{
		cfg:        cfg,
		log:        log,
		openHandle: openProcessHandle,
		injected:   map[app.PID]uint64{},
	}
}

// Enabled reports whether the agent should be injected: the injected script
// is both the trace-context propagation vehicle and the only source of the
// nodejs.eventloop.* runtime metrics, so either consumer turns it on —
// unless nodejs.enabled, the global opt-out, is set to false.
func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled &&
		(i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() || i.cfg.AppRuntimeMetricsEnabled())
}

// injectionTrigger names what turned the injection on, so the logs explain a
// metrics-only injection.
func (i *NodeInjector) injectionTrigger() string {
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		return "traces"
	}
	return "runtime metrics"
}

// Accepts reports whether this instrumentable is a Node.js process the
// injector is configured to handle. Callers that defer the injection check it
// before taking a queue slot.
func (i *NodeInjector) Accepts(ie *ebpf.Instrumentable) bool {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return false
	}

	if ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return false
	}

	return true
}

// Inject injects into an accepted target.
//
// The executable and the signal go through the target's pinned process handle,
// so a PID the kernel recycled between discovery and here cannot be signaled
// in the original's place. The rest still works from the numeric PID: the gates
// read /proc, and the inspector conversation enters a network namespace, so a
// replacement can be the process examined and — where an inspector is already
// listening, which needs no signal — the one injected.
func (i *NodeInjector) Inject(ctx context.Context, target InjectionTarget) {
	pid := target.Pid
	i.log.Debug("loading NodeJS instrumentation", "pid", pid, "trigger", i.injectionTrigger())

	if err := target.Process.Alive(); err != nil {
		i.log.Debug("NodeJS process is gone, skipping injection", "pid", pid, "error", err)
		return
	}

	exe, err := target.Process.Open("exe", os.O_RDONLY)
	if err != nil {
		i.log.Debug("couldn't open the NodeJS executable, skipping injection", "pid", pid, "error", err)
		return
	}
	defer exe.Close()

	elfFile, err := elf.NewFile(exe)
	if err != nil {
		i.log.Debug("couldn't read the NodeJS executable, skipping injection", "pid", pid, "error", err)
		return
	}
	defer elfFile.Close()

	injected, err := i.attachAgent(ctx, target, elfFile)

	// Recorded before the error is reported, and on the strength of the script
	// having been sent rather than of the injection having succeeded: a failure
	// while reading the inspector's reply leaves a script that may already have
	// been evaluated, and one that is resident but unrecorded is never removed.
	if injected {
		i.mu.Lock()
		i.injected[pid] = target.StartTime
		i.mu.Unlock()
	}

	if err != nil {
		i.log.Error("couldn't attach NodeJS injector", "pid", pid, "error", err)
		i.log.Error("trace-context propagation and nodejs runtime metrics will not work for NodeJS services!")
	}
}

// Forget drops a process from the uninjection set, so a PID discovery has
// already seen exit is never reopened at shutdown.
func (i *NodeInjector) Forget(pid app.PID) {
	i.mu.Lock()
	delete(i.injected, pid)
	i.mu.Unlock()
}

// attachAgent injects the agent through the Node.js inspector, opening it with
// SIGUSR1 when it is not already listening.
//
// Only the inspector conversation runs inside the target's network namespace.
// Deciding whether the signal is safe to send reads /proc and the application's
// files, needs no namespace of its own, and can wait on the runtime for as long
// as dispositionWait.
func (i *NodeInjector) attachAgent(ctx context.Context, target InjectionTarget, elfFile *elf.File) (bool, error) {
	pid := int(target.Pid)
	code := i.agentCode()

	injected, err := i.injectViaOpenInspector(pid, code, time.Time{})
	if injected || err != nil {
		return injected, err
	}

	reason := sigusr1Refusal(ctx, pid, elfFile)

	// Shutdown is not a refusal: the gates were abandoned rather than answered,
	// so nothing was concluded about this process and nothing is reported.
	if err := ctx.Err(); err != nil {
		return false, nil
	}

	if reason != "" {
		i.log.Warn("not sending SIGUSR1 to open the Node.js inspector, skipping agent injection. "+
			"Node.js trace correlation will not work", "pid", pid, "reason", reason)
		return false, nil
	}

	if err := sendSIGUSR1(target.Process); err != nil {
		return false, fmt.Errorf("error enabling node inspector: %w", err)
	}

	sent := false

	err = netns.WithNetNS(pid, func() error {
		conn, err := connectWait("127.0.0.1", 9229, 5*time.Second, 200*time.Millisecond)
		if err != nil {
			return fmt.Errorf("failed to connect to inspector after SIGUSR1: %w", err)
		}

		var injectErr error

		// SIGUSR1 opened this port, so this injection closes it again.
		sent, injectErr = i.injectViaConn(conn, code, time.Time{}, true)

		return injectErr
	})

	return sent, err
}

// injectViaOpenInspector handles the case of an inspector already listening,
// as it is under --inspect, where no signal is needed at all. The first return
// value reports whether the injection was carried out.
//
// The port was the application's before OBI connected, so it is left open.
func (i *NodeInjector) injectViaOpenInspector(pid int, code string, deadline time.Time) (bool, error) {
	injected := false

	err := netns.WithNetNS(pid, func() error {
		conn, err := connect("127.0.0.1", 9229)
		if err != nil {
			return nil
		}

		// Validate this is actually a Node.js inspector, not some other
		// service that happens to listen on port 9229.
		if !i.isNodeInspector(conn, deadline) {
			conn.Close()
			return nil
		}

		i.log.Debug("Node.js inspector already open, injecting directly", "pid", pid)

		var injectErr error

		injected, injectErr = i.injectViaConn(conn, code, deadline, false)

		return injectErr
	})

	return injected, err
}

const (
	refusalSignalIsFatal           = "SIGUSR1 is neither caught nor ignored, so it would terminate the process"
	refusalDispositionUnknown      = "the process caught and ignored signal sets could not be read"
	refusalHandlerFound            = "process has a custom SIGUSR1 handler"
	refusalSourceReferencesSIGUSR1 = "process source files reference SIGUSR1"
)

// dispositionWait bounds how long to wait for the runtime to install its own
// SIGUSR1 handler. Node installs it about 11ms after exec, and until then
// SIGUSR1 terminates the process, so a process discovered at exec time is
// otherwise refused for a condition that clears on its own.
const (
	dispositionWait     = 500 * time.Millisecond
	dispositionInterval = 10 * time.Millisecond
)

// sigusr1Refusal reports why the signal is withheld, or an empty reason when
// it is safe to send. Discovery has already established that this is a Node.js
// runtime; what is left is whether the signal would terminate it, and whether
// the application has taken the signal over.
func sigusr1Refusal(ctx context.Context, pid int, elfFile *elf.File) string {
	syms := readNodeSymbols(elfFile)

	switch awaitSignalDisposition(ctx, pid) {
	case signalDispositionFatal:
		return refusalSignalIsFatal
	case signalDispositionUnknown:
		return refusalDispositionUnknown
	case signalDispositionHandled:
	}

	switch hasUserSIGUSR1Handler(pid, elfFile, syms) {
	case signalCheckFound:
		return refusalHandlerFound
	case signalCheckFailed:
		// The runtime carries no readable libuv signal tree, so the
		// application's own files are the only remaining evidence.
		if sourceHasSIGUSR1Reference(ctx, pid) {
			return refusalSourceReferencesSIGUSR1
		}
	case signalCheckNotFound:
	}

	return ""
}

// awaitSignalDisposition waits out the window after exec in which a runtime
// has not yet installed its own SIGUSR1 handler, so a process discovered at
// exec time is not refused for a condition that clears on its own.
//
// Cancellation reports Unknown rather than the last reading: shutdown says
// nothing about the target, and claiming the signal would have killed it would
// log a conclusion never reached.
func awaitSignalDisposition(ctx context.Context, pid int) signalDisposition {
	deadline := time.Now().Add(dispositionWait)

	for {
		disposition := sigusr1Disposition(pid)
		if disposition != signalDispositionFatal || time.Now().After(deadline) {
			return disposition
		}

		select {
		case <-ctx.Done():
			return signalDispositionUnknown
		case <-time.After(dispositionInterval):
		}
	}
}

// isNodeInspector validates that a connection to port 9229 is actually a
// Node.js inspector by requesting /json/version and checking for a valid
// JSON response.
func (i *NodeInjector) isNodeInspector(conn net.Conn, deadline time.Time) bool {
	resp, err := httpGetWithTimeout(conn, "/json/version", stepTimeout(deadline))
	if err != nil {
		return false
	}

	// The Node.js inspector responds with a JSON object containing
	// "Browser" and "Protocol-Version" fields.
	return len(resp) > 0 && resp[0] == '{'
}

//go:embed fdextractor.js
var _extractorCode string

//go:embed spanbridge.js
var _spanBridgeCode string

// Substituted at injection time so each injection installs only the
// machinery its configuration asks for (see the OBI_RT_ENABLED and
// OBI_TRACES_ENABLED comments in fdextractor.js).
const (
	rtEnabledPlaceholder     = "= false; /*OBI_RT_ENABLED*/"
	rtEnabledOn              = "= true; /*OBI_RT_ENABLED*/"
	tracesEnabledPlaceholder = "= false; /*OBI_TRACES_ENABLED*/"
	tracesEnabledOn          = "= true; /*OBI_TRACES_ENABLED*/"
	spansEnabledPlaceholder  = "= false; /*OBI_SPANS_ENABLED*/"
	spansEnabledOn           = "= true; /*OBI_SPANS_ENABLED*/"
)

// agentCode returns the extractor script with the RT gate substituted from
// the same predicate that sets the nodejs_runtime_metrics_enabled BPF
// constant, so the agent and the eBPF side cannot disagree. When manual
// spans are enabled the span bridge is appended as a second script: both are
// self-contained IIFEs, joined with an explicit ';' so the bridge's leading
// '(' is not parsed as a call of the extractor IIFE's return value.
func (i *NodeInjector) agentCode() string {
	code := _extractorCode
	if i.cfg.AppRuntimeMetricsEnabled() {
		code = strings.Replace(code, rtEnabledPlaceholder, rtEnabledOn, 1)
	}
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		code = strings.Replace(code, tracesEnabledPlaceholder, tracesEnabledOn, 1)
	}
	if i.cfg.NodeJS.ManualSpans {
		code += ";\n" + strings.Replace(_spanBridgeCode, spansEnabledPlaceholder, spansEnabledOn, 1)
	}
	return code
}

// uninstallCode is both scripts with every gate left off. Each one's prologue
// undoes what a previous injection installed — the extractor restores the net
// prototypes it wrapped and clears the async hook, sampling timer, delay
// histogram and GC observer; the bridge restores Module._load and the api
// setters it wrapped, and stops emitting. What survives either way is a
// delegate already cached by a ProxyTracer, which is inert once the bridge has
// stopped emitting.
func uninstallCode() string {
	return _extractorCode + ";\n" + _spanBridgeCode
}

const (
	// uninjectAllowanceShare divides the shutdown timeout between this pass
	// and the rest of the shutdown path. Overrunning the swarm's cancel
	// timeout turns a clean SIGTERM into a "couldn't finish" error.
	uninjectAllowanceShare = 2
	uninjectConcurrency    = 4
)

// One target's work, from the moment a worker takes it up to the moment its
// inspector is closed again. Each step runs under its own slice of this, and
// this is a slice of the allowance, so no sum can exceed what UninjectAll was
// given. The evaluate takes whatever the connect left rather than a fixed cut,
// bounded above by the deadline minus the close.
const (
	uninjectGateBudget = 250 * time.Millisecond
	// The wait for the reopened inspector is the step most likely to need the
	// time: a busy event loop reaches the inspector late, and giving up on it
	// after SIGUSR1 leaves the port open with nothing to close it.
	uninjectConnectBudget  = 2 * time.Second
	uninjectEvaluateBudget = 500 * time.Millisecond
	uninjectCommitTail     = uninjectGateBudget + uninjectConnectBudget + uninjectEvaluateBudget + debugEndBudget

	// uninjectSignalTail is what must still be left before SIGUSR1 is worth
	// sending: reopening the inspector, evaluating, and closing it again.
	// SIGUSR1 reopens the application's debugger port and only the completed
	// handshake closes it, so a target that cannot finish is never started.
	uninjectSignalTail = uninjectConnectBudget + uninjectEvaluateBudget + debugEndBudget
)

// uninjectAllowance is the whole of what this pass may take. It is the only
// budgeted quantity: every deadline below is carved out of it rather than
// added to it.
func (i *NodeInjector) uninjectAllowance() time.Duration {
	return i.cfg.ShutdownTimeout / uninjectAllowanceShare
}

// uninjectDeadline is the instant the pass must be done by, fixed to when
// shutdown began. A zero shutdownAt means the caller could not observe that —
// the pass then measures from now and bounds only itself.
func (i *NodeInjector) uninjectDeadline(shutdownAt time.Time) time.Time {
	if shutdownAt.IsZero() || shutdownAt.UnixNano() <= 0 {
		return time.Now().Add(i.uninjectAllowance())
	}

	return shutdownAt.Add(i.uninjectAllowance())
}

// UninjectAll removes the injected script from every process this agent
// injected.
//
// shutdownAt is when the shutdown this pass belongs to began. The allowance is
// measured from there rather than from entry, because whatever ran first —
// draining the injection queues, above all — spends the same timeout, and a
// pass that started its own clock late would sign targets up for work the
// process will not be alive to finish.
func (i *NodeInjector) UninjectAll(shutdownAt time.Time) {
	i.mu.Lock()
	targets := i.injected
	i.injected = map[app.PID]uint64{}
	i.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	if i.uninjectAllowance() < uninjectCommitTail {
		i.log.Warn("shutdown_timeout leaves no room to remove NodeJS instrumentation; "+
			"the injected scripts stay resident until their applications restart",
			"processes", len(targets), "shutdown_timeout", i.cfg.ShutdownTimeout,
			"needs_at_least", uninjectCommitTail*uninjectAllowanceShare)

		return
	}

	deadline := i.uninjectDeadline(shutdownAt)

	if remaining := time.Until(deadline); remaining < uninjectCommitTail {
		i.log.Warn("shutdown is already out of time to remove NodeJS instrumentation; "+
			"the injected scripts stay resident until their applications restart",
			"processes", len(targets), "remaining", remaining.Truncate(time.Millisecond))

		return
	}

	i.log.Info("removing NodeJS instrumentation before shutdown", "processes", len(targets))

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	code := uninstallCode()
	sem := make(chan struct{}, uninjectConcurrency)

	var wg sync.WaitGroup

	admitted := 0

	// A target is taken up only while a whole uninjectCommitTail still fits, so
	// the last one admitted finishes by the deadline and the pass never returns
	// with a handshake in flight. Waiting for a free worker is itself part of
	// the allowance, so the wait and the rule are the same decision.
admission:
	for pid, startTime := range targets {
		wait := time.NewTimer(time.Until(deadline) - uninjectCommitTail)

		select {
		case sem <- struct{}{}:
			wait.Stop()
		case <-wait.C:
			break admission
		}

		admitted++

		wg.Go(func() {
			defer func() { <-sem }()

			if err := i.uninject(ctx, pid, startTime, code); err != nil {
				i.log.Warn("couldn't remove NodeJS instrumentation; "+
					"the injected script stays resident until the application restarts",
					"pid", pid, "error", err)
			}
		})
	}

	if left := len(targets) - admitted; left > 0 {
		i.log.Warn("out of time to remove NodeJS instrumentation from every process; "+
			"the injected scripts stay resident until their applications restart",
			"not_reached", left, "of", len(targets))
	}

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	drain := time.NewTimer(time.Until(deadline))
	defer drain.Stop()

	select {
	case <-done:
	case <-drain.C:
		i.log.Warn("gave up waiting for NodeJS instrumentation to be removed; " +
			"the injected scripts stay resident until their applications restart")
	}
}

// uninject reopens the process this agent injected and evaluates the uninstall
// pass in it.
//
// The handle is what makes reopening safe: it validates the start time captured
// at injection, and the signal that reopens the inspector goes through it, so a
// PID the kernel recycled since cannot be signaled in the original's place.
func (i *NodeInjector) uninject(ctx context.Context, pid app.PID, startTime uint64, code string) error {
	ctx, cancel := context.WithTimeout(ctx, uninjectCommitTail)
	defer cancel()

	deadline, _ := ctx.Deadline()

	process, err := i.openHandle(pid, startTime)
	if err != nil {
		return fmt.Errorf("reopening process %d to remove the agent: %w", pid, err)
	}
	defer process.Close()

	numericPid := int(pid)

	// Everything but the close, which injectFileWS holds back for its own
	// deferred evaluate: this path needs no signal, and the check below refuses
	// the signal path anyway if the attempt spent the budget.
	injected, err := i.injectViaOpenInspector(numericPid, code, deadline.Add(-debugEndBudget))
	if injected || err != nil {
		return err
	}

	// Reopening the inspector costs the target another SIGUSR1, so it goes
	// through the same gates the injection did. Being injected once does not
	// settle them: an --inspect process was injected without the signal and so
	// without ever evaluating them, and an application can take the signal over
	// after injection.
	exe, err := process.Open("exe", os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("opening the executable of process %d: %w", pid, err)
	}
	defer exe.Close()

	elfFile, err := elf.NewFile(exe)
	if err != nil {
		return fmt.Errorf("reading the executable of process %d: %w", pid, err)
	}
	defer elfFile.Close()

	gateCtx, gateCancel := context.WithTimeout(ctx, uninjectGateBudget)
	reason := sigusr1Refusal(gateCtx, numericPid, elfFile)
	gateErr := gateCtx.Err()
	gateCancel()

	// The budget running out during the gates is not a refusal: nothing was
	// concluded about this process, and reporting one would assert a finding
	// that was never reached. It is the gate context that has to be checked,
	// not the target's: a scan abandoned when its own slice expired reports
	// "no reference found", which reads as "safe to signal".
	if gateErr != nil {
		return fmt.Errorf("gates for process %d did not finish: %w", pid, gateErr)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if reason != "" {
		return fmt.Errorf("not signaling process %d: %s", pid, reason)
	}

	// SIGUSR1 reopens the application's debugger port, and only a completed
	// handshake closes it again — injectFileWS ends with process._debugEnd().
	// Leaving 127.0.0.1:9229 listening in the application for the rest of its
	// life is worse than leaving the script resident, so a target whose slice
	// of the allowance can no longer hold the whole handshake is not signaled.
	if remaining := time.Until(deadline); remaining < uninjectSignalTail {
		return fmt.Errorf("not signaling process %d: %v left, too little to reopen and close its inspector",
			pid, remaining.Truncate(time.Millisecond))
	}

	if err := sendSIGUSR1(process); err != nil {
		return fmt.Errorf("error reopening node inspector: %w", err)
	}

	return netns.WithNetNS(numericPid, func() error {
		conn, err := connectWait("127.0.0.1", 9229, uninjectConnectBudget, 200*time.Millisecond)
		if err != nil {
			// SIGUSR1 has already reopened the port and only a completed
			// handshake closes it, so this leaves it listening for the life of
			// the process. Said plainly because it is the worst outcome the
			// pass can produce.
			return fmt.Errorf("inspector did not answer after SIGUSR1 within %v; "+
				"the debugger port of process %d stays open until it restarts: %w",
				uninjectConnectBudget, pid, err)
		}

		// SIGUSR1 above reopened the port, so this closes it again.
		_, err = i.injectViaConn(conn, code, deadline.Add(-debugEndBudget), true)

		return err
	})
}
