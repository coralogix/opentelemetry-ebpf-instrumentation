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

	"golang.org/x/sys/unix"

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

	openHandle func(app.PID, uint64) (*procs.ProcessHandle, error)

	mu       sync.Mutex
	injected map[app.PID]injectedProcess
}

type injectedProcess struct {
	startTime uint64
	gates     *signalGates
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
		injected:   map[app.PID]injectedProcess{},
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

const skippingInjection = "skipping Node.js agent injection. Trace-context propagation and " +
	"Node.js runtime metrics will not work"

// Inject injects into an accepted target.
//
// The executable, the signal and its disposition all go through the target's
// pinned process handle, so a PID the kernel recycled between discovery and
// here cannot be signaled in the original's place. The rest still works from
// the numeric PID: the handler gate reads the process memory and the inspector
// conversation enters a network namespace, so a replacement can be the process
// examined and — where an inspector is already listening, which needs no
// signal — the one injected.
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

	if reason := i.runtimeRefusal(target, elfFile); reason != "" {
		i.log.Warn(skippingInjection, "pid", pid, "reason", reason)
		return
	}

	gates := &signalGates{}
	injected, err := i.attachAgent(ctx, target, elfFile, gates)

	// Recorded once sent: a script evaluated before a failed reply is still resident.
	if injected {
		i.mu.Lock()
		i.injected[pid] = injectedProcess{startTime: target.StartTime, gates: gates}
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
func (i *NodeInjector) attachAgent(ctx context.Context, target InjectionTarget, elfFile *elf.File, gates *signalGates) (bool, error) {
	pid := int(target.Pid)
	code := i.agentCode()

	injected, err := i.injectViaOpenInspector(pid, code, time.Time{})
	if injected || err != nil {
		return injected, err
	}

	reason := gates.refusal(ctx, target.Process, elfFile)

	// Shutdown is not a refusal: the gates were abandoned rather than answered,
	// so nothing was concluded about this process and nothing is reported.
	if err := ctx.Err(); err != nil {
		return false, nil
	}

	if reason != "" {
		i.log.Warn(skippingInjection, "pid", pid, "reason", reason)
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

// Every reason an injection is skipped, in the order they are decided: what the
// executable says first, then what the process says about SIGUSR1.
const (
	refusalVersionUnknown      = "the Node.js version could not be read from the executable"
	refusalNoAsyncLocalStorage = "Node.js %s does not provide AsyncLocalStorage, " +
		"which the injected agent requires: it was added in %s and backported to %s"
	// Refusing the whole injection rather than dropping the bridge alone: the
	// two scripts are evaluated as one expression, and manual spans are opt-in,
	// so silently not delivering them would be worse than saying so.
	refusalManualSpansTooOld = "nodejs.manual_spans needs Node.js %s or newer for the span " +
		"bridge to parse, and this process runs %s"

	refusalSignalIsFatal           = "SIGUSR1 is neither caught nor ignored, so it would terminate the process"
	refusalDispositionUnknown      = "SIGUSR1 handling is unknown: the process caught and ignored signal sets could not be read"
	refusalHandlerFound            = "process has a custom SIGUSR1 handler"
	refusalSourceReferencesSIGUSR1 = "process source files reference SIGUSR1"
)

// runtimeRefusal reports why this executable must not be injected, or "" when it
// may be. It decides before touching the process, so a runtime the agent cannot
// run on is never signaled and its debugger port is never opened — which also keeps
// OBI off Node.js 9.3.0, where closing the inspector again segfaults the process.
//
// A version that cannot be read is a refusal rather than a pass: it is the only
// evidence the agent can run there.
func (i *NodeInjector) runtimeRefusal(target InjectionTarget, elfFile *elf.File) string {
	nodeVersion, ok := nodeVersionFromProcess(target, elfFile)
	if !ok {
		return refusalVersionUnknown
	}

	if !supportsAsyncLocalStorage(nodeVersion) {
		return fmt.Sprintf(refusalNoAsyncLocalStorage, nodeVersion.Original(),
			node13Backport.Original(), minInjectableVersion.Original())
	}

	if i.cfg.NodeJS.ManualSpans && !supportsManualSpans(nodeVersion) {
		return fmt.Sprintf(refusalManualSpansTooOld,
			minManualSpansVersion.Original(), nodeVersion.Original())
	}

	return ""
}

// dispositionWait bounds how long to wait for the runtime to install its own
// SIGUSR1 handler. Node installs it about 11ms after exec, and until then
// SIGUSR1 terminates the process, so a process discovered at exec time is
// otherwise refused for a condition that clears on its own.
const dispositionWait = 500 * time.Millisecond

// signalGates keeps what the SIGUSR1 gates learn that holds for the life of a
// process — the executable's symbols and a completed source scan — so the
// shutdown pass re-reads only the disposition and the handler tree.
type signalGates struct {
	symsRead bool
	syms     nodeSymbols

	scanned   bool
	sourceHit bool
}

func (g *signalGates) symbols(elfFile *elf.File) nodeSymbols {
	if !g.symsRead {
		g.syms = readNodeSymbols(elfFile)
		g.symsRead = true
	}

	return g.syms
}

// sourceReferencesSIGUSR1 remembers only a scan that finished: a cancelled one
// reports no reference found.
func (g *signalGates) sourceReferencesSIGUSR1(ctx context.Context, pid int) bool {
	if !g.scanned {
		g.sourceHit = sourceHasSIGUSR1Reference(ctx, pid)
		g.scanned = ctx.Err() == nil
	}

	return g.sourceHit
}

// sigusr1Refusal reports why the signal is withheld, or an empty reason when
// it is safe to send. Discovery has already established that this is a Node.js
// runtime; what is left is whether the signal would terminate it, and whether
// the application has taken the signal over.
func sigusr1Refusal(ctx context.Context, process *procs.ProcessHandle, elfFile *elf.File) string {
	return (&signalGates{}).refusal(ctx, process, elfFile)
}

func (g *signalGates) refusal(ctx context.Context, process *procs.ProcessHandle, elfFile *elf.File) string {
	pid := int(process.PID())
	syms := g.symbols(elfFile)

	switch process.AwaitSignalDisposition(ctx, unix.SIGUSR1, dispositionWait) {
	case procs.SignalDispositionFatal:
		return refusalSignalIsFatal
	case procs.SignalDispositionUnknown:
		return refusalDispositionUnknown
	case procs.SignalDispositionHandled:
	}

	switch hasUserSIGUSR1Handler(pid, elfFile, syms) {
	case signalCheckFound:
		return refusalHandlerFound
	case signalCheckFailed:
		// The runtime carries no readable libuv signal tree, so the
		// application's own files are the only remaining evidence.
		if g.sourceReferencesSIGUSR1(ctx, pid) {
			return refusalSourceReferencesSIGUSR1
		}
	case signalCheckNotFound:
	}

	return ""
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

	ctxHookEnabledPlaceholder = "= false; /*OBI_CTX_HOOK_ENABLED*/"
	ctxHookEnabledOn          = "= true; /*OBI_CTX_HOOK_ENABLED*/"
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
	if i.cfg.PopulateTraceContext() {
		code = strings.Replace(code, ctxHookEnabledPlaceholder, ctxHookEnabledOn, 1)
	}
	if i.cfg.NodeJS.ManualSpans {
		code += ";\n" + strings.Replace(_spanBridgeCode, spansEnabledPlaceholder, spansEnabledOn, 1)
	}
	return code
}

// uninstallCode is both scripts with every gate off: each prologue tears down
// what a previous injection installed.
func uninstallCode() string {
	return _extractorCode + ";\n" + _spanBridgeCode
}

const (
	// Half the shutdown timeout, so the rest of shutdown still fits.
	uninjectAllowanceShare = 2
	uninjectConcurrency    = 4
)

const (
	uninjectGateBudget     = 250 * time.Millisecond
	uninjectConnectBudget  = 2 * time.Second
	uninjectEvaluateBudget = 500 * time.Millisecond
	uninjectCommitTail     = uninjectGateBudget + uninjectConnectBudget + uninjectEvaluateBudget + debugEndBudget

	// SIGUSR1 opens a port only a completed handshake closes, so it is sent
	// only while the whole handshake still fits.
	uninjectSignalTail = uninjectConnectBudget + uninjectEvaluateBudget + debugEndBudget
)

func (i *NodeInjector) uninjectAllowance() time.Duration {
	return i.cfg.ShutdownTimeout / uninjectAllowanceShare
}

func (i *NodeInjector) uninjectDeadline(shutdownAt time.Time) time.Time {
	if shutdownAt.IsZero() || shutdownAt.UnixNano() <= 0 {
		return time.Now().Add(i.uninjectAllowance())
	}

	return shutdownAt.Add(i.uninjectAllowance())
}

// UninjectAll removes the injected script from every process this agent
// injected, returning within the allowance measured from shutdownAt.
func (i *NodeInjector) UninjectAll(shutdownAt time.Time) {
	i.mu.Lock()
	targets := i.injected
	i.injected = map[app.PID]injectedProcess{}
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

	// A target is admitted only while a whole commit tail still fits.
admission:
	for pid, proc := range targets {
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

			if err := i.uninject(ctx, pid, proc, code); err != nil {
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

// uninject reopens the process through a handle validated against the start
// time recorded at injection, so a recycled PID is never signaled.
func (i *NodeInjector) uninject(ctx context.Context, pid app.PID, proc injectedProcess, code string) error {
	ctx, cancel := context.WithTimeout(ctx, uninjectCommitTail)
	defer cancel()

	deadline, _ := ctx.Deadline()

	process, err := i.openHandle(pid, proc.startTime)
	if err != nil {
		return fmt.Errorf("reopening process %d to remove the agent: %w", pid, err)
	}
	defer process.Close()

	numericPid := int(pid)

	injected, err := i.injectViaOpenInspector(numericPid, code, deadline.Add(-debugEndBudget))
	if injected || err != nil {
		return err
	}

	// Same gates as injection: an --inspect process never went through them,
	// and an application can take SIGUSR1 over after injection.
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
	gates := proc.gates
	if gates == nil {
		gates = &signalGates{}
	}

	reason := gates.refusal(gateCtx, process, elfFile)
	gateErr := gateCtx.Err()
	gateCancel()

	// An abandoned source scan reports "no reference found", so the gate
	// context decides, not the reason.
	if gateErr != nil {
		return fmt.Errorf("gates for process %d did not finish: %w", pid, gateErr)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if reason != "" {
		return fmt.Errorf("not signaling process %d: %s", pid, reason)
	}

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
			return fmt.Errorf("inspector did not answer after SIGUSR1 within %v; "+
				"the debugger port of process %d stays open until it restarts: %w",
				uninjectConnectBudget, pid, err)
		}

		_, err = i.injectViaConn(conn, code, deadline.Add(-debugEndBudget), true)

		return err
	})
}
