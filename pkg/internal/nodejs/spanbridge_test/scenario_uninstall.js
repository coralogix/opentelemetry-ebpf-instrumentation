'use strict';
// The shutdown pass: injecting the bridge with its gate off must undo a prior
// gated injection — Module._load and the wrapped api setters restored by
// identity, and no further spans reaching the transport.
//
// A re-injection with the gate ON must instead leave the resident bridge
// alone. The tracer here is acquired ONCE, before the first injection, which
// is the documented module-scope idiom and the case that matters: a
// ProxyTracer caches the first delegate it resolves, so a bridge torn down
// under a still-cached tracer would drop that tracer's spans for good.

const fs = require('fs');
const path = require('path');
const Module = require('module');

const api = require('@opentelemetry/api');

const captured = [];
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    captured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    return false;
  }
  return origExists(p, ...rest);
};

const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
const enabled = src.replace('= false; /*OBI_SPANS_ENABLED*/', '= true; /*OBI_SPANS_ENABLED*/');

const pristineLoad = Module._load;
const pristineSetTP = api.trace.setGlobalTracerProvider;
const pristineSetCM = api.context.setGlobalContextManager;

// Acquired before any injection, and reused throughout: this is the handle
// that caches a delegate.
const tracer = api.trace.getTracer('app');

eval(enabled);

const installed = {
  active: !!globalThis.__obiSpanBridge,
  loadPatched: Module._load !== pristineLoad,
  setTPWrapped: api.trace.setGlobalTracerProvider !== pristineSetTP,
  setCMWrapped: api.context.setGlobalContextManager !== pristineSetCM,
};

tracer.startSpan('first').end();
const afterFirstInject = captured.length;

// A second gated injection, as happens when OBI restarts against a process
// that still carries the agent. The resident bridge must keep emitting
// through the tracer the application already holds.
eval(enabled);

tracer.startSpan('after-reinjection').end();
const afterReinject = captured.length - afterFirstInject;

// The ungated pass is the uninstall.
eval(src);

const removed = {
  globalCleared: globalThis.__obiSpanBridge === undefined,
  latchCleared: globalThis.__obiSpanBridgeLoaded === false,
  loadRestored: Module._load === pristineLoad,
  setTPRestored: api.trace.setGlobalTracerProvider === pristineSetTP,
  setCMRestored: api.context.setGlobalContextManager === pristineSetCM,
};

const beforeSilence = captured.length;
for (let i = 0; i < 20; i++) {
  tracer.startSpan('after-uninstall').end();
}

fs.existsSync = origExists;

process.stdout.write(
  JSON.stringify({
    installed,
    removed,
    emittedWhileInstalled: afterFirstInject,
    emittedAfterReinjection: afterReinject,
    emittedAfterUninstall: captured.length - beforeSilence,
  }),
);
