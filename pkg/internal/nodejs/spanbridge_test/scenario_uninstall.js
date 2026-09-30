'use strict';
// The ungated pass uninstalls the bridge; a gated re-injection leaves it emitting.

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

eval(enabled);

tracer.startSpan('after-reinjection').end();
const afterReinject = captured.length - afterFirstInject;

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
