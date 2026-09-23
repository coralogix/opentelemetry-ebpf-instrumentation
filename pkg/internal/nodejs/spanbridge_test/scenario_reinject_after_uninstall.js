'use strict';
// The agent-upgrade sequence: install, uninstall at shutdown, install again
// when the next OBI comes up. A tracer the application acquired before any of
// it has cached the first bridge's Tracer and never consults the provider
// again, so the successor has to be reachable through that cached object or
// the application's spans stop for the life of the process.

const fs = require('fs');
const path = require('path');

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

// Acquired once, before anything is injected: the module-scope idiom.
const tracer = api.trace.getTracer('app');

eval(enabled);
tracer.startSpan('run-1').end();
const afterFirstRun = captured.length;

// OBI shuts down cleanly.
eval(src);
const afterShutdown = captured.length - afterFirstRun;

// The next OBI comes up and injects again.
eval(enabled);
tracer.startSpan('run-2').end();
const afterSecondRun = captured.length - afterFirstRun - afterShutdown;

// And that one shuts down too, which must silence it again.
eval(src);
const beforeFinalSilence = captured.length;
tracer.startSpan('after-final-shutdown').end();
const afterFinalShutdown = captured.length - beforeFinalSilence;

fs.existsSync = origExists;

process.stdout.write(
  JSON.stringify({
    emittedInFirstRun: afterFirstRun,
    emittedWhileShutDown: afterShutdown,
    emittedInSecondRun: afterSecondRun,
    emittedAfterFinalShutdown: afterFinalShutdown,
  }),
);
