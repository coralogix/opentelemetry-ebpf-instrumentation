'use strict';
// Install, uninstall, reinstall: a tracer cached before all of it reaches the successor.

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

const tracer = api.trace.getTracer('app');

eval(enabled);
tracer.startSpan('run-1').end();
const afterFirstRun = captured.length;

eval(src);
const afterShutdown = captured.length - afterFirstRun;

eval(enabled);
tracer.startSpan('run-2').end();
const afterSecondRun = captured.length - afterFirstRun - afterShutdown;

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
