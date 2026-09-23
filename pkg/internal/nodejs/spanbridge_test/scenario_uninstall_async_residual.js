'use strict';
// After the uninstall, a tracer the application cached still points at the
// retired bridge. Using it must not reach AsyncLocalStorage.run(): run()
// re-enables an instance the uninstall disabled, and nothing is left to
// disable it again, so the async_hooks hook backing it would stay live for the
// rest of the process — the exact cost the uninstall exists to remove.
//
// Counting run() on the prototype is the deterministic form of that question;
// the timing of it is too noisy to assert on.

const fs = require('fs');
const path = require('path');
const asyncHooks = require('async_hooks');

const api = require('@opentelemetry/api');

const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) =>
  (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) ? false : origExists(p, ...rest);

let runCalls = 0;
const origRun = asyncHooks.AsyncLocalStorage.prototype.run;
asyncHooks.AsyncLocalStorage.prototype.run = function (...args) {
  runCalls++;
  return origRun.apply(this, args);
};

const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
const enabled = src.replace('= false; /*OBI_SPANS_ENABLED*/', '= true; /*OBI_SPANS_ENABLED*/');

const tracer = api.trace.getTracer('app');

eval(enabled);

// Installed: startActiveSpan is expected to establish context, which is what
// makes the ALS live in the first place.
let installedCallbackRan = false;
tracer.startActiveSpan('installed', (span) => {
  installedCallbackRan = true;
  span.end();
});
const runsWhileInstalled = runCalls;

eval(src);

// The application keeps using its cached tracer after OBI is gone.
const before = runCalls;
tracer.startSpan('after').end();

let retiredCallbackRan = false;
let retiredSpanRecording = true;
tracer.startActiveSpan('after-active', (span) => {
  retiredCallbackRan = true;
  retiredSpanRecording = span.isRecording();
  span.end();
});
const runsWhileRetired = runCalls - before;

asyncHooks.AsyncLocalStorage.prototype.run = origRun;
fs.existsSync = origExists;

process.stdout.write(
  JSON.stringify({
    installedCallbackRan,
    runsWhileInstalled,
    retiredCallbackRan,
    retiredSpanRecording,
    runsWhileRetired,
  }),
);
