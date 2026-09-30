"use strict";
// A cached bridge Tracer forwards startActiveSpan with the caller's argument count.

const fs = require('fs');
const path = require('path');

const bridgeCaptured = [];
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    bridgeCaptured.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)).name);
    return false;
  }
  return origExists(p, ...rest);
};

function injectBridge() {
  const src = fs
    .readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8')
    .replace('= false; /*OBI_SPANS_ENABLED*/', '= true; /*OBI_SPANS_ENABLED*/');
  // eslint-disable-next-line no-eval
  eval(src);
}

async function run() {
  const appCaptured = [];
  const { trace } = require('@opentelemetry/api');

  injectBridge();

  const tracer = trace.getTracer('app');
  tracer.startSpan('before').end();

  const { NodeTracerProvider } = require('@opentelemetry/sdk-trace-node');
  const proc = {
    onStart() {},
    onEnd(span) {
      appCaptured.push(span.name);
    },
    shutdown() {
      return Promise.resolve();
    },
    forceFlush() {
      return Promise.resolve();
    },
  };
  new NodeTracerProvider({ spanProcessors: [proc] }).register();

  let threw = null;
  let ran = false;
  let recording = null;
  try {
    tracer.startActiveSpan('two-arg', (span) => {
      ran = true;
      recording = typeof span === 'object' && span !== null && typeof span.end === 'function';
      span.end();
    });
  } catch (e) {
    threw = String((e && e.message) || e);
  }

  let threwThree = null;
  let ranThree = false;
  try {
    tracer.startActiveSpan('three-arg', { attributes: { a: 1 } }, (span) => {
      ranThree = true;
      span.end();
    });
  } catch (e) {
    threwThree = String((e && e.message) || e);
  }

  await new Promise((r) => setTimeout(r, 20));
  fs.existsSync = origExists;

  process.stdout.write(
    JSON.stringify({
      bridge: bridgeCaptured,
      app: appCaptured,
      threw,
      ran,
      recording,
      threwThree,
      ranThree,
    }),
  );
}

run().catch((e) => {
  process.stderr.write(String(e && (e.stack || e.message)));
  process.exit(1);
});
