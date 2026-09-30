"use strict";
// Re-injecting over a released agent must not recurse through its wrappers.

const fs = require('fs');
const net = require('net');
const path = require('path');

const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi')) {
    return false;
  }
  return origExists(p, ...rest);
};

function evalAgent(file, traces) {
  const src = fs
    .readFileSync(file, 'utf8')
    .replace('= false; /*OBI_TRACES_ENABLED*/', (traces ? '= true; ' : '= false; ') + '/*OBI_TRACES_ENABLED*/');
  // eslint-disable-next-line no-eval
  eval(src);
}

const released = path.join(__dirname, 'fixture_fdextractor_released.js');
const current = path.join(__dirname, '..', 'fdextractor.js');

// stdout is a pipe under the runner; the stub is restored before writing.
const pristineWrite = net.Socket.prototype.write;

let baseCalls = 0;
const base = function () {
  baseCalls++;
  return true;
};
net.Socket.prototype.write = base;

evalAgent(released, true); // a released OBI injected this process
const releasedWrapped = net.Socket.prototype.write !== base;

evalAgent(current, true); // the upgraded OBI re-injects it
const rewrapped = net.Socket.prototype.write !== base;

let threw = null;
const before = baseCalls;
try {
  net.Socket.prototype.write.call({}, 'probe');
} catch (e) {
  threw = e instanceof RangeError ? 'RangeError' : e.constructor.name;
}
const reachedBaseOnce = baseCalls === before + 1;

const store = global[Symbol.for('otel-ebpf-instrumentation.fdextractor')];
const releasedOutOfPath = store.installed.nextSocketWrite === base;

evalAgent(current, false); // the upgraded OBI shuts down
const restoredToBase = net.Socket.prototype.write === base;

net.Socket.prototype.write = pristineWrite;
fs.existsSync = origExists;

process.stdout.write(JSON.stringify({ releasedWrapped, rewrapped, threw, reachedBaseOnce, releasedOutOfPath, restoredToBase }));
