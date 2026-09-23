"use strict";
// Regression for the OBI upgrade path: a new agent re-injecting into a process
// that still carries a previously released agent.
//
// The released agent's wrappers read the shared store when they run. If the new
// agent reassigns the fields that store holds, the old wrapper is pointed at a
// chain it is already part of and every socket write recurses until the stack
// overflows — taking the customer's application with it.

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

// process.stdout is a pipe when this runs under the test runner, so the stub
// below would swallow the result. The prototype is put back before writing it.
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

net.Socket.prototype.write = pristineWrite;
fs.existsSync = origExists;

process.stdout.write(JSON.stringify({ releasedWrapped, rewrapped, threw, reachedBaseOnce }));
