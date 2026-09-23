"use strict";
// Regressions for OBI's net-prototype wrappers coexisting with another agent.
//
// The other agent is modelled the way real ones behave: it captures whatever is
// installed and calls through to it. That shape is what makes the ordering
// hazardous — an OBI wrapper from an earlier injection stays reachable inside
// the third-party wrapper after OBI declines to restore it, so a re-injection
// must not point that older wrapper back at the chain it is already part of.

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

function evalExtractor(traces) {
  const src = fs
    .readFileSync(path.join(__dirname, '..', 'fdextractor.js'), 'utf8')
    .replace('= false; /*OBI_TRACES_ENABLED*/', (traces ? '= true; ' : '= false; ') + '/*OBI_TRACES_ENABLED*/');
  // eslint-disable-next-line no-eval
  eval(src);
}

const pristineWrite = net.Socket.prototype.write;

// Stand in for the real write so the chain can be driven without a socket.
let baseCalls = 0;
const base = function () {
  baseCalls++;
  return true;
};
net.Socket.prototype.write = base;

// 1. OBI injects and wraps.
evalExtractor(true);
const obiWrite = net.Socket.prototype.write;
const obiWrapped = obiWrite !== base;

// 2. Another agent wraps over OBI's, calling through as real agents do.
let foreignCalls = 0;
const under = net.Socket.prototype.write;
const foreignWrite = function (...args) {
  foreignCalls++;
  return under.apply(this, args);
};
net.Socket.prototype.write = foreignWrite;

// 3. OBI uninstalls. Its wrapper is still reachable inside the foreign one.
evalExtractor(false);
const foreignSurvived = net.Socket.prototype.write === foreignWrite;
const resetToBase = net.Socket.prototype.write === base;

// 4. OBI re-injects into the same live process, as it does after a restart.
evalExtractor(true);
const rewrapped = net.Socket.prototype.write !== foreignWrite;

const foreignBefore = foreignCalls;
const baseBefore = baseCalls;
let threw = null;
try {
  net.Socket.prototype.write.call({}, 'probe');
} catch (e) {
  threw = e instanceof RangeError ? 'RangeError' : e.constructor.name;
}
const foreignStillInPath = foreignCalls > foreignBefore;
const reachedBase = baseCalls === baseBefore + 1;

// 5. With nothing layered on top, the uninstall restores what OBI found.
evalExtractor(false);
net.Socket.prototype.write = base;
evalExtractor(true);
const ownWrapperDiffers = net.Socket.prototype.write !== base;
evalExtractor(false);
const restoredWhenOurs = net.Socket.prototype.write === base;

net.Socket.prototype.write = pristineWrite;
fs.existsSync = origExists;

process.stdout.write(
  JSON.stringify({
    obiWrapped,
    foreignSurvived,
    resetToBase,
    rewrapped,
    threw,
    foreignStillInPath,
    reachedBase,
    ownWrapperDiffers,
    restoredWhenOurs,
  }),
);
