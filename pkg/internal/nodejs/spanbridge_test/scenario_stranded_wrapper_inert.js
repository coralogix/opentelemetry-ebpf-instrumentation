"use strict";
// Regression for a stranded wrapper waking up.
//
// When another agent has wrapped over OBI's, the uninstall cannot remove OBI's
// wrapper — it is reachable only through the other agent's. That wrapper must
// stay inert for good. If it reads whatever the current injection installed
// instead of its own retired state, the next injection revives it and every
// correlated write emits the eBPF sentinel twice.

const fs = require('fs');
const net = require('net');
const path = require('path');

let sentinels = 0;
const origExists = fs.existsSync;
fs.existsSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi')) {
    if (p.startsWith('/dev/null/obi/')) {
      sentinels++;
    }
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
const pristineEmit = net.Server.prototype.emit;

let baseWrites = 0;
const base = function () {
  baseWrites++;
  return true;
};
net.Socket.prototype.write = base;

// 1. OBI injects. 2. Another agent chains over its write wrapper.
evalExtractor(true);
const under = net.Socket.prototype.write;
net.Socket.prototype.write = function (...args) {
  return under.apply(this, args);
};

// 3. OBI uninstalls: its write wrapper is stranded inside the foreign one.
evalExtractor(false);

// 4. OBI injects again.
evalExtractor(true);

// Drive one correlated write: a server connection opens request scope, and a
// write to a different fd inside it is what emits the sentinel.
const inbound = { _handle: { fd: 11 } };
const outbound = { _handle: { fd: 12 } };

const srv = new net.Server();
srv.on('connection', () => {
  net.Socket.prototype.write.call(outbound, 'payload');
});

const before = sentinels;
srv.emit('connection', inbound);
const emitted = sentinels - before;

net.Socket.prototype.write = pristineWrite;
net.Server.prototype.emit = pristineEmit;
fs.existsSync = origExists;

process.stdout.write(JSON.stringify({ emitted, baseWrites }));
