"use strict";
// A wrapper stranded under a foreign one stays inert after re-injection.

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

evalExtractor(true);
const under = net.Socket.prototype.write;
net.Socket.prototype.write = function (...args) {
  return under.apply(this, args);
};

evalExtractor(false);

evalExtractor(true);

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
