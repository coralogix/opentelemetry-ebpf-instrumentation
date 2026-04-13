// start-all.js
const { spawn } = require('child_process');

const services = [
  { route: 'c', port: 6002 }, // End of chain
  { route: 'b', port: 6001, upstream: process.env.UPSTREAM_B || 'http://localhost:6002' }, // Middle
  { route: 'a', port: 6000, upstream: process.env.UPSTREAM_A || 'http://localhost:6001' }, // Start
];

services.forEach(({ route, port, upstream }) => {
  const args = ['service.js', route, port.toString()];
  if (upstream) args.push(upstream);

  const proc = spawn('node', args, { stdio: 'inherit' });

  proc.on('exit', code => {
    console.log(`Service ${route.toUpperCase()} exited with code ${code}`);
  });
});
