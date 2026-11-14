/**
 * scope-smoke.mjs — prove a network scope is enforced in a real sandbox.
 *
 * Unit tests cover the rule text; this covers what only a running sandbox can
 * show. A target container listens on one port of a private Docker network, and
 * the scope allows exactly that address and port. From the tool user's side the
 * allowed port must answer, and a second port on the same host, the network's
 * gateway, a name lookup and an attempt to remove the rules must all fail.
 *
 * Usage:
 *   node sandbox/scope-smoke.mjs
 *
 * A host without KVM can run it with CYBERSEC_SANDBOX_RUNTIME=runc
 * CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1; the rules are the same.
 */

import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DEFAULT_IMAGE, kata } from './kata.mjs';

const id = randomBytes(4).toString('hex');
const network = `cybersec-scope-smoke-${id}`;
const target = `cybersec-scope-target-${id}`;
const image = process.env.CYBERSEC_SANDBOX_IMAGE ?? DEFAULT_IMAGE;
const scratch = mkdtempSync(join(tmpdir(), 'cybersec-scope-smoke-'));

const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8' }).trim();
const quietly = (...args) => {
  try {
    execFileSync('docker', args, { stdio: 'ignore' });
  } catch {
    // Cleanup is best-effort.
  }
};

// Connect and report the errno: refused (111) means the packet reached the host,
// unreachable (113) means a rule answered for it.
const connect = (host, port) =>
  `python3 -c 'import socket,sys\ntry:\n    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=4).close(); print("connected")\nexcept OSError as e:\n    print(e.errno)' ${host} ${port}`;

const failures = [];
const check = (label, ok, detail) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? ` (${detail})` : ''}`);
  if (!ok) failures.push(label);
};

let sandbox;
try {
  docker('network', 'create', network);
  docker(
    'run', '--detach', '--rm', '--name', target, '--network', network,
    '--entrypoint', 'python3', image, '-m', 'http.server', '8080', '--bind', '0.0.0.0',
  );
  const address = docker('inspect', '--format', `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`, target);
  const gateway = docker('network', 'inspect', '--format', '{{(index .IPAM.Config 0).Gateway}}', network);

  const scopeFile = join(scratch, 'scope.json');
  writeFileSync(scopeFile, JSON.stringify({ name: 'scope-smoke', allow: [{ host: address, ports: [8080], proto: 'tcp' }] }));

  sandbox = await kata({ network, scope: scopeFile }).create({ env: {} });
  const run = async (command) => (await sandbox.exec(command)).stdout.trim();

  // The target needs a moment to start listening.
  let allowed = '';
  for (let attempt = 0; attempt < 20 && allowed !== 'connected'; attempt += 1) {
    allowed = await run(connect(address, 8080));
    if (allowed !== 'connected') await new Promise((resolve) => setTimeout(resolve, 500));
  }
  check('the port in scope answers', allowed === 'connected', allowed);
  const otherPort = await run(connect(address, 8081));
  check('another port on the same host is rejected', otherPort === '113', `errno ${otherPort}, 111 would mean it left the sandbox`);
  const toGateway = await run(connect(gateway, 9));
  check('the network gateway is rejected', toGateway === '113', `errno ${toGateway}`);
  const outside = await run(connect('192.0.2.1', 9));
  check('an address outside the scope is rejected at once', outside === '113', `errno ${outside}`);
  const lookup = await run(
    `python3 -c 'import socket\ntry:\n    socket.getaddrinfo("example.com", 80); print("resolved")\nexcept OSError:\n    print("no answer")'`,
  );
  check('names outside the scope do not resolve', lookup === 'no answer', lookup);
  const flush = await sandbox.exec('nft flush ruleset');
  check('the tool user cannot remove the rules', flush.exitCode !== 0);
  const stillRejected = await run(connect(address, 8081));
  check('the rules are still in force afterwards', stillRejected === '113', `errno ${stillRejected}`);
} catch (error) {
  check(`setup: ${error.message}`, false);
} finally {
  if (sandbox) await sandbox.close();
  quietly('stop', '--time', '1', target);
  quietly('network', 'rm', network);
  rmSync(scratch, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`scope smoke: ${failures.length} check(s) failed`);
  process.exitCode = 1;
} else {
  console.log('scope smoke: OK — the scope holds from the tool user\'s side');
}
