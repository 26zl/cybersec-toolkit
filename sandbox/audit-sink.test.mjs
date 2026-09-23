import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  AUDIT_KEY_BYTES,
  AUDIT_KEY_ENV,
  AUDIT_STREAM_PREFIX,
  auditRecordTag,
  authenticateAuditLine,
  createAuditSink,
  createAuditStderrTee,
  isAuditRecord,
  resolveHostAuditPath,
  splitAuditLines,
} from './audit-sink.mjs';

const ROOT = join(import.meta.dirname, '..');
const KEY = Buffer.alloc(AUDIT_KEY_BYTES, 7);

const scratch = () => mkdtempSync(join(tmpdir(), 'cybersec-audit-'));
const record = (tool, seq = 1, ts = '2026-09-10T19:00:00.000Z') =>
  JSON.stringify({ ts, event: 'tool_call', tool, chain: 'c'.repeat(32), seq, prev: '0'.repeat(64) });
// A stderr line in the form mcp_server/audit.py mirrors a record in.
const tagged = (line, key = KEY) => `${AUDIT_STREAM_PREFIX}${auditRecordTag(key, line)} ${line}\n`;
const readLines = (path) => (existsSync(path) ? readFileSync(path, 'utf8').split('\n').filter(Boolean) : []);
const endOf = (tee) => new Promise((done) => tee.end(done));

const collectingTee = (target) => {
  const forwarded = [];
  const tee = createAuditStderrTee({ write: (line) => forwarded.push(line) }, createAuditSink({ path: target }), KEY);
  return { tee, forwarded };
};

test('resolveHostAuditPath follows the same precedence as audit.py', () => {
  assert.equal(resolveHostAuditPath({ CYBERSEC_MCP_AUDIT_LOG: '/var/log/x.log' }), '/var/log/x.log');
  assert.equal(resolveHostAuditPath({ XDG_STATE_HOME: '/state' }), '/state/cybersec-tools-mcp/audit.log');
  assert.equal(resolveHostAuditPath({ HOME: '/home/a' }), '/home/a/.local/state/cybersec-tools-mcp/audit.log');
  assert.equal(resolveHostAuditPath({ HOME: '/home/a', CYBERSEC_MCP_AUDIT_LOG: '~/audit.log' }), '/home/a/audit.log');
});

test('splitAuditLines separates mirrored records from ordinary stderr', () => {
  const split = splitAuditLines('', `${AUDIT_STREAM_PREFIX}${record('guided_assessment')}\nStarting MCP server\n`);
  assert.deepEqual(split.audit, [record('guided_assessment')]);
  assert.deepEqual(split.passthrough, ['Starting MCP server']);
  assert.equal(split.rest, '');
});

test('splitAuditLines carries a partial line into the next chunk', () => {
  const line = `${AUDIT_STREAM_PREFIX}${record('run_tool')}`;
  const first = splitAuditLines('', line.slice(0, 20));
  assert.deepEqual(first.audit, []);
  assert.equal(first.rest, line.slice(0, 20));

  const second = splitAuditLines(first.rest, `${line.slice(20)}\n`);
  assert.deepEqual(second.audit, [record('run_tool')]);
  assert.equal(second.rest, '');
});

test('splitAuditLines flushes an unterminated line instead of buffering forever', () => {
  const huge = 'x'.repeat(1024 * 1024 + 1);
  const split = splitAuditLines('', huge);
  assert.deepEqual(split.audit, []);
  assert.deepEqual(split.passthrough, [huge]);
  assert.equal(split.rest, '');
});

test('isAuditRecord accepts only well-formed records', () => {
  assert.equal(isAuditRecord(record('run_tool')), true);
  assert.equal(isAuditRecord('{"no":"event"}'), false);
  assert.equal(isAuditRecord('not json'), false);
  assert.equal(isAuditRecord('"a string"'), false);
  assert.equal(isAuditRecord('null'), false);
});

test('authenticateAuditLine returns the record only when its tag verifies', () => {
  const line = record('run_tool');
  const tag = auditRecordTag(KEY, line);
  assert.equal(authenticateAuditLine(`${tag} ${line}`, KEY), line);

  assert.equal(authenticateAuditLine(`${auditRecordTag(randomBytes(AUDIT_KEY_BYTES), line)} ${line}`, KEY), null);
  assert.equal(authenticateAuditLine(`${auditRecordTag(KEY, record('other'))} ${line}`, KEY), null);
  assert.equal(authenticateAuditLine(`${'0'.repeat(64)} ${line}`, KEY), null);
  assert.equal(authenticateAuditLine(`${tag.slice(2)} ${line}`, KEY), null);
  assert.equal(authenticateAuditLine(line, KEY), null);
  assert.equal(authenticateAuditLine('', KEY), null);
});

test('createAuditSink writes owner-only records under an owner-only directory', () => {
  const target = join(scratch(), 'nested', 'audit.log');
  const sink = createAuditSink({ path: target });

  assert.equal(sink.write(record('guided_assessment')), true);
  assert.equal(sink.write(record('run_tool')), true);

  const lines = readFileSync(target, 'utf8').trim().split('\n');
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).tool, 'guided_assessment');
  assert.equal(statSync(target).mode & 0o777, 0o600);
  assert.equal(statSync(join(target, '..')).mode & 0o777, 0o700);
});

test('createAuditSink rotates at the 5 MB mark like the Python handler', () => {
  const target = join(scratch(), 'audit.log');
  writeFileSync(target, Buffer.alloc(5 * 1024 * 1024, 0x61), { mode: 0o600 });

  createAuditSink({ path: target }).write(record('run_tool'));

  assert.equal(existsSync(`${target}.1`), true);
  assert.equal(readFileSync(target, 'utf8').trim(), record('run_tool'));
});

test('createAuditSink degrades to a single warning when the log is unusable', () => {
  const warnings = [];
  const sink = createAuditSink({ path: 'relative/audit.log', warn: (m) => warnings.push(m) });

  assert.equal(sink.enabled, false);
  assert.equal(sink.write(record('run_tool')), false);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /must be absolute/);
});

test('createAuditSink fails closed when the audit log is required', () => {
  assert.throws(() => createAuditSink({ path: 'relative/audit.log', required: true }), /Host audit log unavailable/);
});

test('the stderr tee persists authenticated records and forwards ordinary stderr', async () => {
  const target = join(scratch(), 'audit.log');
  const { tee, forwarded } = collectingTee(target);

  tee.write(`Starting MCP server\n${tagged(record('guided_assessment'))}`);
  await endOf(tee);

  assert.deepEqual(readLines(target), [record('guided_assessment')]);
  assert.deepEqual(forwarded, ['Starting MCP server\n']);
});

test('the stderr tee rejects records it cannot authenticate', async () => {
  const target = join(scratch(), 'audit.log');
  const { tee, forwarded } = collectingTee(target);
  const forged = record('suggest_for_ctf');

  tee.write(`${AUDIT_STREAM_PREFIX}${forged}\n`);
  tee.write(`${AUDIT_STREAM_PREFIX}${'0'.repeat(64)} ${forged}\n`);
  tee.write(tagged(forged, randomBytes(AUDIT_KEY_BYTES)));
  tee.write(`${AUDIT_STREAM_PREFIX}${auditRecordTag(KEY, record('run_tool'))} ${forged}\n`);
  await endOf(tee);

  assert.deepEqual(readLines(target), []);
  assert.equal(forwarded.length, 4);
  for (const line of forwarded) assert.match(line, /^Rejected unauthenticated audit record: /);
});

test('the stderr tee rejects a replayed or unsequenced record', async () => {
  const target = join(scratch(), 'audit.log');
  const { tee, forwarded } = collectingTee(target);

  tee.write(tagged(record('guided_assessment', 1)));
  tee.write(tagged(record('run_tool', 2)));
  tee.write(tagged(record('guided_assessment', 1)));
  tee.write(tagged(JSON.stringify({ event: 'tool_call', tool: 'guided_assessment' })));
  await endOf(tee);

  assert.deepEqual(readLines(target), [record('guided_assessment', 1), record('run_tool', 2)]);
  assert.deepEqual(
    forwarded.map((line) => line.slice(0, line.indexOf(':'))),
    ['Rejected replayed audit record', 'Rejected malformed audit record'],
  );
});

test('the stderr tee refuses to start without a full-length session key', () => {
  const sink = createAuditSink({ path: join(scratch(), 'audit.log') });
  assert.throws(() => createAuditStderrTee({ write: () => {} }, sink), /session key/);
  assert.throws(() => createAuditStderrTee({ write: () => {} }, sink, Buffer.alloc(16)), /session key/);
});

// A host log holding only a stale non-advisor record, so the guard starts out denying.
const guardHarness = () => {
  const home = scratch();
  const stateDir = join(home, '.local', 'state', 'cybersec-tools-mcp');
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, 'guard-session'), '2026-09-10T18:00:00.000Z\n');

  const { CYBERSEC_MCP_AUDIT_LOG: _log, CYBERSEC_AGENT_GUARD: _guard, ...inherited } = process.env;
  const env = { ...inherited, HOME: home, XDG_STATE_HOME: join(home, '.local', 'state') };
  const run = () =>
    execFileSync('bash', [join(ROOT, 'scripts', 'agent-guard.sh'), 'pre-bash'], {
      env,
      input: JSON.stringify({ tool_input: { command: 'nmap -sV 10.0.0.1' } }),
      encoding: 'utf8',
    });

  const sink = createAuditSink({ path: join(stateDir, 'audit.log') });
  sink.write(JSON.stringify({ ts: '2026-09-10T17:00:00.000Z', event: 'tool_call', tool: 'run_tool' }));
  return { sink, run };
};

// The regression this guards: a sandboxed server logs inside the VM, so without
// the tee scripts/agent-guard.sh either finds no clearance at all or blocks
// every governed tool for the rest of the session.
test('a mirrored advisor call clears scripts/agent-guard.sh on the host', async () => {
  const { sink, run } = guardHarness();
  assert.match(run(), /"permissionDecision":"deny"/, 'stale, non-advisor records must not clear the guard');

  const tee = createAuditStderrTee({ write: () => {} }, sink, KEY);
  tee.write(tagged(record('guided_assessment', 1, '2026-09-10T19:30:00.000Z')));
  await endOf(tee);

  assert.equal(run().trim(), '', 'a mirrored guided_assessment call clears the guard');
});

// The host log is the guard's clearance source, so a record that anything else
// in the VM prints to the server's stderr must not clear it.
test('a forged advisor record does not clear scripts/agent-guard.sh', async () => {
  const { sink, run } = guardHarness();
  const forged = record('guided_assessment', 1, '2026-09-10T19:30:00.000Z');

  const tee = createAuditStderrTee({ write: () => {} }, sink, KEY);
  tee.write(`${AUDIT_STREAM_PREFIX}${forged}\n`);
  tee.write(tagged(forged, randomBytes(AUDIT_KEY_BYTES)));
  await endOf(tee);

  assert.match(run(), /"permissionDecision":"deny"/);
});

test('records mirrored by mcp_server/audit.py pass the tee verbatim', async () => {
  const dir = scratch();
  const guestLog = join(dir, 'guest-audit.log');
  const target = join(dir, 'host-audit.log');
  const { tee, forwarded } = collectingTee(target);

  const server = spawn(
    'python3',
    ['-c', 'from mcp_server.audit import log_tool_call; log_tool_call("guided_assessment", {}); log_tool_call("run_tool", {})'],
    {
      cwd: ROOT,
      env: {
        PATH: process.env.PATH,
        CYBERSEC_MCP_AUDIT_STREAM: '1',
        CYBERSEC_MCP_AUDIT_LOG: guestLog,
        [AUDIT_KEY_ENV]: KEY.toString('hex'),
      },
      stdio: ['ignore', 'ignore', 'pipe'],
    },
  );
  server.stderr.pipe(tee);
  await once(tee, 'finish');

  assert.deepEqual(forwarded, []);
  assert.deepEqual(readLines(target).map((line) => JSON.parse(line).tool), ['guided_assessment', 'run_tool']);
  // Verbatim, so scripts/verify_audit_chain.py can check the host copy.
  assert.deepEqual(readLines(target), readLines(guestLog));
});

// Stands in for the docker CLI: resolves name-only --env flags from its own
// environment as the real CLI does, and runs guest-server.py as the server.
const FAKE_DOCKER = `
const { appendFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');

const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify({ args, key: process.env.${AUDIT_KEY_ENV} ?? null }) + '\\n');
if (args[0] !== 'exec') {
  process.stdout.write({ info: '{"kata":{}}', image: 'sha256:fake', run: 'fake-container' }[args[0]] ?? '');
  process.exit(0);
}

const guestEnv = {
  PATH: process.env.PATH,
  PYTHONPATH: process.env.FAKE_GUEST_PYTHONPATH,
  CYBERSEC_MCP_AUDIT_STREAM: '1',
  CYBERSEC_MCP_AUDIT_LOG: process.env.FAKE_GUEST_AUDIT_LOG,
};
args.forEach((arg, index) => {
  if (arg !== '--env') return;
  const [name, ...value] = args[index + 1].split('=');
  guestEnv[name] = value.length ? value.join('=') : process.env[name];
});
const server = spawnSync('python3', [process.env.FAKE_GUEST_SERVER, process.env.FAKE_GUEST_TOOL], {
  env: guestEnv,
  stdio: ['ignore', 'inherit', 'inherit'],
});
process.exit(server.status ?? 1);
`;

const GUEST_SERVER = `
import subprocess
import sys

from mcp_server.audit import log_tool_call

log_tool_call("guided_assessment", {})
subprocess.run([sys.executable, sys.argv[1]], check=True)
`;

// A tool the server runs: it shares the server's stderr and tags a forged
// advisor record with whatever key it can find in its environment.
const GUEST_TOOL = `
import hashlib
import hmac
import json
import os
import sys

key = bytes.fromhex(os.environ.get("${AUDIT_KEY_ENV}") or "00" * 32)
line = json.dumps({"ts": "2026-09-10T19:30:00.000Z", "event": "tool_call", "tool": "suggest_for_ctf",
                   "chain": "f" * 32, "seq": 1, "prev": "0" * 64})
print("${AUDIT_STREAM_PREFIX}" + hmac.new(key, line.encode(), hashlib.sha256).hexdigest() + " " + line, file=sys.stderr)
`;

test('the launcher hands the audit key to the server process alone', { timeout: 60_000 }, async () => {
  const dir = scratch();
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  writeFileSync(join(dir, 'fake-docker.cjs'), FAKE_DOCKER);
  writeFileSync(join(bin, 'docker'), `#!/bin/sh\nexec '${process.execPath}' '${join(dir, 'fake-docker.cjs')}' "$@"\n`);
  chmodSync(join(bin, 'docker'), 0o755);
  writeFileSync(join(dir, 'guest-server.py'), GUEST_SERVER);
  writeFileSync(join(dir, 'guest-tool.py'), GUEST_TOOL);

  const hostLog = join(dir, 'host-audit.log');
  const dockerLog = join(dir, 'docker-calls.jsonl');
  const launcher = spawn(process.execPath, [join(import.meta.dirname, 'mcp.mjs')], {
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      HOME: dir,
      CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME: '1',
      CYBERSEC_MCP_AUDIT_LOG: hostLog,
      FAKE_DOCKER_LOG: dockerLog,
      FAKE_GUEST_AUDIT_LOG: join(dir, 'guest-audit.log'),
      FAKE_GUEST_PYTHONPATH: ROOT,
      FAKE_GUEST_SERVER: join(dir, 'guest-server.py'),
      FAKE_GUEST_TOOL: join(dir, 'guest-tool.py'),
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  launcher.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  const [exitCode] = await once(launcher, 'close');
  assert.equal(exitCode, 0, stderr);

  const calls = readLines(dockerLog).map((line) => JSON.parse(line));
  const exec = calls.find((call) => call.args[0] === 'exec');
  assert.match(exec?.key ?? '', /^[0-9a-f]{64}$/, 'docker exec resolves the key from its own environment');
  const flag = exec.args.indexOf('--env');
  assert.deepEqual(exec.args.slice(flag, flag + 2), ['--env', AUDIT_KEY_ENV], 'passed by name only');
  for (const call of calls) {
    assert.equal(call.args.join(' ').includes(exec.key), false, `docker ${call.args[0]}: key on its command line`);
    if (call === exec) continue;
    assert.equal(call.key, null, `docker ${call.args[0]}: key in its environment`);
    assert.equal(call.args.join(' ').includes(AUDIT_KEY_ENV), false, `docker ${call.args[0]}: key forwarded`);
  }

  assert.deepEqual(readLines(hostLog).map((line) => JSON.parse(line).tool), ['guided_assessment']);
  assert.match(stderr, /Rejected unauthenticated audit record: .*suggest_for_ctf/);
});
