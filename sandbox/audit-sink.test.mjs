import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  AUDIT_STREAM_PREFIX,
  createAuditSink,
  createAuditStderrTee,
  isAuditRecord,
  resolveHostAuditPath,
  splitAuditLines,
} from './audit-sink.mjs';

const scratch = () => mkdtempSync(join(tmpdir(), 'cybersec-audit-'));
const record = (tool) => JSON.stringify({ ts: '2026-09-10T19:00:00.000Z', event: 'tool_call', tool });

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

test('the stderr tee persists records and forwards everything else', async () => {
  const target = join(scratch(), 'audit.log');
  const forwarded = [];
  const tee = createAuditStderrTee({ write: (line) => forwarded.push(line) }, createAuditSink({ path: target }));

  tee.write(`Starting MCP server\n${AUDIT_STREAM_PREFIX}${record('guided_assessment')}\n`);
  tee.write(`${AUDIT_STREAM_PREFIX}not-a-record\n`);
  await new Promise((done) => tee.end(done));

  assert.equal(readFileSync(target, 'utf8').trim(), record('guided_assessment'));
  assert.deepEqual(forwarded, ['Starting MCP server\n', 'not-a-record\n']);
});

// The regression this guards: a sandboxed server logs inside the VM, so without
// the tee scripts/agent-guard.sh either finds no clearance at all or blocks
// every governed tool for the rest of the session.
test('a mirrored advisor call clears scripts/agent-guard.sh on the host', async (t) => {
  const home = scratch();
  const stateDir = join(home, '.local', 'state', 'cybersec-tools-mcp');
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, 'guard-session'), '2026-09-10T18:00:00.000Z\n');

  const guard = join(import.meta.dirname, '..', 'scripts', 'agent-guard.sh');
  const env = { ...process.env, HOME: home, XDG_STATE_HOME: join(home, '.local', 'state') };
  const run = () =>
    execFileSync('bash', [guard, 'pre-bash'], {
      env,
      input: JSON.stringify({ tool_input: { command: 'nmap -sV 10.0.0.1' } }),
      encoding: 'utf8',
    });

  const sink = createAuditSink({ path: join(stateDir, 'audit.log') });
  sink.write(JSON.stringify({ ts: '2026-09-10T17:00:00.000Z', event: 'tool_call', tool: 'run_tool' }));
  assert.match(run(), /"permissionDecision":"deny"/, 'stale, non-advisor records must not clear the guard');

  const tee = createAuditStderrTee({ write: () => {} }, sink);
  tee.write(`${AUDIT_STREAM_PREFIX}${JSON.stringify({
    ts: '2026-09-10T19:30:00.000Z',
    event: 'tool_call',
    tool: 'guided_assessment',
  })}\n`);
  await new Promise((done) => tee.end(done));

  assert.equal(run().trim(), '', 'a mirrored guided_assessment call clears the guard');
});
