/**
 * smoke.mjs — drive a real MCP handshake against a launched server.
 *
 * Unit tests cover argument construction; this covers the parts only a running
 * server can prove: the image starts, the stdio bridge carries JSON-RPC, tools
 * are registered, and audit records reach the host log.
 *
 * Usage:
 *   node sandbox/smoke.mjs                        # sandbox path (needs an engine)
 *   node sandbox/smoke.mjs bash scripts/mcp-launch.sh --local
 *
 * A host without KVM can still exercise the sandbox path with
 * CYBERSEC_SANDBOX_RUNTIME=runc CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1 — that
 * tests the plumbing, not the isolation.
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const TIMEOUT_MS = Number(process.env.CYBERSEC_SMOKE_TIMEOUT_MS ?? 120_000);
const [command, ...args] = process.argv.slice(2).length
  ? process.argv.slice(2)
  : ['node', join(import.meta.dirname, 'mcp.mjs')];

const auditLog =
  process.env.CYBERSEC_MCP_AUDIT_LOG ?? join(mkdtempSync(join(tmpdir(), 'cybersec-smoke-')), 'audit.log');
const child = spawn(command, args, {
  stdio: ['pipe', 'pipe', 'inherit'],
  env: { ...process.env, CYBERSEC_MCP_AUDIT_LOG: auditLog },
});

const pending = new Map();
let buffered = '';

child.stdout.on('data', (chunk) => {
  buffered += chunk.toString('utf8');
  const lines = buffered.split('\n');
  buffered = lines.pop() ?? '';
  for (const line of lines) {
    if (!line.trim()) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue; // Not JSON-RPC; the transport tolerates noise on stdout.
    }
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      waiter(message);
    }
  }
});

let nextId = 0;
const request = (method, params) =>
  new Promise((resolve, reject) => {
    const id = (nextId += 1);
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${method}`)), TIMEOUT_MS);
    pending.set(id, (message) => {
      clearTimeout(timer);
      if (message.error) reject(new Error(`${method} failed: ${JSON.stringify(message.error)}`));
      else resolve(message.result);
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });

const notify = (method, params) =>
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);

const fail = (message) => {
  console.error(`smoke: ${message}`);
  if (child.exitCode !== null || child.signalCode !== null) process.exit(1);
  // SIGTERM lets the launcher remove its VM; SIGKILL alone would orphan the container.
  child.once('close', () => process.exit(1));
  child.kill('SIGTERM');
  setTimeout(() => child.kill('SIGKILL'), 15_000).unref();
};

child.on('error', (error) => fail(`could not launch ${command}: ${error.message}`));
child.stdin.on('error', (error) => fail(`server closed its input: ${error.message}`));

try {
  const initialized = await request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'cybersec-smoke', version: '0' },
  });
  const serverName = initialized?.serverInfo?.name ?? '(unnamed)';
  notify('notifications/initialized', {});

  const listed = await request('tools/list', {});
  const tools = listed?.tools ?? [];
  if (tools.length === 0) throw new Error('server registered no tools');
  const names = tools.map((tool) => tool.name);
  for (const required of ['guided_assessment', 'run_tool', 'list_tools']) {
    if (!names.includes(required)) throw new Error(`tool '${required}' missing from tools/list`);
  }

  child.stdin.end();
  const exitCode = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not exit after stdin closed')), TIMEOUT_MS);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });

  const records = readFileSync(auditLog, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
  if (!records.some((record) => record.event === 'server_start')) {
    throw new Error(`no server_start record reached the host audit log (${auditLog})`);
  }

  console.log(
    `smoke: OK — ${serverName}, ${tools.length} tools, ${records.length} audit records, exit ${exitCode}`,
  );
  console.log(`smoke: audit log at ${auditLog}`);
} catch (error) {
  fail(error.message);
}
