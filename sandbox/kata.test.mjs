import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  appendTail,
  assertVmBoundary,
  assertWorkspaceUsable,
  buildExecEnv,
  buildRunArgs,
  isKataRuntime,
  registerShutdown,
  resolveOptions,
  selectRuntime,
  WORKTREE_PATH,
} from './kata.mjs';

const flagValues = (args, flag) =>
  args.reduce((found, arg, index) => (arg === flag ? [...found, args[index + 1]] : found), []);

const baseOptions = (overrides = {}) => resolveOptions({ image: 'toolkit:test', ...overrides }, {});

test('selectRuntime prefers a plain kata runtime over other kata variants', () => {
  const runtimes = { runc: {}, 'kata-qemu': {}, kata: {}, 'io.containerd.runc.v2': {} };
  assert.equal(selectRuntime(runtimes), 'kata');
});

test('selectRuntime accepts any registered kata variant', () => {
  assert.equal(selectRuntime({ runc: {}, 'kata-clh': {} }), 'kata-clh');
});

test('selectRuntime honours an explicitly requested runtime', () => {
  assert.equal(selectRuntime({ runc: {}, 'kata-fc': {} }, 'kata-fc'), 'kata-fc');
});

test('selectRuntime rejects a requested runtime Docker does not know', () => {
  assert.throws(() => selectRuntime({ runc: {} }, 'kata'), /not registered with Docker/);
});

test('selectRuntime refuses a non-Kata runtime that would share the host kernel', () => {
  assert.throws(() => selectRuntime({ runc: {}, kata: {} }, 'runc'), /not a Kata runtime/);
  assert.equal(selectRuntime({ runc: {} }, 'runc', { allowUnsafe: true }), 'runc');
});

test('isKataRuntime recognises the names Kata registers under', () => {
  for (const name of ['kata', 'kata-qemu', 'kata-runtime', 'io.containerd.kata.v2']) {
    assert.equal(isKataRuntime(name), true, name);
  }
  for (const name of ['runc', 'crun', 'io.containerd.runc.v2', undefined]) {
    assert.equal(isKataRuntime(name), false, String(name));
  }
});

test('assertVmBoundary rejects a runtime that shares the host kernel', () => {
  // A kata-named runc runtime yields a container with the host's boot id.
  assert.throws(() => assertVmBoundary('bootid-xyz', 'bootid-xyz', 'kata-impostor'), /no VM boundary/);
});

test('assertVmBoundary accepts a guest that booted its own kernel', () => {
  assert.doesNotThrow(() => assertVmBoundary('guest-bootid', 'host-bootid', 'kata'));
});

test('assertVmBoundary fails closed when a boot id is unreadable', () => {
  assert.throws(() => assertVmBoundary('', 'host-bootid', 'kata'), /could not confirm a VM boundary/);
  assert.throws(() => assertVmBoundary('guest-bootid', '', 'kata'), /could not confirm a VM boundary/);
});

test('resolveOptions keeps the unsafe-runtime opt-in off unless set to 1', () => {
  assert.equal(resolveOptions({}, {}).allowUnsafeRuntime, false);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME: '0' }).allowUnsafeRuntime, false);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME: 'true' }).allowUnsafeRuntime, false);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME: '1' }).allowUnsafeRuntime, true);
});

test('selectRuntime fails closed when no kata runtime is registered', () => {
  assert.throws(() => selectRuntime({ runc: {}, 'io.containerd.runc.v2': {} }), /No Kata runtime/);
  assert.throws(() => selectRuntime({}), /docs\/SANDBOX\.md/);
});

test('resolveOptions falls back to the environment, then to defaults', () => {
  const resolved = resolveOptions(
    {},
    { CYBERSEC_SANDBOX_IMAGE: 'from-env:1', CYBERSEC_SANDBOX_MEMORY: '8g', CYBERSEC_SANDBOX_NETWORK: 'none' },
  );
  assert.equal(resolved.image, 'from-env:1');
  assert.equal(resolved.memory, '8g');
  assert.equal(resolved.network, 'none');
  assert.equal(resolved.user, '10001:10001');
  assert.equal(resolved.cpus, '2');
  assert.deepEqual(resolved.capAdd, []);
});

test('resolveOptions lets explicit options win over the environment', () => {
  const resolved = resolveOptions({ image: 'explicit:1' }, { CYBERSEC_SANDBOX_IMAGE: 'from-env:1' });
  assert.equal(resolved.image, 'explicit:1');
});

test('resolveOptions rejects a relative workspace path', () => {
  assert.throws(() => resolveOptions({ workspace: 'evidence' }, {}), /absolute path/);
});

test('assertWorkspaceUsable refuses the host root, including through a symlink', () => {
  const dir = mkdtempSync(join(tmpdir(), 'kata-ws-'));
  try {
    const link = join(dir, 'root-link');
    symlinkSync('/', link);
    assert.throws(() => assertWorkspaceUsable('/'), /host root/);
    assert.throws(() => assertWorkspaceUsable(link), /host root/);
    assert.doesNotThrow(() => assertWorkspaceUsable(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveOptions rejects a malformed capability', () => {
  assert.throws(() => resolveOptions({ capAdd: 'net_raw; rm -rf /' }, {}), /Invalid capability/);
  assert.deepEqual(resolveOptions({ capAdd: 'NET_RAW,NET_ADMIN' }, {}).capAdd, ['NET_RAW', 'NET_ADMIN']);
});

test('buildRunArgs pins the kata runtime and drops privileges', () => {
  const args = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });

  assert.deepEqual(flagValues(args, '--runtime'), ['kata']);
  assert.deepEqual(flagValues(args, '--cap-drop'), ['ALL']);
  assert.deepEqual(flagValues(args, '--security-opt'), ['no-new-privileges']);
  assert.deepEqual(flagValues(args, '--user'), ['10001:10001']);
  assert.deepEqual(flagValues(args, '--pids-limit'), ['512']);
  assert.deepEqual(args.slice(-3), ['sleep', 'toolkit:test', 'infinity']);
});

test('buildRunArgs exposes no host path unless a workspace is configured', () => {
  const args = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });
  assert.equal(args.includes('--volume'), false);

  const joined = args.join(' ');
  assert.equal(joined.includes('docker.sock'), false);
  assert.equal(joined.includes(process.env.HOME ?? '/root'), false);
});

test('buildRunArgs mounts only the configured workspace, honouring read-only', () => {
  const rw = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions({ workspace: '/srv/case' }), env: {} });
  assert.deepEqual(flagValues(rw, '--volume'), [`/srv/case:${WORKTREE_PATH}`]);

  const ro = baseOptions({ workspace: '/srv/case', workspaceReadonly: '1' });
  assert.deepEqual(flagValues(buildRunArgs({ name: 'sbx', runtime: 'kata', options: ro, env: {} }), '--volume'), [
    `/srv/case:${WORKTREE_PATH}:ro`,
  ]);
});

test('buildRunArgs forwards the MCP policy environment into the VM', () => {
  const args = buildRunArgs({
    name: 'sbx',
    runtime: 'kata',
    options: baseOptions(),
    env: { CYBERSEC_MCP_ALLOW_EXTERNAL: '0', CYBERSEC_MCP_ALLOW_SCRIPTS: '0' },
  });
  assert.deepEqual(flagValues(args, '--env'), ['CYBERSEC_MCP_ALLOW_EXTERNAL=0', 'CYBERSEC_MCP_ALLOW_SCRIPTS=0']);
});

test('buildRunArgs adds requested capabilities and a network only when set', () => {
  const plain = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });
  assert.equal(plain.includes('--cap-add'), false);
  assert.equal(plain.includes('--network'), false);

  const tuned = baseOptions({ capAdd: 'NET_RAW', network: 'none' });
  const args = buildRunArgs({ name: 'sbx', runtime: 'kata', options: tuned, env: {} });
  assert.deepEqual(flagValues(args, '--cap-add'), ['NET_RAW']);
  assert.deepEqual(flagValues(args, '--network'), ['none']);
});

test('buildExecEnv passes exec-scoped variables by name, values only through the CLI environment', () => {
  const secret = 'ab'.repeat(32);
  const { args, env } = buildExecEnv({ CYBERSEC_MCP_AUDIT_KEY: secret }, { PATH: '/usr/bin' });

  assert.deepEqual(args, ['--env', 'CYBERSEC_MCP_AUDIT_KEY']);
  assert.equal(args.some((arg) => arg.includes(secret)), false);
  assert.deepEqual(env, { PATH: '/usr/bin', CYBERSEC_MCP_AUDIT_KEY: secret });
  assert.deepEqual(buildExecEnv(undefined, { PATH: '/usr/bin' }), { args: [], env: { PATH: '/usr/bin' } });
});

test('buildExecEnv refuses names docker would misread and non-string values', () => {
  // NAME=value would put the value back on the command line; DOCKER_* would reconfigure the CLI.
  for (const name of ['NAME=value', '', '1ABC', 'WITH SPACE', 'DOCKER_HOST']) {
    assert.throws(() => buildExecEnv({ [name]: 'x' }, {}), /Invalid exec environment variable name/, name);
  }
  assert.throws(() => buildExecEnv({ CYBERSEC_MCP_AUDIT_KEY: 1 }, {}), /must be a string/);
});

const fakeProcess = (calls) => Object.assign(new EventEmitter(), { exit: (code) => calls.push(`exit ${code}`) });

test('registerShutdown waits for a booting VM before removing it on a signal', async () => {
  const calls = [];
  const proc = fakeProcess(calls);
  let finishBoot;
  const booting = new Promise((resolve) => {
    finishBoot = resolve;
  });
  registerShutdown(() => calls.push('cleanup'), () => booting, proc);

  proc.emit('SIGTERM', 'SIGTERM');
  await new Promise(setImmediate);
  assert.deepEqual(calls, [], 'the container may not exist yet, so nothing is removed');

  finishBoot();
  await new Promise(setImmediate);
  assert.deepEqual(calls, ['cleanup', 'exit 143']);
});

test('registerShutdown tears down at once when nothing is booting, and unregisters cleanly', () => {
  const calls = [];
  const proc = fakeProcess(calls);
  const unregister = registerShutdown(() => calls.push('cleanup'), undefined, proc);

  proc.emit('SIGINT', 'SIGINT');
  assert.deepEqual(calls, ['cleanup', 'exit 130']);

  unregister();
  assert.equal(proc.listenerCount('SIGTERM') + proc.listenerCount('exit'), 0);
});

test('appendTail keeps the trailing window of streamed output', () => {
  assert.equal(appendTail('', 'abc', 4), 'abc');
  assert.equal(appendTail('abc', 'de', 4), 'bcde');
  assert.equal(appendTail('', 'abcdef', 3), 'def');
});
