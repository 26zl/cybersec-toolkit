import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  appendTail,
  buildRunArgs,
  isKataRuntime,
  resolveEngine,
  resolveOptions,
  selectPodmanRuntime,
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

test('resolveEngine prefers an explicit engine, then what is on PATH', async () => {
  const onPath = (present) => async (name) => present.includes(name);

  assert.equal(await resolveEngine('podman', onPath(['docker', 'podman'])), 'podman');
  assert.equal(await resolveEngine(undefined, onPath(['podman'])), 'podman');
  assert.equal(await resolveEngine(undefined, onPath(['docker', 'podman'])), 'docker');
  await assert.rejects(() => resolveEngine('nerdctl', onPath(['nerdctl'])), /Unknown container engine/);
  await assert.rejects(() => resolveEngine('docker', onPath(['podman'])), /not found on PATH/);
  await assert.rejects(() => resolveEngine(undefined, onPath([])), /Neither docker nor podman/);
});

test('selectPodmanRuntime needs an explicit Kata runtime name', () => {
  assert.throws(() => selectPodmanRuntime(undefined), /set CYBERSEC_SANDBOX_RUNTIME/);
  assert.throws(() => selectPodmanRuntime('crun'), /not a Kata runtime/);
  assert.equal(selectPodmanRuntime('kata'), 'kata');
  assert.equal(selectPodmanRuntime('crun', { allowUnsafe: true }), 'crun');
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

test('appendTail keeps the trailing window of streamed output', () => {
  assert.equal(appendTail('', 'abc', 4), 'abc');
  assert.equal(appendTail('abc', 'de', 4), 'bcde');
  assert.equal(appendTail('', 'abcdef', 3), 'def');
});
