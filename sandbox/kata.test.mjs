import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

import {
  appendTail,
  assertImageCurrent,
  assertImagePresent,
  assertVmBoundary,
  assertWorkspaceUsable,
  buildExecEnv,
  buildRunArgs,
  isKataRuntime,
  launchFailureHint,
  SANDBOX_UNAVAILABLE,
  registerShutdown,
  resolveOptions,
  sandboxModeLabel,
  selectRuntime,
  WORKTREE_PATH,
} from './kata.mjs';

test('sandboxModeLabel claims kata only for a checked Kata VM', () => {
  assert.equal(sandboxModeLabel('kata', false), 'kata');
  // The unsafe opt-in skips the boot-ID check, so the boundary is unverified.
  assert.equal(sandboxModeLabel('kata', true), 'unsafe:kata');
  assert.equal(sandboxModeLabel('runc', true), 'unsafe:runc');
});

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

test('resolveOptions mounts the workspace read-only for any true spelling', () => {
  assert.equal(resolveOptions({ workspaceReadonly: true }, {}).workspaceReadonly, true);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_WORKSPACE_RO: 'true' }).workspaceReadonly, true);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_WORKSPACE_RO: '1' }).workspaceReadonly, true);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_WORKSPACE_RO: 'ON' }).workspaceReadonly, true);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_WORKSPACE_RO: 'off' }).workspaceReadonly, false);
  assert.equal(resolveOptions({}, {}).workspaceReadonly, false);
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

test('assertWorkspaceUsable refuses system trees, $HOME and the checkout', () => {
  // Parents of Docker/Kata state (/var, /run) would expose the runtime itself to the guest.
  for (const tree of ['/etc', '/usr', '/var', '/run', '/boot']) {
    if (existsSync(tree)) assert.throws(() => assertWorkspaceUsable(tree), /system directory/, tree);
  }
  assert.throws(() => assertWorkspaceUsable(homedir()), /home directory/);
  assert.throws(() => assertWorkspaceUsable(resolve(import.meta.dirname, '..')), /checkout/);
  // A dedicated directory outside those trees is fine.
  const dir = mkdtempSync(join(tmpdir(), 'kata-ws-ok-'));
  try {
    assert.doesNotThrow(() => assertWorkspaceUsable(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('assertWorkspaceUsable refuses a directory inside the checkout', () => {
  // The client reads instruction files, skills and MCP settings from the project tree.
  assert.throws(() => assertWorkspaceUsable(resolve(import.meta.dirname)), /inside the toolkit checkout/);
});

test('a scope adds NET_ADMIN to the bounding set and nothing else changes', () => {
  const plain = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });
  const scoped = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions({ scope: '/srv/scope.json' }), env: {} });
  assert.deepEqual(flagValues(scoped, '--cap-add'), ['NET_ADMIN']);
  assert.deepEqual(flagValues(scoped, '--cap-drop'), ['ALL']);
  assert.deepEqual(flagValues(scoped, '--user'), ['10001:10001']);
  assert.deepEqual(flagValues(scoped, '--security-opt'), ['no-new-privileges']);
  assert.deepEqual(
    scoped.filter((arg) => arg !== '--cap-add' && arg !== 'NET_ADMIN'),
    plain,
  );
  // Asked for twice, it is passed once.
  const both = baseOptions({ scope: '/srv/scope.json', capAdd: 'NET_ADMIN,NET_RAW' });
  assert.deepEqual(flagValues(buildRunArgs({ name: 'sbx', runtime: 'kata', options: both, env: {} }), '--cap-add'), [
    'NET_ADMIN',
    'NET_RAW',
  ]);
  // Names in a scope are pinned by Docker at creation, since /etc/hosts is read-only inside.
  const pinned = buildRunArgs({
    name: 'sbx',
    runtime: 'kata',
    options: baseOptions({ scope: '/srv/scope.json' }),
    env: {},
    hostArgs: ['--add-host', 'web.example:198.51.100.7'],
  });
  assert.deepEqual(flagValues(pinned, '--add-host'), ['web.example:198.51.100.7']);
  assert.equal(scoped.includes('--add-host'), false);
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_SCOPE: '/srv/scope.json' }).scope, '/srv/scope.json');
  assert.equal(resolveOptions({}, {}).scope, undefined);
});

test('assertImageCurrent refuses an image built from other server sources', () => {
  const label = { 'cybersec.sandbox.source_hash': 'aaaa' };
  assert.doesNotThrow(() => assertImageCurrent(label, 'aaaa', 'img'));
  assert.throws(() => assertImageCurrent(label, 'bbbb', 'img'), /older server and policy code.*make sandbox-image/);
  // An image without the label was built before the check existed.
  assert.throws(() => assertImageCurrent({}, 'bbbb', 'img'), /not built from this checkout/);
  assert.throws(() => assertImageCurrent(null, 'bbbb', 'img'), /not built from this checkout/);
  // The operator can accept it, and a hash that cannot be computed decides nothing.
  assert.doesNotThrow(() => assertImageCurrent(label, 'bbbb', 'img', true));
  assert.doesNotThrow(() => assertImageCurrent(label, '', 'img'));
  assert.equal(resolveOptions({}, { CYBERSEC_SANDBOX_ALLOW_STALE_IMAGE: '1' }).allowStaleImage, true);
  assert.equal(resolveOptions({}, {}).allowStaleImage, false);
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
  assert.ok(args.includes('--init'), 'an init reaps orphaned processes');
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
  assert.equal(rw.includes('--volume'), false);
  assert.deepEqual(flagValues(rw, '--mount'), [`type=bind,src=/srv/case,dst=${WORKTREE_PATH}`]);

  const ro = baseOptions({ workspace: '/srv/case', workspaceReadonly: '1' });
  assert.deepEqual(flagValues(buildRunArgs({ name: 'sbx', runtime: 'kata', options: ro, env: {} }), '--mount'), [
    `type=bind,src=/srv/case,dst=${WORKTREE_PATH},readonly`,
  ]);
});

test('buildRunArgs keeps a colon in the workspace path and refuses a comma or control character', () => {
  const colon = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions({ workspace: '/srv/acme:2024' }), env: {} });
  assert.deepEqual(flagValues(colon, '--mount'), [`type=bind,src=/srv/acme:2024,dst=${WORKTREE_PATH}`]);
  for (const bad of ['/srv/a,b', '/srv/a\nb']) {
    const options = baseOptions({ workspace: bad });
    assert.throws(() => buildRunArgs({ name: 'sbx', runtime: 'kata', options, env: {} }), /cannot be mounted/);
  }
});

test('buildRunArgs never lets docker pull a substitute image', () => {
  const args = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });
  assert.deepEqual(flagValues(args, '--pull'), ['never']);
});

test('resolveOptions rejects values that would change docker flags or tmpfs options', () => {
  const bad = (key, value, pattern) => assert.throws(() => resolveOptions({ [key]: value }, {}), pattern, `${key}=${value}`);
  bad('user', 'root', /CYBERSEC_SANDBOX_USER/);
  bad('user', '0:0', /CYBERSEC_SANDBOX_USER/);
  bad('user', 'nobody --privileged', /CYBERSEC_SANDBOX_USER/);
  bad('memory', '2g --privileged', /CYBERSEC_SANDBOX_MEMORY/);
  bad('user', '1000,exec', /CYBERSEC_SANDBOX_USER/);
  bad('scratchSize', '2g,suid', /CYBERSEC_SANDBOX_SCRATCH_SIZE/);
  bad('memory', '2g --privileged', /CYBERSEC_SANDBOX_MEMORY/);
  bad('cpus', 'two', /CYBERSEC_SANDBOX_CPUS/);
  bad('pidsLimit', '-1', /CYBERSEC_SANDBOX_PIDS_LIMIT/);
  assert.equal(resolveOptions({ user: '1000:1000', memory: '512M', cpus: '1.5' }, {}).user, '1000:1000');
});

test('resolveOptions accepts the size and user spellings docker accepts', () => {
  for (const memory of ['1.5g', '512MiB', '2GB', '2t']) assert.equal(resolveOptions({ memory }, {}).memory, memory);
  assert.equal(resolveOptions({ scratchSize: '1.5g' }, {}).scratchSize, '1.5g');
  assert.equal(resolveOptions({ user: 'nobody' }, {}).user, 'nobody');
  assert.equal(resolveOptions({ user: 'toolkit:toolkit' }, {}).user, 'toolkit:toolkit');
});

test('assertWorkspaceUsable accepts a sibling of the scope file and of a custom audit log, refuses their directories', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kata-sib-')));
  try {
    const cases = join(root, 'cases');
    const work = join(cases, 'work');
    mkdirSync(work, { recursive: true });
    const opts = { home: join(root, 'home'), env: { CYBERSEC_MCP_AUDIT_LOG: join(cases, 'audit.log') }, scope: join(cases, 'scope.json') };
    assert.equal(assertWorkspaceUsable(work, opts), work);
    assert.throws(() => assertWorkspaceUsable(cases, opts), /overlaps the (directory of the scope file|host audit log directory)/);
    assert.throws(() => assertWorkspaceUsable(root, opts), /overlaps the (directory of the scope file|host audit log directory)/);
    const audit = { home: opts.home, env: opts.env };
    assert.equal(assertWorkspaceUsable(work, audit), work);
    assert.throws(() => assertWorkspaceUsable(cases, audit), /audit log directory/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('assertWorkspaceUsable accepts a workspace under a directory a listed symlink resolves to', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kata-run-')));
  try {
    const run = join(root, 'run');
    const usb = join(run, 'media', 'u', 'usb');
    mkdirSync(usb, { recursive: true });
    mkdirSync(join(run, 'docker'));
    symlinkSync(run, join(root, 'var-run'));
    const trees = [join(run, 'docker'), join(run, 'containerd')];
    assert.equal(assertWorkspaceUsable(usb, { trees }), usb);
    assert.throws(() => assertWorkspaceUsable(join(run, 'docker'), { trees }), /system directory/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('assertWorkspaceUsable protects scope and audit files reached through final symlinks', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kata-policy-link-')));
  try {
    const aliases = join(root, 'aliases');
    const protectedFiles = join(root, 'protected');
    const work = join(root, 'case');
    for (const dir of [aliases, protectedFiles, work]) mkdirSync(dir);
    for (const filename of ['scope.json', 'audit.log']) {
      writeFileSync(join(protectedFiles, filename), '{}');
      symlinkSync(join(protectedFiles, filename), join(aliases, filename));
    }
    for (const opts of [
      { scope: join(aliases, 'scope.json'), env: {} },
      { env: { CYBERSEC_MCP_AUDIT_LOG: join(aliases, 'audit.log') } },
    ]) {
      const options = { ...opts, home: join(root, 'home'), trees: [] };
      assert.throws(() => assertWorkspaceUsable(protectedFiles, options), /overlaps the (directory of the scope file|host audit log directory)/);
      assert.throws(() => assertWorkspaceUsable(aliases, options), /overlaps the (directory of the scope file|host audit log directory)/);
      assert.equal(assertWorkspaceUsable(work, options), work);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('assertWorkspaceUsable refuses the audit directory, the scope directory and credential stores', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kata-home-')));
  try {
    const home = join(root, 'home');
    const audit = join(root, 'audit');
    const scopeDir = join(root, 'scope');
    for (const dir of [join(home, '.ssh', 'keys'), join(home, '.local/state/cybersec-tools-mcp'), join(home, 'cases'), audit, scopeDir]) {
      mkdirSync(dir, { recursive: true });
    }
    const opts = { home, env: { HOME: home, CYBERSEC_MCP_AUDIT_LOG: join(audit, 'audit.log') }, scope: join(scopeDir, 'scope.json') };
    assert.throws(() => assertWorkspaceUsable(join(home, '.ssh'), opts), /protected directory/);
    assert.throws(() => assertWorkspaceUsable(join(home, '.ssh', 'keys'), opts), /protected directory/);
    assert.throws(() => assertWorkspaceUsable(join(home, '.local/state/cybersec-tools-mcp'), opts), /protected directory|audit log/);
    assert.throws(() => assertWorkspaceUsable(audit, opts), /audit log directory/);
    assert.throws(() => assertWorkspaceUsable(scopeDir, opts), /scope file/);
    assert.throws(() => assertWorkspaceUsable(home, opts), /home directory/);
    assert.equal(assertWorkspaceUsable(join(home, 'cases'), opts), join(home, 'cases'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('assertWorkspaceUsable follows symlinks to a system tree and returns the resolved path', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'kata-tree-')));
  try {
    const tree = join(root, 'state');
    const via = join(root, 'alias');
    const link = join(root, 'link');
    mkdirSync(tree);
    symlinkSync(tree, via);
    symlinkSync(tree, link);
    // The configured tree is itself a symlink: the workspace is its target.
    assert.throws(() => assertWorkspaceUsable(tree, { trees: [via] }), /system directory/);
    // The workspace is a symlink to the tree.
    assert.throws(() => assertWorkspaceUsable(link, { trees: [tree] }), /system directory/);
    const ok = join(root, 'case');
    mkdirSync(ok);
    const okLink = join(root, 'case-link');
    symlinkSync(ok, okLink);
    assert.equal(assertWorkspaceUsable(okLink, { trees: [tree] }), ok);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('registerShutdown still exits when a boot never settles', async () => {
  const calls = [];
  const proc = fakeProcess(calls);
  registerShutdown(() => calls.push('cleanup'), () => new Promise(() => {}), proc, 20);
  proc.emit('SIGTERM', 'SIGTERM');
  await new Promise((done) => setTimeout(done, 80));
  assert.deepEqual(calls, ['cleanup', 'exit 143']);
});

test('launchFailureHint offers host mode only for an unavailable sandbox', () => {
  const unavailable = Object.assign(new Error('no runtime'), { code: SANDBOX_UNAVAILABLE });
  assert.match(launchFailureHint(unavailable), /--local/);
  assert.doesNotMatch(launchFailureHint(new Error('Network scope could not be enforced')), /--local/);
  assert.match(launchFailureHint(new Error('overlaps')), /not a fault to bypass/);
});

// A docker stand-in on PATH: prints STDERR_TEXT and exits 1.
const withFailingDocker = async (stderrText, body) => {
  const dir = mkdtempSync(join(tmpdir(), 'kata-shim-'));
  const savedPath = process.env.PATH;
  try {
    writeFileSync(join(dir, 'docker'), `#!/bin/sh\necho "${stderrText}" >&2\nexit 1\n`);
    chmodSync(join(dir, 'docker'), 0o755);
    process.env.PATH = `${dir}:${savedPath}`;
    await body();
  } finally {
    process.env.PATH = savedPath;
    rmSync(dir, { recursive: true, force: true });
  }
};

test('assertImagePresent reports a missing image as such and any other docker failure verbatim', { skip: process.platform === 'win32' }, async () => {
  await withFailingDocker('Error: No such image: x', async () => {
    await assert.rejects(assertImagePresent('x', false), (error) => {
      assert.match(error.message, /not found.*make sandbox-image/);
      assert.equal(error.code, SANDBOX_UNAVAILABLE);
      return true;
    });
  });
  await withFailingDocker('permission denied while trying to connect to the docker socket', async () => {
    await assert.rejects(assertImagePresent('x', false), (error) => {
      assert.match(error.message, /permission denied/);
      assert.equal(error.code, SANDBOX_UNAVAILABLE);
      return true;
    });
  });
  await withFailingDocker('Cannot connect to the Docker daemon at unix:///var/run/docker.sock', async () => {
    await assert.rejects(assertImagePresent('x', false), (error) => {
      assert.equal(error.code, SANDBOX_UNAVAILABLE);
      assert.match(launchFailureHint(error), /--local/);
      return true;
    });
  });
  await withFailingDocker('some unrelated docker failure', async () => {
    await assert.rejects(assertImagePresent('x', false), (error) => error.code !== SANDBOX_UNAVAILABLE);
  });
});

test('.dockerignore keeps credentials and local environments out of the build context', () => {
  const lines = readFileSync(resolve(import.meta.dirname, '..', '.dockerignore'), 'utf8').split('\n');
  for (const pattern of ['**/.venv/', '**/*.key', '**/.npmrc', '**/.netrc', '**/id_rsa*', '**/.ssh/', '**/.aws/', 'docker-compose.override.yml']) {
    assert.ok(lines.includes(pattern), pattern);
  }
});

test('buildRunArgs forwards the MCP policy environment into the VM', () => {
  const args = buildRunArgs({
    name: 'sbx',
    runtime: 'kata',
    options: baseOptions(),
    env: { CYBERSEC_MCP_ALLOW_EXTERNAL: '0', CYBERSEC_MCP_ALLOW_SCRIPTS: '0' },
  });
  // Names only; values must not appear on the docker command line.
  assert.deepEqual(flagValues(args, '--env'), ['CYBERSEC_MCP_ALLOW_EXTERNAL', 'CYBERSEC_MCP_ALLOW_SCRIPTS']);
  assert.equal(args.some((a) => /^CYBERSEC_MCP_[A-Z_]+=/.test(a)), false);
});

test('buildRunArgs makes the root read-only and caps every writable path', () => {
  const tmpfs = (options) => flagValues(buildRunArgs({ name: 'sbx', runtime: 'kata', options, env: {} }), '--tmpfs');
  const args = buildRunArgs({ name: 'sbx', runtime: 'kata', options: baseOptions(), env: {} });
  assert.ok(args.includes('--read-only'));
  const scratch = tmpfs(baseOptions({ scratchSize: '256m' }));
  assert.deepEqual(scratch.map((s) => s.split(':')[0]), ['/tmp', '/var/tmp', '/home/toolkit', '/var/log/cybersec', WORKTREE_PATH]);
  assert.ok(scratch.every((s) => s.includes('size=256m') && s.includes('uid=10001')));
  // A mounted workspace is the operator's directory, not scratch space.
  assert.equal(tmpfs(baseOptions({ workspace: '/srv/case' })).some((s) => s.startsWith(`${WORKTREE_PATH}:`)), false);
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
