/**
 * kata.mjs — Kata Containers sandbox provider for Sandcastle.
 *
 * Sandcastle's bundled Docker provider cannot select an alternative OCI runtime,
 * so its containers share the host kernel. This provider drives the docker or
 * podman CLI but pins a Kata runtime, which puts a hardware-virtualized
 * boundary between security tooling and the host.
 *
 * The returned provider satisfies Sandcastle's isolated-provider contract, so it
 * can be handed to run()/createSandbox() for agent orchestration or driven
 * directly, as sandbox/mcp.mjs does for the stdio MCP transport.
 *
 * See docs/SANDBOX.md for host prerequisites and configuration.
 */

import { execFile, execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createInterface } from 'node:readline';

import { createIsolatedSandboxProvider } from '@ai-hero/sandcastle';

export const SANDBOX_LABEL_KEY = 'cybersec-toolkit.sandbox';
export const SANDBOX_LABEL_VALUE = 'kata';
export const WORKTREE_PATH = '/workspace';
export const DEFAULT_IMAGE = 'cybersec-toolkit-sandbox:latest';
export const BUILD_HINT =
  `docker build -f sandbox/Dockerfile -t ${DEFAULT_IMAGE} .`;

const DEFAULT_USER = '10001:10001';
const DEFAULT_MEMORY = '2g';
const DEFAULT_CPUS = '2';
const DEFAULT_PIDS_LIMIT = '512';
const MAX_TAIL_CHARS = 64 * 1024;
// Runtime names Kata registers under, most specific first.
const KATA_RUNTIME_PREFERENCE = ['kata', 'kata-runtime', 'kata-qemu', 'io.containerd.kata.v2'];

const asString = (value) => (value === undefined || value === null ? undefined : String(value));

/** Whether a runtime name denotes Kata, i.e. an actual VM boundary. */
export const isKataRuntime = (name) => /kata/i.test(name ?? '');

export const ENGINES = ['docker', 'podman'];

const assertKataRuntime = (name, allowUnsafe) => {
  // A non-Kata runtime is a namespace container sharing the host kernel — the
  // thing this provider exists to avoid — so it is never silently used.
  if (isKataRuntime(name) || allowUnsafe) return name;
  throw new Error(
    `Runtime '${name}' is not a Kata runtime: tools would share the host kernel with no VM boundary. ` +
      'Set CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1 to accept that deliberately (a CI smoke test, say).',
  );
};

/** Resolve the container engine, preferring an explicit choice over discovery. */
export const resolveEngine = async (configured, onPath = binaryOnPath) => {
  if (configured) {
    if (!ENGINES.includes(configured)) {
      throw new Error(`Unknown container engine '${configured}' (expected: ${ENGINES.join(' or ')}).`);
    }
    if (!(await onPath(configured))) throw new Error(`${configured} not found on PATH; see docs/SANDBOX.md.`);
    return configured;
  }
  for (const candidate of ENGINES) {
    if (await onPath(candidate)) return candidate;
  }
  throw new Error(`Neither ${ENGINES.join(' nor ')} found on PATH; see docs/SANDBOX.md.`);
};

/**
 * Pick the runtime for podman, which does not advertise its configured
 * runtimes the way `docker info` does, so the name has to be given.
 */
export const selectPodmanRuntime = (requested, { allowUnsafe = false } = {}) => {
  if (!requested) {
    throw new Error(
      'Podman does not advertise its configured runtimes; set CYBERSEC_SANDBOX_RUNTIME ' +
        '(the name from containers.conf, usually "kata"). See docs/SANDBOX.md.',
    );
  }
  return assertKataRuntime(requested, allowUnsafe);
};

const parseCapabilities = (raw) => {
  if (raw === undefined) return [];
  const caps = (Array.isArray(raw) ? raw : String(raw).split(',')).map((c) => c.trim()).filter(Boolean);
  for (const cap of caps) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(cap)) {
      throw new Error(`Invalid capability '${cap}': expected a name such as NET_RAW.`);
    }
  }
  return caps;
};

/** Merge explicit options with their environment fallbacks and defaults. */
export const resolveOptions = (options = {}, env = process.env) => {
  const pick = (value, name) => asString(value) ?? (env[name] ? String(env[name]) : undefined);

  const workspace = pick(options.workspace, 'CYBERSEC_SANDBOX_WORKSPACE');
  if (workspace !== undefined && !isAbsolute(workspace)) {
    throw new Error(`CYBERSEC_SANDBOX_WORKSPACE must be an absolute path, got '${workspace}'.`);
  }

  return {
    image: pick(options.image, 'CYBERSEC_SANDBOX_IMAGE') ?? DEFAULT_IMAGE,
    runtime: pick(options.runtime, 'CYBERSEC_SANDBOX_RUNTIME'),
    network: pick(options.network, 'CYBERSEC_SANDBOX_NETWORK'),
    user: pick(options.user, 'CYBERSEC_SANDBOX_USER') ?? DEFAULT_USER,
    memory: pick(options.memory, 'CYBERSEC_SANDBOX_MEMORY') ?? DEFAULT_MEMORY,
    cpus: pick(options.cpus, 'CYBERSEC_SANDBOX_CPUS') ?? DEFAULT_CPUS,
    pidsLimit: pick(options.pidsLimit, 'CYBERSEC_SANDBOX_PIDS_LIMIT') ?? DEFAULT_PIDS_LIMIT,
    capAdd: parseCapabilities(options.capAdd ?? env.CYBERSEC_SANDBOX_CAP_ADD),
    allowUnsafeRuntime: (pick(options.allowUnsafeRuntime, 'CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME') ?? '0') === '1',
    engine: pick(options.engine, 'CYBERSEC_SANDBOX_ENGINE'),
    workspace,
    workspaceReadonly: (pick(options.workspaceReadonly, 'CYBERSEC_SANDBOX_WORKSPACE_RO') ?? '0') === '1',
  };
};

/**
 * Pick the Kata runtime to launch under from `docker info` output.
 *
 * Kata registers under several names depending on how it was installed, so an
 * unrequested runtime is matched by pattern rather than assumed.
 */
export const selectRuntime = (runtimes, requested, { allowUnsafe = false } = {}) => {
  const names = Object.keys(runtimes ?? {});
  const available = names.join(', ') || 'none';

  if (requested) {
    if (!names.includes(requested)) {
      throw new Error(`Runtime '${requested}' is not registered with Docker (available: ${available}).`);
    }
    return assertKataRuntime(requested, allowUnsafe);
  }

  const kata = names.filter((name) => isKataRuntime(name)).sort();
  const chosen = KATA_RUNTIME_PREFERENCE.find((name) => kata.includes(name)) ?? kata[0];
  if (!chosen) {
    throw new Error(
      `No Kata runtime is registered with Docker (available: ${available}). ` +
        'Install Kata Containers and register it in /etc/docker/daemon.json, ' +
        'or set CYBERSEC_SANDBOX_RUNTIME. See docs/SANDBOX.md.',
    );
  }
  return chosen;
};

/** Build the `docker run` argument vector for an idle sandbox VM. */
export const buildRunArgs = ({ name, runtime, options, env }) => {
  const args = [
    'run',
    '--detach',
    '--rm',
    '--name',
    name,
    '--runtime',
    runtime,
    '--label',
    `${SANDBOX_LABEL_KEY}=${SANDBOX_LABEL_VALUE}`,
    '--user',
    options.user,
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    options.pidsLimit,
    '--memory',
    options.memory,
    '--cpus',
    options.cpus,
  ];

  for (const cap of options.capAdd) args.push('--cap-add', cap);
  if (options.network) args.push('--network', options.network);

  // The only host path the VM can see, and only when the operator names one.
  if (options.workspace) {
    args.push('--volume', `${options.workspace}:${WORKTREE_PATH}${options.workspaceReadonly ? ':ro' : ''}`);
  }

  for (const [key, value] of Object.entries(env ?? {})) args.push('--env', `${key}=${value}`);

  args.push('--workdir', WORKTREE_PATH, '--entrypoint', 'sleep', options.image, 'infinity');
  return args;
};

/** Append to a streamed-output tail, keeping at most `limit` trailing characters. */
export const appendTail = (tail, chunk, limit = MAX_TAIL_CHARS) => {
  const next = tail + chunk;
  return next.length > limit ? next.slice(next.length - limit) : next;
};

const binaryOnPath = (name) =>
  new Promise((resolve) => {
    execFile(name, ['--version'], (error) => resolve(!error || error.code !== 'ENOENT'));
  });

const engineExec = (engine, args, { maxBuffer = 10 * 1024 * 1024 } = {}) =>
  new Promise((resolve, reject) => {
    execFile(engine, args, { maxBuffer }, (error, stdout, stderr) => {
      if (!error) {
        resolve(stdout.toString());
        return;
      }
      if (error.code === 'ENOENT') {
        reject(new Error(`${engine} CLI not found on PATH; see docs/SANDBOX.md for host prerequisites.`));
        return;
      }
      reject(new Error(`${engine} ${args[0]} failed: ${stderr?.toString().trim() || error.message}`));
    });
  });

const readRuntimes = async (engine) => {
  const raw = await engineExec(engine, ['info', '--format', '{{json .Runtimes}}']);
  try {
    return JSON.parse(raw.trim() || '{}');
  } catch {
    throw new Error(`Could not parse the runtime list from 'docker info': ${raw.trim()}`);
  }
};

const assertImagePresent = async (engine, image) => {
  try {
    await engineExec(engine, ['image', 'inspect', image, '--format', '{{.Id}}']);
  } catch {
    throw new Error(`Sandbox image '${image}' not found. Build it with: ${BUILD_HINT}`);
  }
};

const assertWorkspaceUsable = (workspace) => {
  if (!workspace) return;
  let stats;
  try {
    stats = statSync(workspace);
  } catch {
    throw new Error(`Workspace '${workspace}' does not exist on the host.`);
  }
  if (!stats.isDirectory()) throw new Error(`Workspace '${workspace}' is not a directory.`);
};

/**
 * Remove the sandbox on abnormal exit.
 *
 * A container that outlives its launcher keeps a VM — and any target access it
 * was granted — alive, so teardown also runs from the exit and signal paths.
 */
const registerShutdown = (cleanup) => {
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const onExit = () => cleanup();
  const onSignal = (signal) => {
    cleanup();
    process.exit(signal === 'SIGINT' ? 130 : 143);
  };

  process.on('exit', onExit);
  for (const signal of signals) process.on(signal, onSignal);

  return () => {
    process.off('exit', onExit);
    for (const signal of signals) process.off(signal, onSignal);
  };
};

/**
 * Create a Kata sandbox provider.
 *
 * Options fall back to CYBERSEC_SANDBOX_* environment variables, then to
 * defaults documented in docs/SANDBOX.md.
 */
export const kata = (options = {}) => {
  const resolved = resolveOptions(options);

  return createIsolatedSandboxProvider({
    name: 'kata',
    env: options.env,
    create: async (createOptions) => {
      assertWorkspaceUsable(resolved.workspace);
      const engine = await resolveEngine(resolved.engine);
      const runtime =
        engine === 'podman'
          ? selectPodmanRuntime(resolved.runtime, { allowUnsafe: resolved.allowUnsafeRuntime })
          : selectRuntime(await readRuntimes(engine), resolved.runtime, { allowUnsafe: resolved.allowUnsafeRuntime });
      if (!isKataRuntime(runtime)) {
        process.stderr.write(`WARNING: sandbox runtime '${runtime}' is not Kata — tools share the host kernel.\n`);
      }
      await assertImagePresent(engine, resolved.image);

      const containerName = `cybersec-kata-${randomUUID()}`;
      await engineExec(
        engine,
        buildRunArgs({
          name: containerName,
          runtime,
          options: resolved,
          env: { ...options.env, ...createOptions.env },
        }),
      );

      let removed = false;
      const removeSync = () => {
        if (removed) return;
        removed = true;
        try {
          execFileSync(engine, ['rm', '--force', containerName], { stdio: 'ignore' });
        } catch {
          // Teardown is best-effort; the label allows a manual sweep.
        }
      };
      const unregisterShutdown = registerShutdown(removeSync);

      return {
        worktreePath: WORKTREE_PATH,

        exec: (command, opts = {}) =>
          new Promise((resolve, reject) => {
            const args = ['exec'];
            if (opts.stdin !== undefined) args.push('--interactive');
            // The image ships no sudo binary, so elevation is a uid switch.
            if (opts.sudo) args.push('--user', '0:0');
            if (opts.cwd) args.push('--workdir', opts.cwd);
            args.push(containerName, 'sh', '-c', command);

            const child = spawn(engine, args, {
              stdio: [opts.stdin !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
            });
            child.on('error', (error) => reject(new Error(`${engine} exec failed: ${error.message}`)));
            if (opts.stdin !== undefined) {
              child.stdin.write(opts.stdin);
              child.stdin.end();
            }

            let stdout = '';
            let stderr = '';
            if (opts.onLine) {
              const lines = createInterface({ input: child.stdout });
              lines.on('line', (line) => {
                stdout = appendTail(stdout, `${line}\n`);
                opts.onLine(line);
              });
            } else {
              child.stdout.on('data', (chunk) => {
                stdout = appendTail(stdout, chunk.toString());
              });
            }
            child.stderr.on('data', (chunk) => {
              stderr = appendTail(stderr, chunk.toString());
            });
            child.on('close', (code) => resolve({ stdout, stderr, exitCode: code ?? 0 }));
          }),

        interactiveExec: (args, opts) =>
          new Promise((resolve, reject) => {
            const execArgs = ['exec'];
            execArgs.push('isTTY' in opts.stdin && opts.stdin.isTTY ? '-it' : '--interactive');
            if (opts.cwd) execArgs.push('--workdir', opts.cwd);
            execArgs.push(containerName, ...args);

            // A stream without a file descriptor (an audit tee, say) cannot be
            // handed to spawn; pipe that one and keep the rest on direct fds.
            const stderrHasFd = typeof opts.stderr?.fd === 'number';
            const child = spawn(engine, execArgs, {
              stdio: [opts.stdin, opts.stdout, stderrHasFd ? opts.stderr : 'pipe'],
            });
            if (!stderrHasFd) child.stderr.pipe(opts.stderr);
            child.on('error', (error) => reject(new Error(`${engine} exec failed: ${error.message}`)));
            child.on('close', (code) => resolve({ exitCode: code ?? 0 }));
          }),

        copyIn: async (hostPath, sandboxPath) => {
          await engineExec(engine, ['cp', hostPath, `${containerName}:${sandboxPath}`]);
        },

        copyFileOut: async (sandboxPath, hostPath) => {
          await engineExec(engine, ['cp', `${containerName}:${sandboxPath}`, hostPath]);
        },

        close: async () => {
          unregisterShutdown();
          removeSync();
        },
      };
    },
  });
};

export default kata;
