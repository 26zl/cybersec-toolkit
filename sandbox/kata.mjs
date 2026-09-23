/**
 * kata.mjs — Kata Containers sandbox provider for Sandcastle.
 *
 * Sandcastle's bundled Docker provider cannot select an alternative OCI runtime,
 * so its containers share the host kernel. This provider drives the docker CLI
 * but pins a Kata runtime, which puts a hardware-virtualized boundary between
 * security tooling and the host. Podman cannot host Kata 2.x+: Kata ships only
 * a containerd shim v2, and Podman drives OCI CLI runtimes.
 *
 * The returned provider satisfies Sandcastle's isolated-provider contract, so it
 * can be handed to run()/createSandbox() for agent orchestration or driven
 * directly, as sandbox/mcp.mjs does for the stdio MCP transport.
 *
 * See docs/SANDBOX.md for host prerequisites and configuration.
 */

import { execFile, execFileSync, spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
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

const assertKataRuntime = (name, allowUnsafe) => {
  // A non-Kata runtime is a namespace container sharing the host kernel — the
  // thing this provider exists to avoid — so it is never silently used.
  if (isKataRuntime(name) || allowUnsafe) return name;
  throw new Error(
    `Runtime '${name}' is not a Kata runtime: tools would share the host kernel with no VM boundary. ` +
      'Set CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1 to accept that deliberately (a CI smoke test, say).',
  );
};

// Per-boot random UUID; not namespaced, so a container that shares the host
// kernel reads the host's value, while a VM has its own.
export const BOOT_ID_PATH = '/proc/sys/kernel/random/boot_id';

const readHostBootId = () => {
  try {
    return readFileSync(BOOT_ID_PATH, 'utf8').trim();
  } catch {
    return '';
  }
};

/**
 * Assert the started sandbox is a VM, not a namespace container.
 *
 * The runtime name is chosen by whoever configured Docker, so a non-Kata
 * runtime registered under a kata-ish name passes the name check while sharing
 * the host kernel. An identical boot id proves that sharing; a real VM boots
 * its own kernel and gets its own id. Boot ids are random per boot, so a match
 * is not coincidence. Fails closed when either id is unreadable.
 */
export const assertVmBoundary = (guestBootId, hostBootId, runtime) => {
  if (!hostBootId || !guestBootId) {
    throw new Error(
      `Runtime '${runtime}': could not confirm a VM boundary (boot id unavailable). ` +
        'Set CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1 to run without one deliberately.',
    );
  }
  if (guestBootId === hostBootId) {
    throw new Error(
      `Runtime '${runtime}' shares the host kernel (identical boot id): no VM boundary. ` +
        'It is named like Kata but does not isolate the guest. ' +
        'Set CYBERSEC_SANDBOX_ALLOW_UNSAFE_RUNTIME=1 to accept a non-VM runtime deliberately.',
    );
  }
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

const dockerExec = (args, { maxBuffer = 10 * 1024 * 1024 } = {}) =>
  new Promise((resolve, reject) => {
    execFile('docker', args, { maxBuffer }, (error, stdout, stderr) => {
      if (!error) {
        resolve(stdout.toString());
        return;
      }
      if (error.code === 'ENOENT') {
        reject(new Error('docker CLI not found on PATH; see docs/SANDBOX.md for host prerequisites.'));
        return;
      }
      reject(new Error(`docker ${args[0]} failed: ${stderr?.toString().trim() || error.message}`));
    });
  });

const readRuntimes = async () => {
  const raw = await dockerExec(['info', '--format', '{{json .Runtimes}}']);
  try {
    return JSON.parse(raw.trim() || '{}');
  } catch {
    throw new Error(`Could not parse the runtime list from 'docker info': ${raw.trim()}`);
  }
};

const assertImagePresent = async (image) => {
  try {
    await dockerExec(['image', 'inspect', image, '--format', '{{.Id}}']);
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
 * A signal that lands while `pending()` is still booting the VM waits for it:
 * removing a container that does not exist yet would leave it orphaned.
 */
export const registerShutdown = (cleanup, pending = () => undefined, proc = process) => {
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const onExit = () => cleanup();
  const onSignal = (signal) => {
    const finish = () => {
      cleanup();
      proc.exit(signal === 'SIGINT' ? 130 : 143);
    };
    const booting = pending();
    if (booting) booting.then(finish, finish);
    else finish();
  };

  proc.on('exit', onExit);
  for (const signal of signals) proc.on(signal, onSignal);

  return () => {
    proc.off('exit', onExit);
    for (const signal of signals) proc.off(signal, onSignal);
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
      const runtime = selectRuntime(await readRuntimes(), resolved.runtime, {
        allowUnsafe: resolved.allowUnsafeRuntime,
      });
      if (!isKataRuntime(runtime)) {
        process.stderr.write(`WARNING: sandbox runtime '${runtime}' is not Kata — tools share the host kernel.\n`);
      }
      await assertImagePresent(resolved.image);

      const containerName = `cybersec-kata-${randomUUID()}`;
      let removed = false;
      const removeSync = () => {
        if (removed) return;
        removed = true;
        try {
          execFileSync('docker', ['rm', '--force', containerName], { stdio: 'ignore' });
        } catch {
          // Teardown is best-effort; the label allows a manual sweep.
        }
      };

      // Registered before `docker run`, which is where the VM boots: a signal
      // in that window must still remove it.
      let booting;
      const unregisterShutdown = registerShutdown(removeSync, () => booting);
      booting = dockerExec(
        buildRunArgs({
          name: containerName,
          runtime,
          options: resolved,
          env: { ...options.env, ...createOptions.env },
        }),
      );
      try {
        await booting;
      } catch (error) {
        removeSync();
        unregisterShutdown();
        throw error;
      }
      booting = undefined;

      // Prove the boundary before handing the sandbox out. The name check and
      // the warning above can be satisfied by a runtime that only calls itself
      // Kata; this catches one that shares the host kernel. The explicit unsafe
      // opt-in (already warned about) skips it.
      if (!resolved.allowUnsafeRuntime) {
        const teardownAndThrow = (error) => {
          removeSync();
          unregisterShutdown();
          throw error;
        };
        let guestBootId;
        try {
          guestBootId = (await dockerExec(['exec', containerName, 'cat', BOOT_ID_PATH])).trim();
        } catch (error) {
          teardownAndThrow(new Error(`Could not verify the sandbox is a VM: ${error.message}`));
        }
        try {
          assertVmBoundary(guestBootId, readHostBootId(), runtime);
        } catch (error) {
          teardownAndThrow(error);
        }
      }

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

            const child = spawn('docker', args, {
              stdio: [opts.stdin !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
            });
            child.on('error', (error) => reject(new Error(`docker exec failed: ${error.message}`)));
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
            child.on('close', (code) => resolve({ stdout, stderr, exitCode: code ?? 1 }));
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
            const child = spawn('docker', execArgs, {
              stdio: [opts.stdin, opts.stdout, stderrHasFd ? opts.stderr : 'pipe'],
            });
            if (!stderrHasFd) child.stderr.pipe(opts.stderr);
            child.on('error', (error) => reject(new Error(`docker exec failed: ${error.message}`)));
            child.on('close', (code) => resolve({ exitCode: code ?? 1 }));
          }),

        copyIn: async (hostPath, sandboxPath) => {
          await dockerExec(['cp', hostPath, `${containerName}:${sandboxPath}`]);
        },

        copyFileOut: async (sandboxPath, hostPath) => {
          await dockerExec(['cp', `${containerName}:${sandboxPath}`, hostPath]);
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
