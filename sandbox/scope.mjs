/**
 * scope.mjs — the network scope of an engagement, enforced inside the sandbox.
 *
 * The policy layer's external-target check runs before a tool starts and does
 * not cover scripts, child processes or redirects. A scope file is enforced
 * afterwards as well: the launcher turns it into an nftables ruleset with a
 * default-deny output chain and loads it in the sandbox's own kernel through a
 * root setup step. The tool user has no capabilities and no way to gain any, so
 * neither a tool nor a script can change the rules.
 *
 * Names are resolved once, on the host, and pinned in the guest's /etc/hosts
 * when the sandbox is created: DNS stays closed unless the scope opens it,
 * because a resolver is a channel to anywhere.
 *
 * See docs/SANDBOX.md ("Engagement scope").
 */

import { lookup } from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { BlockList, isIPv4, isIPv6 } from 'node:net';
import { isAbsolute } from 'node:path';

export const SCOPE_TABLE = 'cybersec_scope';
// Docker's embedded resolver on user-defined networks; it forwards from outside the sandbox.
const EMBEDDED_RESOLVER = '127.0.0.11';
// Documentation ranges (RFC 5737) are never routed: an attempt to reach one ends
// at once only when a rule rejects it.
const PROBE_CANDIDATES = ['192.0.2.1', '198.51.100.1', '203.0.113.1'];
const MAX_ENTRIES = 256;
const MAX_PORTS = 64;
const MAX_ADDRESSES_PER_NAME = 16;

// Addresses a host name must not lead to unless the scope lists them literally: DNS for a name is not under the operator's control.
const UNSAFE_V4 = new BlockList();
for (const [net, bits] of [['0.0.0.0', 8], ['127.0.0.0', 8], ['169.254.0.0', 16], ['224.0.0.0', 4], ['255.255.255.255', 32]]) {
  UNSAFE_V4.addSubnet(net, bits, 'ipv4');
}
// Kept apart from the IPv4 list: a mapped-address rule would otherwise match every IPv4 address.
const UNSAFE_V6 = new BlockList();
for (const [net, bits] of [['::', 128], ['::1', 128], ['fe80::', 10], ['ff00::', 8], ['::ffff:0:0', 96]]) {
  UNSAFE_V6.addSubnet(net, bits, 'ipv6');
}
const unsafeForNames = (address, family) =>
  family === 4 ? UNSAFE_V4.check(address, 'ipv4') : UNSAFE_V6.check(address, 'ipv6');

const HOSTNAME =
  /^(?=.{1,253}$)(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

const fail = (source, message) => {
  throw new Error(`Scope file '${source}': ${message}`);
};

const onlyKeys = (source, object, allowed, where) => {
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key)) fail(source, `unknown key '${key}' in ${where} (allowed: ${allowed.join(', ')})`);
  }
};

const parseHost = (source, raw, where) => {
  if (typeof raw !== 'string' || !raw) fail(source, `${where} needs a "host" string`);
  if (raw.includes('*')) {
    fail(source, `${where}: wildcard '${raw}' cannot be enforced by address; list the hosts or a CIDR range`);
  }
  if (isIPv4(raw)) return { kind: 'ip', family: 4, address: raw };
  // A zone id would end up inside the ruleset text.
  if (isIPv6(raw) && !raw.includes('%')) return { kind: 'ip', family: 6, address: raw.toLowerCase() };

  const slash = raw.lastIndexOf('/');
  if (slash > 0) {
    const address = raw.slice(0, slash);
    const prefix = raw.slice(slash + 1);
    const family = isIPv4(address) ? 4 : isIPv6(address) && !address.includes('%') ? 6 : 0;
    if (!family || !/^\d{1,3}$/.test(prefix)) fail(source, `${where}: '${raw}' is not a CIDR range`);
    const bits = Number(prefix);
    if (bits < 1 || bits > (family === 4 ? 32 : 128)) {
      fail(source, `${where}: prefix length of '${raw}' is out of range (a scope cannot be everything)`);
    }
    return { kind: 'cidr', family, address: `${address.toLowerCase()}/${bits}` };
  }
  if (HOSTNAME.test(raw)) return { kind: 'name', name: raw.toLowerCase() };
  return fail(source, `${where}: '${raw}' is not an address, a CIDR range or a host name`);
};

const parsePorts = (source, raw, where) => {
  if (raw === undefined) return null;
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_PORTS) {
    fail(source, `${where}: "ports" must be a list of 1-${MAX_PORTS} ports or "low-high" ranges`);
  }
  return raw.map((item) => {
    const match = typeof item === 'string' ? /^(\d{1,5})-(\d{1,5})$/.exec(item) : null;
    const [low, high] = match ? [Number(match[1]), Number(match[2])] : [item, item];
    if (!Number.isInteger(low) || !Number.isInteger(high) || low < 1 || high > 65535 || low > high) {
      fail(source, `${where}: '${item}' is not a port or a "low-high" range`);
    }
    return [low, high];
  });
};

/** Validate scope JSON. Every unknown key is an error: a typo must not widen or narrow a scope silently. */
export const parseScope = (text, source = 'scope') => {
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    fail(source, `not valid JSON (${error.message})`);
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) fail(source, 'must be a JSON object');
  onlyKeys(source, data, ['name', 'allow', 'dns'], 'the scope');

  const name = data.name ?? 'unnamed';
  if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name)) {
    fail(source, '"name" must be 1-64 letters, digits, spaces, dots, dashes or underscores');
  }
  if (data.dns !== undefined && typeof data.dns !== 'boolean') fail(source, '"dns" must be true or false');
  if (!Array.isArray(data.allow) || data.allow.length > MAX_ENTRIES) {
    fail(source, `"allow" must be a list of at most ${MAX_ENTRIES} entries`);
  }

  const allow = data.allow.map((entry, index) => {
    const where = `allow[${index}]`;
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) fail(source, `${where} must be an object`);
    onlyKeys(source, entry, ['host', 'ports', 'proto'], where);
    const ports = parsePorts(source, entry.ports, where);
    if (entry.proto !== undefined && !['tcp', 'udp'].includes(entry.proto)) {
      fail(source, `${where}: "proto" must be "tcp" or "udp"`);
    }
    if (entry.proto !== undefined && !ports) fail(source, `${where}: "proto" needs "ports"`);
    return { ...parseHost(source, entry.host, where), ports, proto: entry.proto ?? null };
  });
  return { name, dns: data.dns === true, allow };
};

export const loadScope = (path) => {
  if (!isAbsolute(path)) throw new Error(`CYBERSEC_SANDBOX_SCOPE must be an absolute path, got '${path}'.`);
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new Error(`Scope file '${path}' cannot be read: ${error.message}`);
  }
  return parseScope(text, path);
};

/**
 * Turn host names into the addresses they have right now.
 *
 * Returns `targets` (address-based rules) and `pins` (address, name) pairs for
 * the guest's /etc/hosts. A name that does not resolve is an error: starting
 * with part of a scope missing would look like a target that is down.
 */
export const resolveScope = async (scope, resolver = lookup) => {
  const targets = [];
  const pins = [];
  for (const entry of scope.allow) {
    const { ports, proto } = entry;
    if (entry.kind !== 'name') {
      targets.push({ family: entry.family, address: entry.address, ports, proto, origin: entry.address });
      continue;
    }
    let answers;
    try {
      answers = await resolver(entry.name, { all: true, verbatim: true });
    } catch (error) {
      throw new Error(`Scope '${scope.name}': host '${entry.name}' does not resolve (${error.code ?? error.message}).`);
    }
    const usable = answers.filter(
      ({ address, family }) => (family === 4 && isIPv4(address)) || (family === 6 && isIPv6(address) && !address.includes('%')),
    );
    if (usable.length === 0) throw new Error(`Scope '${scope.name}': host '${entry.name}' has no usable address.`);
    const literal = new Set(scope.allow.filter((item) => item.kind === 'ip').map((item) => item.address));
    for (const { address, family } of usable) {
      if (unsafeForNames(address, family) && !literal.has(address.toLowerCase())) {
        throw new Error(
          `Scope '${scope.name}': host '${entry.name}' resolves to ${address}, a loopback, link-local, unspecified, ` +
            'multicast or mapped address; list it as an address in the scope file if that is intended.',
        );
      }
    }
    if (usable.length > MAX_ADDRESSES_PER_NAME) {
      throw new Error(
        `Scope '${scope.name}': host '${entry.name}' resolves to ${usable.length} addresses (at most ${MAX_ADDRESSES_PER_NAME}); list the ones in scope.`,
      );
    }
    usable.sort((a, b) => a.family - b.family || (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
    for (const { address, family } of usable) {
      targets.push({ family, address: address.toLowerCase(), ports, proto, origin: entry.name });
      pins.push([address.toLowerCase(), entry.name]);
    }
  }
  return { name: scope.name, dns: scope.dns, targets, pins };
};

const portSet = (ports) => `{ ${ports.map(([low, high]) => (low === high ? `${low}` : `${low}-${high}`)).join(', ')} }`;

const allowRule = ({ family, address, ports, proto }) => {
  const destination = `${family === 4 ? 'ip' : 'ip6'} daddr ${address}`;
  if (!ports) return `${destination} accept`;
  if (proto) return `${destination} ${proto} dport ${portSet(ports)} accept`;
  return `${destination} meta l4proto { tcp, udp } th dport ${portSet(ports)} accept`;
};

/**
 * The nftables script for a resolved scope.
 *
 * Only values this module has validated reach the text: addresses that passed
 * net.isIP, integer ports and fixed keywords. `nameservers` is used when the
 * scope opens DNS.
 */
export const buildRuleset = (scope, nameservers = []) => {
  const lines = [];
  // Without DNS in scope, the embedded resolver must not answer either: it sits on loopback.
  if (!scope.dns) lines.push(`ip daddr ${EMBEDDED_RESOLVER} reject with icmpx type admin-prohibited`);
  lines.push('oifname "lo" accept', 'ct state established,related accept');
  // Neighbour discovery, or an on-link IPv6 target in scope is unreachable.
  lines.push('icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept');
  if (scope.dns) {
    for (const server of nameservers) {
      const family = isIPv4(server) ? 'ip' : isIPv6(server) && !server.includes('%') ? 'ip6' : null;
      if (!family || server === EMBEDDED_RESOLVER) continue;
      lines.push(`${family} daddr ${server.toLowerCase()} meta l4proto { tcp, udp } th dport 53 accept`);
    }
  }
  for (const target of scope.targets) lines.push(allowRule(target));
  // Reject, not drop: a tool gets an immediate error instead of a timeout.
  lines.push('reject with icmpx type admin-prohibited');

  return [
    // Declaring before deleting makes the load succeed whether or not the table exists.
    `table inet ${SCOPE_TABLE}`,
    `delete table inet ${SCOPE_TABLE}`,
    `table inet ${SCOPE_TABLE} {`,
    '  chain output {',
    '    type filter hook output priority 0; policy drop;',
    ...lines.map((line) => `    ${line}`),
    '  }',
    '}',
    '',
  ].join('\n');
};

/**
 * `docker run` arguments that pin the scope's names in the guest's /etc/hosts.
 *
 * The file is read-only inside the sandbox, so Docker has to write it at creation.
 */
export const buildHostArgs = (scope) => scope.pins.flatMap(([address, name]) => ['--add-host', `${name}:${address}`]);

const ipv4ToInt = (address) => address.split('.').reduce((sum, octet) => sum * 256 + Number(octet), 0);

const coversIPv4 = (target, address) => {
  if (target.family !== 4) return false;
  const [base, prefix = '32'] = target.address.split('/');
  const bits = Number(prefix);
  const size = 2 ** (32 - bits);
  return Math.floor(ipv4ToInt(base) / size) === Math.floor(ipv4ToInt(address) / size);
};

/** An address outside the scope to test the rules against, or null when the scope covers every candidate. */
export const pickProbeAddress = (scope) =>
  PROBE_CANDIDATES.find((candidate) => !scope.targets.some((target) => coversIPv4(target, candidate))) ?? null;

const SUMMARY_ENTRIES = 24;

/** One line for logs and for the server's own description of where it may connect. */
export const summarize = (scope) => {
  const entries = scope.targets.map(({ address, ports, proto, origin }) => {
    const where = origin === address ? address : `${origin} (${address})`;
    return ports ? `${where} ${proto ?? 'tcp+udp'}/${portSet(ports).slice(2, -2).replaceAll(', ', ',')}` : where;
  });
  const shown = entries.slice(0, SUMMARY_ENTRIES);
  if (entries.length > shown.length) shown.push(`and ${entries.length - shown.length} more`);
  return `${scope.name}: ${shown.join('; ') || 'no destinations'}; DNS ${scope.dns ? 'open' : 'closed'}`;
};

const PROBE_SOURCE = [
  'import socket, sys, time',
  'start = time.monotonic()',
  'try:',
  '    socket.create_connection((sys.argv[1], 9), timeout=4).close()',
  '    print("connected")',
  '    sys.exit(1)',
  'except OSError as error:',
  '    took = time.monotonic() - start',
  '    print(f"{type(error).__name__} after {took:.1f}s")',
  '    sys.exit(0 if took < 2 and not isinstance(error, TimeoutError) else 1)',
].join('\n');

/**
 * Load a resolved scope into a running sandbox and prove it holds.
 *
 * `run(dockerArgs, stdin)` executes the docker CLI and resolves with stdout.
 * Throws when any step fails; the caller tears the sandbox down, so a session
 * never starts with a scope that is only partly in force.
 */
export const applyScope = async ({
  run,
  container,
  scope,
  warn = (message) => process.stderr.write(`${message}\n`),
}) => {
  const asRoot = ['exec', '--interactive', '--user', '0:0', container];

  let nameservers = [];
  if (scope.dns) {
    const resolvConf = await run(['exec', container, 'cat', '/etc/resolv.conf']);
    nameservers = [...resolvConf.matchAll(/^\s*nameserver\s+(\S+)/gm)].map((match) => match[1]);
  }

  try {
    await run([...asRoot, 'nft', '-f', '-'], buildRuleset(scope, nameservers));
  } catch (error) {
    throw new Error(`the rules did not load (${error.message}). An image without nftables needs a rebuild.`);
  }
  const loaded = await run([...asRoot, 'nft', 'list', 'chain', 'inet', SCOPE_TABLE, 'output']);
  if (!/policy drop/.test(loaded)) throw new Error('the loaded output chain does not default to drop');

  // The tool user must see the rules from its side, and must not be able to remove them.
  const probe = pickProbeAddress(scope);
  if (probe) {
    try {
      // -I and a neutral workdir: a socket.py in the mounted workspace must not stand in for the real module.
      await run(['exec', '--workdir', '/', container, 'python3', '-I', '-c', PROBE_SOURCE, probe]);
    } catch (error) {
      throw new Error(`a connection outside the scope (${probe}) was not rejected (${error.message})`);
    }
  } else {
    warn('WARNING: the scope covers every probe address, so the rules were loaded but not tested with a connection.');
  }
  let flushed = false;
  try {
    await run(['exec', container, 'nft', 'flush', 'ruleset']);
    flushed = true;
  } catch {
    // Expected: the tool user has no capability to touch the ruleset.
  }
  if (flushed) throw new Error('the tool user was able to flush the ruleset');
};
