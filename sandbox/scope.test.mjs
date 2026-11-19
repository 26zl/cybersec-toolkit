import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  applyScope,
  buildHostArgs,
  buildRuleset,
  loadScope,
  parseScope,
  pickProbeAddress,
  resolveScope,
  SCOPE_TABLE,
  summarize,
} from './scope.mjs';

const scopeOf = (allow, extra = {}) => parseScope(JSON.stringify({ name: 'lab', allow, ...extra }));
// Resolves only names in the documentation domain, like a resolver that knows the lab.
const labResolver = async (name) => {
  if (name === 'web.example') return [{ address: '198.51.100.7', family: 4 }, { address: '2001:DB8::7', family: 6 }];
  const error = new Error('not found');
  error.code = 'ENOTFOUND';
  throw error;
};

test('parseScope accepts addresses, ranges and names, and normalizes ports', () => {
  const scope = scopeOf([
    { host: '10.10.11.5' },
    { host: '10.10.0.0/16', ports: [80, '8000-8100'], proto: 'tcp' },
    { host: '2001:DB8::/32', ports: [443] },
    { host: 'Web.Example', ports: [443] },
  ]);
  assert.deepEqual(scope.allow[0], { kind: 'ip', family: 4, address: '10.10.11.5', ports: null, proto: null });
  assert.deepEqual(scope.allow[1].ports, [[80, 80], [8000, 8100]]);
  assert.equal(scope.allow[2].address, '2001:db8::/32');
  assert.deepEqual(scope.allow[3], { kind: 'name', name: 'web.example', ports: [[443, 443]], proto: null });
  assert.equal(scope.dns, false);
});

test('parseScope refuses anything it cannot enforce or does not recognise', () => {
  const bad = (allow, extra, pattern) => assert.throws(() => scopeOf(allow, extra), pattern);
  bad([{ host: '*.example.com' }], {}, /wildcard/);
  bad([{ host: '0.0.0.0/0' }], {}, /cannot be everything/);
  bad([{ host: '::/0' }], {}, /cannot be everything/);
  bad([{ host: '10.0.0.1/33' }], {}, /out of range/);
  bad([{ host: 'fe80::1%eth0' }], {}, /not an address/);
  bad([{ host: '10.10.11' }], {}, /not an address/);
  bad([{ host: '10.0.0.1; drop' }], {}, /not an address/);
  bad([{ host: '10.0.0.1', ports: [0] }], {}, /not a port/);
  bad([{ host: '10.0.0.1', ports: ['90-80'] }], {}, /not a port/);
  bad([{ host: '10.0.0.1', ports: ['80, 443 accept'] }], {}, /not a port/);
  bad([{ host: '10.0.0.1', proto: 'tcp' }], {}, /needs "ports"/);
  bad([{ host: '10.0.0.1', ports: [80], proto: 'icmp' }], {}, /"tcp" or "udp"/);
  bad([{ host: '10.0.0.1', port: 80 }], {}, /unknown key 'port'/);
  bad([{ host: '10.0.0.1' }], { dnss: true }, /unknown key 'dnss'/);
  bad([{ host: '10.0.0.1' }], { dns: 'yes' }, /"dns" must be true or false/);
  assert.throws(() => parseScope('{"allow": "all"}'), /"allow" must be a list/);
  assert.throws(() => parseScope('not json'), /not valid JSON/);
  assert.throws(() => loadScope('scope.json'), /absolute path/);
  assert.throws(() => loadScope('/nonexistent/scope.json'), /cannot be read/);
});

test('resolveScope pins every address of a name and fails on one that does not resolve', async () => {
  const scope = await resolveScope(scopeOf([{ host: '10.10.11.5' }, { host: 'web.example', ports: [443] }]), labResolver);
  assert.deepEqual(
    scope.targets.map((target) => target.address),
    ['10.10.11.5', '198.51.100.7', '2001:db8::7'],
  );
  assert.deepEqual(scope.pins, [['198.51.100.7', 'web.example'], ['2001:db8::7', 'web.example']]);
  assert.deepEqual(buildHostArgs(scope), [
    '--add-host', 'web.example:198.51.100.7',
    '--add-host', 'web.example:2001:db8::7',
  ]);
  assert.deepEqual(buildHostArgs(await resolveScope(scopeOf([{ host: '10.10.11.5' }]), labResolver)), []);

  await assert.rejects(resolveScope(scopeOf([{ host: 'gone.example' }]), labResolver), /does not resolve \(ENOTFOUND\)/);
  // An answer that is not an address never reaches the ruleset.
  const odd = async () => [{ address: '10.0.0.1 accept', family: 4 }];
  await assert.rejects(resolveScope(scopeOf([{ host: 'web.example' }]), odd), /no usable address/);
});

test('buildRuleset denies by default and allows exactly what the scope lists', async () => {
  const scope = await resolveScope(
    scopeOf([
      { host: '10.10.11.5' },
      { host: '10.10.0.0/16', ports: [80, '8000-8100'], proto: 'tcp' },
      { host: 'web.example', ports: [53], proto: 'udp' },
      { host: '192.168.5.0/24', ports: [22] },
    ]),
    labResolver,
  );
  const rules = buildRuleset(scope);

  assert.match(rules, new RegExp(`^table inet ${SCOPE_TABLE}\\ndelete table inet ${SCOPE_TABLE}\\n`));
  assert.match(rules, /type filter hook output priority 0; policy drop;/);
  assert.match(rules, /\n    ip daddr 10\.10\.11\.5 accept\n/);
  assert.match(rules, /\n    ip daddr 10\.10\.0\.0\/16 tcp dport \{ 80, 8000-8100 \} accept\n/);
  assert.match(rules, /\n    ip daddr 198\.51\.100\.7 udp dport \{ 53 \} accept\n/);
  assert.match(rules, /\n    ip6 daddr 2001:db8::7 udp dport \{ 53 \} accept\n/);
  assert.match(rules, /\n    ip daddr 192\.168\.5\.0\/24 meta l4proto \{ tcp, udp \} th dport \{ 22 \} accept\n/);
  // The last rule answers everything else at once.
  assert.match(rules, /\n    reject with icmpx type admin-prohibited\n  \}\n\}\n$/);

  // DNS is closed, the embedded resolver on loopback included, and it is refused before loopback is accepted.
  assert.ok(rules.indexOf('ip daddr 127.0.0.11 reject') < rules.indexOf('oifname "lo" accept'));
  assert.equal(/dport 53 accept/.test(rules.replace('udp dport { 53 } accept', '')), false);
});

test('buildRuleset opens DNS only to the resolvers the guest uses, and only when asked', async () => {
  const closed = await resolveScope(scopeOf([{ host: '10.10.11.5' }]), labResolver);
  assert.equal(buildRuleset(closed, ['9.9.9.9']).includes('9.9.9.9'), false);

  const open = await resolveScope(scopeOf([{ host: '10.10.11.5' }], { dns: true }), labResolver);
  const rules = buildRuleset(open, ['192.168.1.1', '2001:db8::53', '127.0.0.11', 'not-an-address']);
  assert.match(rules, /ip daddr 192\.168\.1\.1 meta l4proto \{ tcp, udp \} th dport 53 accept/);
  assert.match(rules, /ip6 daddr 2001:db8::53 meta l4proto \{ tcp, udp \} th dport 53 accept/);
  assert.equal(rules.includes('127.0.0.11'), false, 'the embedded resolver is reached over loopback');
  assert.equal(rules.includes('not-an-address'), false);
});

test('pickProbeAddress avoids addresses the scope allows', async () => {
  const narrow = await resolveScope(scopeOf([{ host: '10.10.11.5' }]), labResolver);
  assert.equal(pickProbeAddress(narrow), '192.0.2.1');
  const covering = await resolveScope(scopeOf([{ host: '192.0.2.0/24' }, { host: '198.51.100.1' }]), labResolver);
  assert.equal(pickProbeAddress(covering), '203.0.113.1');
  const all = await resolveScope(scopeOf([{ host: '192.0.0.0/8' }, { host: '198.51.100.0/24' }, { host: '203.0.113.1' }]), labResolver);
  assert.equal(pickProbeAddress(all), null);
});

test('summarize names every destination and the DNS setting', async () => {
  const scope = await resolveScope(
    scopeOf([{ host: '10.10.11.5' }, { host: 'web.example', ports: [443, '8000-8010'], proto: 'tcp' }]),
    labResolver,
  );
  assert.equal(
    summarize(scope),
    'lab: 10.10.11.5; web.example (198.51.100.7) tcp/443,8000-8010; web.example (2001:db8::7) tcp/443,8000-8010; DNS closed',
  );
});

// A fake docker: records calls and answers the way a sandbox with working rules would.
const fakeSandbox = (overrides = {}) => {
  const calls = [];
  const run = async (args, input) => {
    calls.push({ args, input });
    const command = args.slice(args.indexOf('sbx') + 1);
    const answer = overrides[command.slice(0, 2).join(' ')];
    if (answer) return answer(args, input);
    if (command[0] === 'cat') return 'nameserver 192.168.1.1\nnameserver 127.0.0.11\n';
    if (command.join(' ') === `nft list chain inet ${SCOPE_TABLE} output`) return 'chain output { policy drop; }';
    if (command.join(' ') === 'nft flush ruleset') throw new Error('Operation not permitted');
    return '';
  };
  return { run, calls };
};

test('applyScope loads the rules as root and proves them from the tool user', async () => {
  const scope = await resolveScope(scopeOf([{ host: 'web.example', ports: [443] }], { dns: true }), labResolver);
  const { run, calls } = fakeSandbox();
  await applyScope({ run, container: 'sbx', scope });

  const commands = calls.map(({ args }) => args.join(' '));
  assert.equal(commands[0], 'exec sbx cat /etc/resolv.conf');
  assert.equal(commands[1], 'exec --interactive --user 0:0 sbx nft -f -');
  assert.match(calls[1].input, /ip daddr 192\.168\.1\.1 meta l4proto \{ tcp, udp \} th dport 53 accept/);
  // /etc/hosts is read-only in the sandbox; the names were pinned when it was created.
  assert.equal(commands.some((command) => command.includes('/etc/hosts')), false);
  // The probe and the flush attempt run as the tool user: no --user flag.
  assert.match(commands[3], /^exec --workdir \/ sbx python3 -I -c /);
  assert.equal(calls[3].args.at(-1), '192.0.2.1');
  assert.equal(commands[4], 'exec sbx nft flush ruleset');
});

test('applyScope fails when a step does not hold, so the launch stops', async () => {
  const scope = await resolveScope(scopeOf([{ host: '10.10.11.5' }]), labResolver);
  const failing = (key, answer) => applyScope({ run: fakeSandbox({ [key]: answer }).run, container: 'sbx', scope });

  await assert.rejects(
    failing('nft -f', () => {
      throw new Error('nft: not found');
    }),
    /rules did not load.*needs a rebuild/,
  );
  await assert.rejects(failing('nft list', () => 'chain output { policy accept; }'), /does not default to drop/);
  await assert.rejects(
    failing('python3 -I', () => {
      throw new Error('connected');
    }),
    /outside the scope \(192\.0\.2\.1\) was not rejected/,
  );
  await assert.rejects(failing('nft flush', () => ''), /tool user was able to flush/);
});

test('resolveScope refuses names that resolve to loopback, link-local or mapped addresses', async () => {
  const to = (...addresses) => async () => addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  const scope = scopeOf([{ host: 'web.example' }]);
  for (const bad of ['127.0.0.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', '::ffff:10.0.0.1']) {
    await assert.rejects(resolveScope(scope, to(bad)), /resolves to/, bad);
  }
  // The same address listed literally in the scope is the operator's own decision.
  const listed = scopeOf([{ host: 'web.example' }, { host: '127.0.0.1' }]);
  const resolved = await resolveScope(listed, to('127.0.0.1'));
  assert.equal(resolved.pins[0][0], '127.0.0.1');
  // Private ranges are legitimate targets.
  await resolveScope(scope, to('10.10.11.5'));
});

test('resolveScope caps the answers per name and orders them deterministically', async () => {
  const many = async () => Array.from({ length: 200 }, (_, i) => ({ address: `198.51.${i}.7`, family: 4 }));
  await assert.rejects(resolveScope(scopeOf([{ host: 'web.example' }]), many), /at most 16/);
  const two = async () => [{ address: '198.51.100.9', family: 4 }, { address: '198.51.100.7', family: 4 }];
  const resolved = await resolveScope(scopeOf([{ host: 'web.example' }]), two);
  assert.deepEqual(resolved.targets.map((t) => t.address), ['198.51.100.7', '198.51.100.9']);
});

test('applyScope warns when no probe address lies outside the scope', async () => {
  const scope = await resolveScope(scopeOf([{ host: '0.0.0.0/1' }, { host: '128.0.0.0/1' }]), labResolver);
  const warnings = [];
  const { run, calls } = fakeSandbox();
  await applyScope({ run, container: 'sbx', scope, warn: (m) => warnings.push(m) });
  assert.equal(calls.some(({ args }) => args.includes('python3')), false);
  assert.match(warnings[0], /not tested/);
});
