/**
 * audit-sink.mjs — host-side persistence for a sandboxed server's audit records.
 *
 * The MCP server's own file sink lives inside the VM and is destroyed with it,
 * so the guest also mirrors each record to stderr behind AUDIT_STREAM_PREFIX.
 * This module writes those records to the host audit log, which is both the
 * operator's durable trail and the clearance source scripts/agent-guard.sh
 * reads. File layout, permissions and rotation mirror mcp_server/audit.py.
 *
 * Guest stderr is not a trusted channel: anything running in the VM may be able
 * to print a sentinel line. Each mirrored line is therefore `<tag> <record>`,
 * the tag an HMAC-SHA256 of the record under a per-launch key that only the
 * server process receives, and only records whose tag verifies are persisted.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { Writable } from 'node:stream';

export const AUDIT_STREAM_PREFIX = '@cybersec-audit@ ';
// Carries the hex-encoded session key to the server; read by mcp_server/audit.py.
export const AUDIT_KEY_ENV = 'CYBERSEC_MCP_AUDIT_KEY';
export const AUDIT_KEY_BYTES = 32;

const TAG_PATTERN = /^[0-9a-f]{64}$/;
const MAX_BYTES = 5 * 1024 * 1024;
const BACKUP_COUNT = 3;
// A stderr line this long is malformed; flush it rather than buffer forever.
const MAX_PARTIAL_LINE = 1024 * 1024;

const expandUser = (value, env) => {
  if (value === '~') return env.HOME || homedir();
  if (value.startsWith('~/')) return join(env.HOME || homedir(), value.slice(2));
  return value;
};

/** Resolve the host audit log path with the same precedence as audit.py. */
export const resolveHostAuditPath = (env = process.env) => {
  const configured = (env.CYBERSEC_MCP_AUDIT_LOG ?? '').trim();
  if (configured) return expandUser(configured, env);
  const stateHome = (env.XDG_STATE_HOME ?? '').trim();
  const base = stateHome ? expandUser(stateHome, env) : join(env.HOME || homedir(), '.local', 'state');
  return join(base, 'cybersec-tools-mcp', 'audit.log');
};

/**
 * Split a stderr chunk into audit records and ordinary lines.
 *
 * Returns the trailing partial line so the caller can prepend it to the next
 * chunk; records are only recognised at the start of a complete line.
 */
export const splitAuditLines = (buffered, chunk) => {
  const text = buffered + chunk;
  const parts = text.split('\n');
  let rest = parts.pop() ?? '';
  const audit = [];
  const passthrough = [];

  for (const line of parts) {
    if (line.startsWith(AUDIT_STREAM_PREFIX)) audit.push(line.slice(AUDIT_STREAM_PREFIX.length));
    else passthrough.push(line);
  }

  if (rest.length > MAX_PARTIAL_LINE) {
    passthrough.push(rest);
    rest = '';
  }

  return { audit, passthrough, rest };
};

/** Hex HMAC-SHA256 tag of a serialized record under the session key. */
export const auditRecordTag = (key, record) => createHmac('sha256', key).update(record, 'utf8').digest('hex');

/** The record a mirrored `<tag> <record>` line carries, or null unless its tag verifies. */
export const authenticateAuditLine = (line, key) => {
  const separator = line.indexOf(' ');
  const tag = line.slice(0, separator);
  if (separator < 0 || !TAG_PATTERN.test(tag)) return null;
  const record = line.slice(separator + 1);
  const expected = createHmac('sha256', key).update(record, 'utf8').digest();
  return timingSafeEqual(Buffer.from(tag, 'hex'), expected) ? record : null;
};

const parseAuditRecord = (line) => {
  try {
    const parsed = JSON.parse(line);
    return typeof parsed === 'object' && parsed !== null && typeof parsed.event === 'string' ? parsed : null;
  } catch {
    return null;
  }
};

/** Whether a mirrored line is a well-formed audit record worth persisting. */
export const isAuditRecord = (line) => parseAuditRecord(line) !== null;

const rotate = (target) => {
  let size = 0;
  try {
    size = statSync(target).size;
  } catch {
    return;
  }
  if (size < MAX_BYTES) return;

  try {
    unlinkSync(`${target}.${BACKUP_COUNT}`);
  } catch {
    // No oldest backup to discard.
  }
  for (let index = BACKUP_COUNT - 1; index >= 1; index -= 1) {
    try {
      renameSync(`${target}.${index}`, `${target}.${index + 1}`);
    } catch {
      // Gap in the backup chain; nothing to shift.
    }
  }
  try {
    renameSync(target, `${target}.1`);
  } catch {
    // Rotation is best-effort; a failed rename keeps appending to the target.
  }
};

/**
 * Open the host audit sink.
 *
 * With `required`, an unusable log aborts the session the way
 * CYBERSEC_MCP_AUDIT_REQUIRED does inside the server; otherwise the failure is
 * reported once and the session continues without a host-side trail.
 */
export const createAuditSink = ({ path, required = false, warn = (m) => process.stderr.write(`${m}\n`) } = {}) => {
  const target = path ?? resolveHostAuditPath();
  let disabled = false;

  const fail = (error) => {
    const message = `Host audit log unavailable at ${target}: ${error.message}`;
    if (required) throw new Error(message);
    if (!disabled) warn(message);
    disabled = true;
  };

  if (!isAbsolute(target)) {
    fail(new Error('path must be absolute'));
  } else {
    try {
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    } catch (error) {
      fail(error);
    }
  }

  return {
    path: target,
    get enabled() {
      return !disabled;
    },
    write(record) {
      if (disabled) return false;
      try {
        if (!existsSync(target)) closeSync(openSync(target, 'a', 0o600));
        rotate(target);
        appendFileSync(target, `${record}\n`, { mode: 0o600 });
        return true;
      } catch (error) {
        fail(error);
        return false;
      }
    },
  };
};

/**
 * Writable that persists authenticated audit records and forwards the rest.
 *
 * `key` is the session key handed to the server. A prefixed line is persisted
 * only when its tag verifies, it parses as a record, and its `seq` moves its
 * chain forward; anything else is written to `out` marked as rejected, and an
 * accepted record the sink could not write is forwarded as-is, so nothing is
 * dropped silently.
 */
export const createAuditStderrTee = (out, sink, key) => {
  if (!Buffer.isBuffer(key) || key.length < AUDIT_KEY_BYTES) {
    throw new Error(`The audit stderr tee needs a session key of at least ${AUDIT_KEY_BYTES} bytes.`);
  }
  let rest = '';
  const lastSeq = new Map();

  const rejection = (record) => {
    if (record === null) return 'unauthenticated';
    const parsed = parseAuditRecord(record);
    if (parsed === null || typeof parsed.chain !== 'string' || !Number.isSafeInteger(parsed.seq)) return 'malformed';
    // A tag stays valid for the whole session, so a replay is refused by its sequence number.
    if (parsed.seq <= (lastSeq.get(parsed.chain) ?? 0)) return 'replayed';
    lastSeq.set(parsed.chain, parsed.seq);
    return null;
  };

  const persist = (line) => {
    const record = authenticateAuditLine(line, key);
    const reason = rejection(record);
    if (reason) out.write(`Rejected ${reason} audit record: ${line}\n`);
    else if (!sink.write(record)) out.write(`${record}\n`);
  };

  const flush = (chunk) => {
    const split = splitAuditLines(rest, chunk);
    rest = split.rest;
    for (const line of split.audit) persist(line);
    if (split.passthrough.length) out.write(`${split.passthrough.join('\n')}\n`);
  };

  return new Writable({
    write(chunk, _encoding, done) {
      flush(chunk.toString('utf8'));
      done();
    },
    final(done) {
      if (rest) flush('\n');
      done();
    },
  });
};
