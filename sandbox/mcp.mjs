/**
 * mcp.mjs — stdio MCP entry point that runs the server inside a Kata VM.
 *
 * MCP clients supply their own agent loop, so only the sandbox lifecycle is
 * needed here: create the VM, wire the client's stdio to the server process
 * inside it, and tear the VM down when the client disconnects.
 *
 * The guest's stderr is teed on the way out so audit records survive the VM
 * (see sandbox/audit-sink.mjs); stdin and stdout stay on direct file
 * descriptors, so the JSON-RPC path is untouched.
 */

import { createAuditSink, createAuditStderrTee } from './audit-sink.mjs';
import { kata } from './kata.mjs';

const truthy = (value) => ['1', 'true', 'yes'].includes((value ?? '').trim().toLowerCase());

let sandbox;
try {
  // Opened before the VM boots so a required-but-unusable audit log fails closed.
  const sink = createAuditSink({ required: truthy(process.env.CYBERSEC_MCP_AUDIT_REQUIRED) });

  sandbox = await kata().create({
    // Only the policy switches cross the boundary; audit and venv paths are
    // baked into the image and must keep pointing at guest paths.
    env: {
      CYBERSEC_MCP_ALLOW_EXTERNAL: process.env.CYBERSEC_MCP_ALLOW_EXTERNAL ?? '0',
      CYBERSEC_MCP_ALLOW_SCRIPTS: process.env.CYBERSEC_MCP_ALLOW_SCRIPTS ?? '0',
    },
  });

  const result = await sandbox.interactiveExec(
    ['/opt/cybersec-toolkit/mcp_server/.venv/bin/python', '-m', 'mcp_server.server'],
    { stdin: process.stdin, stdout: process.stdout, stderr: createAuditStderrTee(process.stderr, sink) },
  );
  process.exitCode = result.exitCode;
} catch (error) {
  console.error(`Kata sandbox failed: ${error.message}`);
  console.error('Run `bash scripts/mcp-launch.sh --local` to execute on the host instead (no VM boundary).');
  process.exitCode = 1;
} finally {
  if (sandbox) await sandbox.close();
}
