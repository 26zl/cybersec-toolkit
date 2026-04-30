---
name: ctf-rev
description: Use when solving a CTF reverse engineering challenge — stripped binaries, packed binaries, anti-debug, custom VMs, .NET/Java decomp, Android dex, obfuscated JS, ELF/PE/Mach-O analysis. Provides workflow and tool ordering from the reversing module. Triggers on "ctf rev", "reversing", "reverse engineer", "decompile", "stripped binary".
---

# CTF reverse engineering methodology

## 1. Triage

```bash
file ./bin
strings ./bin | head -50
strings ./bin | grep -i "flag\|ctf{\|password\|key"
xxd ./bin | head -20                       # magic bytes
checksec --file=./bin                      # protections
```

## 2. Detect packing

```bash
# Entropy check (>7.5 = packed/encrypted)
ent ./bin   # or: python3 -c "from collections import Counter; ..."

# UPX / known packers
upx -t ./bin            # tests + identifies UPX
detect-it-easy-cli ./bin
diec ./bin
```

If UPX-packed: `upx -d ./bin -o unpacked`. For custom packers: dump from memory after unpacking stub runs (gdb / x64dbg).

## 3. Pick the decompiler

| Binary type | Best tool |
| --- | --- |
| ELF / PE / Mach-O | Ghidra (registry), IDA (commercial), Binary Ninja |
| Stripped ELF | Ghidra + recover symbols via FunctionID / Lumen |
| .NET (DLL/EXE) | `dnSpyEx`, `ilspycmd`, `dotPeek` |
| Java JAR | `jadx`, `cfr`, `procyon` |
| Java class | `javap -c -p` |
| Android APK | `jadx-gui`, `apktool d` then `jadx` on dex |
| iOS / Mach-O | Hopper, Ghidra |
| Go binary | `redress`, `GoReSym`, Ghidra + Go plugin |
| Rust | Ghidra + `rustfilt` for symbols |
| WASM | `wabt` (`wasm-decompile`), `wasmer` for run |
| Python `.pyc` | `uncompyle6`, `decompyle3`, `pycdc` |
| PyInstaller .exe | `pyinstxtractor` then `pycdc` on .pyc |
| Compiled Lua | `unluac`, `luadec` |

## 4. Dynamic analysis

```bash
# Trace
ltrace ./bin
strace ./bin
strace -f -e trace=read,write,open ./bin

# Debugger
gdb-multiarch ./bin
# pwndbg or gef extensions are loaded by default

# Fault injection / branch flipping
gdb> set $eax = 1     # change return value to bypass check
```

For Android: `frida` for runtime instrumentation, `objection` on top.

## 5. Anti-debug / anti-VM

Common checks:

- `ptrace(PTRACE_TRACEME)` returns -1 if already debugged → patch with `nop`
- `/proc/self/status` `TracerPid: 0` check → LD_PRELOAD a fake or patch
- timing checks (rdtsc) → patch
- `IsDebuggerPresent()` (Windows) → patch the call site

Tooling: `ScyllaHide` (Windows), gdb scripts to auto-bypass, `frida` to hook.

## 6. Custom VMs

If you see a big switch dispatcher reading a "bytecode" buffer:

1. Identify the opcode handler table
2. Map opcodes → operations
3. Disassemble the bytecode manually (write a small Python disasm)
4. Reverse the program logic in the decoded bytecode

This is common in harder rev challenges. Don't fight the VM — disassemble it.

## 7. Symbolic execution / SMT

For challenges where input → boolean check, and check is complex but pure:

- `angr` — Python symbolic execution. Find path to "win" basic block.
- `manticore` — alternative.
- `z3` directly — when constraints are explicit (e.g., "input[i] ^ key[i] == ...").

Pwntools venv has `z3-solver` already.

## 8. Don't waste time on

- Reading every disassembly line top-to-bottom — find `main`, focus there
- Reimplementing `strings`, `objdump`, `readelf` — use the tools
- Manual hex editing for big patches — use `radare2` or Ghidra's patch instructions

## After solve

Use the `writeup-template` skill. Include the key reverse-engineered algorithm or VM disassembly.
