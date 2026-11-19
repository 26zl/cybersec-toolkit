---
name: ctf-rev
description: Use when solving a CTF reverse engineering challenge — stripped binaries, packed binaries, anti-debug, custom VMs, .NET/Java decomp, Android dex, obfuscated JS, ELF/PE/Mach-O analysis. Provides workflow and tool ordering from the reversing module. Triggers on "ctf rev", "reversing", "reverse engineer", "decompile", "stripped binary".
---

# CTF reverse engineering methodology

> **Pre-flight.** Confirm the event rules allow AI assistance (`authorization-gate`). Start with `suggest_for_ctf` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command, tell the operator; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 1. Triage

```text
run_tool("file", "./bin")
run_pipeline([{"tool": "strings", "args": "./bin"}, {"tool": "head", "args": "-50"}])
run_pipeline([{"tool": "strings", "args": "./bin"}, {"tool": "grep", "args": "-i -e flag -e ctf{ -e password -e key"}])
run_pipeline([{"tool": "xxd", "args": "./bin"}, {"tool": "head", "args": "-20"}])   # magic bytes
run_tool("checksec", "--file=./bin")                                                  # protections
```

## 2. Detect packing

```text
# Entropy check (>7.5 = packed/encrypted): binwalk -E, or run_script with collections.Counter
run_tool("binwalk", "-E ./bin")

# UPX / known packers
run_tool("upx-ucl", "-t ./bin")                 # tests + identifies UPX
# Detect It Easy is registry tool detect-it-easy; use it only if run_tool resolves its CLI
```

If UPX-packed: `run_tool("upx-ucl", "-d ./bin -o unpacked")`. For custom packers: dump from memory after unpacking stub runs (gdb / x64dbg).

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

Policy blocks `ltrace` and `strace` on a sample through `run_tool` because they launch the program. Run a sample only inside the sandbox/VM (`docs/SANDBOX.md`); `strace -p <pid>` on an already-running process is allowed.

```bash
# Inside the sandbox/VM only
ltrace ./bin
strace -f -e trace=read,write,open ./bin

# Debugger
gdb-multiarch ./bin

# Branch flipping at a breakpoint
gdb> set $eax = 1       # change the return value to bypass a check
gdb> set $eflags ^= 0x40  # flip ZF to invert a jz/jnz
# or patch the jump permanently in radare2 / Ghidra
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

The `crypto` venv (`./install.sh --module crypto`) includes `z3`.

## 8. Don't waste time on

- Reading every disassembly line top-to-bottom — find `main`, focus there
- Reimplementing `strings`, `objdump`, `readelf` — use the tools
- Manual hex editing for big patches — use `radare2` or Ghidra's patch instructions

## After solve

Use the `writeup-template` skill. Include the key reverse-engineered algorithm or VM disassembly.
