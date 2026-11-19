---
name: ctf-forensics
description: Use when solving CTF forensics challenges — disk images, memory dumps, PCAPs, log analysis, file carving, deleted file recovery, NTFS/ext4 artifacts. Triggers on "ctf forensics", "memory dump", "pcap analysis", "disk image", "file carving", "log forensics".
---

# CTF forensics methodology

> **Pre-flight.** Confirm the event rules allow AI assistance (`authorization-gate`). Start with `suggest_for_ctf` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command, tell the operator; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 1. Identify the input

```text
run_tool("file", "<input>")
run_pipeline([{"tool": "xxd", "args": "<input>"}, {"tool": "head", "args": "-20"}])
```

| Magic | Type | First tool |
| --- | --- | --- |
| `7F 45 4C 46` | ELF | use `ctf-rev` skill |
| `4D 5A` | PE | use `ctf-rev` skill |
| PK | ZIP/JAR/APK/Office | `unzip -l`, `binwalk` |
| `D4 C3 B2 A1` / `0A 0D 0D 0A` | PCAP / pcapng | wireshark |
| `45 56 46` | EWF / E01 image | `ewfmount` |
| Arbitrary blob, high entropy | Encrypted/compressed | binwalk / strings |

## 2. PCAP analysis

```text
# Quick triage (capinfos ships with wireshark but is not a registry executable; use tshark)
run_tool("tshark", "-r <pcap> -q -z io,phs")                  # protocol hierarchy
run_tool("tshark", "-r <pcap> -q -z conv,tcp")                # TCP conversations
run_tool("tshark", "-r <pcap> -q -z http,tree")               # HTTP requests

# Extract objects
run_tool("tshark", "-r <pcap> --export-objects http,./out")
run_tool("foremost", "-i <pcap> -o ./carved")

# Search payloads
run_tool("tshark", "-r <pcap> -Y http.request.method==POST -T fields -e http.file_data")
```

USB HID keystroke decode (common challenge):

- Filter `usb.capdata` in tshark
- Map HID scancodes → keys (script: `usbkeyboard.py`, `usbrip`)

Bluetooth: `btsnoop` parser, `wireshark` natively decodes.

TLS with key log: `run_tool("tshark", "-r <pcap> -o tls.keylog_file:keys.log")` to decrypt.

## 3. Memory forensics (Volatility)

```text
# Registry name is volatility3 (binary vol); `vol3` below is shorthand for run_tool("volatility3", ...).
# No profile is needed with vol3
vol3 -f mem.raw windows.info

# Common plugins
vol3 -f mem.raw windows.pslist
vol3 -f mem.raw windows.cmdline
vol3 -f mem.raw windows.netstat
vol3 -f mem.raw windows.malfind
vol3 -f mem.raw windows.dumpfiles --pid <pid>
vol3 -f mem.raw windows.hashdump
vol3 -f mem.raw windows.lsadump
vol3 -f mem.raw windows.consoles                  # cmd.exe history
vol3 -f mem.raw windows.clipboard
vol3 -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Linux
vol3 -f mem.raw linux.bash                        # bash history
vol3 -f mem.raw linux.psaux
```

## 4. Disk image analysis

`mmls`, `fls`, `icat`, `fsstat` and the other Sleuth Kit binaries run through `run_tool` when the `sleuthkit` registry tool is installed. `ewfmount` (ewf-tools) and `photorec` (testdisk) are not covered by the registry's extra-binary map, so `run_tool` may reject them; recommend an approved install instead of using the client shell.

```text
# Mount EWF
ewfmount disk.E01 /mnt/ewf
mmls /mnt/ewf/ewf1                                # partition table
fsstat -o <offset> /mnt/ewf/ewf1                  # filesystem info
fls -r -o <offset> /mnt/ewf/ewf1                  # file list (incl. deleted)
icat -o <offset> /mnt/ewf/ewf1 <inode> > out      # extract by inode

# Prefer ewfmount / Sleuth Kit tools (read-only) over mounting.
# Mounting needs root, which the sandbox does not grant by default. If unavoidable:
losetup -fP --read-only disk.raw
mount -o ro,noload,noexec,nodev,nosuid /dev/loop0p1 /mnt/img

# Carve unallocated (foremost and scalpel are registry tools)
run_tool("foremost", "-i disk.raw -o ./carved")
run_tool("scalpel", "disk.raw")                   # config-driven carving
```

Browser history: `dumpzilla` (Firefox), `hindsight` (Chrome), or query SQLite directly.

NTFS artifacts: `MFTECmd`, `Plaso`/`log2timeline` for super timeline.

Registry: `regripper`, `RegistryExplorer`, manual hive parsing with `python-registry`.

## 5. File carving / steganographic-adjacent

If forensics challenge but file looks like an image/audio: try `ctf-stego` skill first. Forensics overlap heavily.

```text
run_tool("binwalk", "-e <file>")            # extract embedded files (--dd and -D are blocked by policy)
run_tool("foremost", "-i <file> -o out")
```

## 6. Log analysis

```text
# Windows event logs
run_tool("chainsaw", "hunt ./logs -r sigma_rules")

# Generic (globs are not expanded: name each file)
run_pipeline([{"tool": "zgrep", "args": "-h pattern a.log.gz"}, {"tool": "sort"}, {"tool": "uniq", "args": "-c"}, {"tool": "sort", "args": "-rn"}])
```

`goaccess` and `EvtxECmd` are not in the registry; recommend them to the operator or use `python-evtx` (pipx) for `.evtx` files.

## 7. Don't waste time on

- Manual hex parsing of well-known formats (PNG, ZIP) — use `binwalk`, `foremost`, `pngcheck`
- Reimplementing tshark filters in Python — tshark CLI is faster
- Brute-forcing zip passwords without first checking for known plaintext attack (`bkcrack`)

## After solve

Use the `writeup-template` skill.
