---
name: ctf-forensics
description: Use when solving CTF forensics challenges — disk images, memory dumps, PCAPs, log analysis, file carving, deleted file recovery, NTFS/ext4 artifacts. Triggers on "ctf forensics", "memory dump", "pcap analysis", "disk image", "file carving", "log forensics".
---

# CTF forensics methodology

## 1. Identify the input

```bash
file <input>
xxd <input> | head -20
```

| Magic | Type | First tool |
| --- | --- | --- |
| `7F 45 4C 46` | ELF | use `ctf-rev` skill |
| `4D 5A` | PE | use `ctf-rev` skill |
| PK | ZIP/JAR/APK/Office | `unzip -l`, `binwalk` |
| `D4 C3 B2 A1` / `0A 0D 0D 0A` | PCAP / pcapng | wireshark |
| `4D 53 53 54 30 30 30` | Volatility memory raw | volatility |
| `45 56 46` | EWF / E01 image | `ewfmount` |
| Arbitrary blob, high entropy | Encrypted/compressed | binwalk / strings |

## 2. PCAP analysis

```bash
# Quick triage
capinfos <pcap>                                # summary
tshark -r <pcap> -q -z io,phs                  # protocol hierarchy
tshark -r <pcap> -q -z conv,tcp                # TCP conversations
tshark -r <pcap> -q -z http,tree               # HTTP requests

# Extract objects
tshark -r <pcap> --export-objects http,./out
foremost -i <pcap> -o ./carved

# Wireshark for visual: File → Export Objects → HTTP/SMB/etc

# Search payloads
tshark -r <pcap> -Y 'http.request.method == "POST"' -T fields -e http.file_data
```

USB HID keystroke decode (common challenge):

- Filter `usb.capdata` in tshark
- Map HID scancodes → keys (script: `usbkeyboard.py`, `usbrip`)

Bluetooth: `btsnoop` parser, `wireshark` natively decodes.

TLS with key log: `tshark -r <pcap> -o tls.keylog_file:keys.log` to decrypt.

## 3. Memory forensics (Volatility)

```bash
# Identify profile (vol2) or no profile needed (vol3)
vol.py -f mem.raw imageinfo                       # vol2
vol3 -f mem.raw windows.info                      # vol3

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
vol3 -f mem.raw windows.registry.printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"

# Linux
vol3 -f mem.raw linux.bash                        # bash history
vol3 -f mem.raw linux.psaux
```

## 4. Disk image analysis

```bash
# Mount EWF
ewfmount disk.E01 /mnt/ewf
mmls /mnt/ewf/ewf1                                # partition table
fsstat -o <offset> /mnt/ewf/ewf1                  # filesystem info
fls -r -o <offset> /mnt/ewf/ewf1                  # file list (incl. deleted)
icat -o <offset> /mnt/ewf/ewf1 <inode> > out      # extract by inode

# Or mount as loopback if raw
losetup -fP --read-only disk.raw
# Then mount partitions

# Carve unallocated
photorec
foremost -i disk.raw -o ./carved
scalpel disk.raw                                  # config-driven carving
```

Browser history: `dumpzilla` (Firefox), `hindsight` (Chrome), or query SQLite directly.

NTFS artifacts: `MFTECmd`, `Plaso`/`log2timeline` for super timeline.

Registry: `regripper`, `RegistryExplorer`, manual hive parsing with `python-registry`.

## 5. File carving / steganographic-adjacent

If forensics challenge but file looks like an image/audio: try `ctf-stego` skill first. Forensics overlap heavily.

```bash
binwalk -e <file>           # extract embedded files
binwalk --dd='.*' <file>    # dump everything
foremost -i <file> -o out
```

## 6. Log analysis

```bash
# Apache / nginx
goaccess access.log -o report.html

# Windows event logs
EvtxECmd -f Security.evtx --csv ./out
chainsaw hunt -r sigma_rules ./logs

# Generic
zgrep -h "pattern" *.log.gz | sort | uniq -c | sort -rn
```

## 7. Don't waste time on

- Manual hex parsing of well-known formats (PNG, ZIP) — use `binwalk`, `foremost`, `pngcheck`
- Reimplementing tshark filters in Python — tshark CLI is faster
- Brute-forcing zip passwords without first checking for known plaintext attack (`bkcrack`)

## After solve

Use the `writeup-template` skill.
