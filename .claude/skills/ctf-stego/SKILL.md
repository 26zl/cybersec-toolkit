---
name: ctf-stego
description: Use when solving steganography CTF challenges — hidden data in images (PNG/JPG/BMP), audio (WAV/MP3), video, or text. Triggers on "ctf stego", "steganography", "hidden in image", "audio stego", "lsb".
---

# CTF stego methodology

> **Pre-flight.** Confirm the event rules allow AI assistance (`authorization-gate`). Start with `suggest_for_ctf` or `guided_assessment`. Commands below are CLI notation: run them with `run_tool`/`run_pipeline` using registry names (`list_tools`), and `run_script` only for real logic. If policy blocks a command, tell the operator; do not fall back to the client shell. A tool that is not in the registry is a recommendation to the user (approval-gated install), not a bare command.

## 0. CRITICAL — never `Read` an unvalidated image

Per CLAUDE.md: reading a corrupt image poisons the conversation. Validate first:

```bash
run_tool("file", "/path/to/image")
run_tool("identify", "/path/to/image")     # ImageMagick
# or run_script:
# from PIL import Image; img = Image.open(path); print(img.size, img.mode)
```

Only `Read` the image after both checks pass.

## 1. Triage every input

```text
run_tool("file", "<file>")
run_pipeline([{"tool": "xxd", "args": "<file>"}, {"tool": "head", "args": "-30"}])
run_tool("exiftool", "<file>")             # metadata — flag often hides here
run_pipeline([{"tool": "strings", "args": "<file>"}, {"tool": "grep", "args": "-i -e ctf -e flag -e key -e pass"}, {"tool": "head"}])
run_tool("binwalk", "<file>")              # multi-file polyglots
```

Always check metadata first. ~30% of intro stego is just `exiftool`.

## 2. Image (PNG / JPG / BMP / GIF)

| Technique | Tool / approach |
| --- | --- |
| LSB in pixels | `zsteg` (PNG/BMP), `stegsolve` |
| EOF data after IEND/EOI | `binwalk -e`, manual hex |
| JPG specific | `steghide extract -sf <file>` (often with empty pass), `stegseek` for brute |
| PNG color planes | `stegsolve` (visual layer toggle) |
| LSB matching, custom | `zsteg -a`, then write custom Python with PIL |
| Polyglot (file with valid headers for multiple formats) | `binwalk`, `foremost` |
| File appended after IEND chunk (PNG) | `pngcheck -v`, manual carve |
| Modified/extra chunks | `pngcheck -v`, `pngcsum` |
| Width/height tampering (PNG) | edit IHDR width/height, recalc CRC — `tweakpng` style |

```text
# zsteg covers most LSB cases for PNG/BMP
run_tool("zsteg", "-a image.png")

# steghide brute (jpg/wav/bmp); wordlist path: see security-wordlists (the misc module unpacks rockyou when SecLists is installed)
run_tool("stegseek", "image.jpg /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt")

# stegsolve is a GUI git clone (not run_tool); the operator toggles layers manually
```

## 3. Audio (WAV / MP3 / FLAC / OGG)

| Technique | Tool |
| --- | --- |
| LSB in samples | `wavsteg`, custom python |
| Steghide payload | `steghide`, `stegseek` |
| Spectrogram (visual hidden in freq domain) | `audacity` view spectrogram, `sonic-visualiser` |
| DTMF tones | `multimon-ng -a DTMF`, manual tone analysis |
| Morse | listen by ear, then `morse-decoder` or manual |
| SSTV (slow-scan TV in audio) | `qsstv`, `slowrx` |

```bash
# Spectrogram via sox
sox audio.wav -n spectrogram -o spec.png
# Then validate spec.png before reading (see step 0)

# DTMF
multimon-ng -a DTMF audio.wav
```

## 4. Video / GIF

```bash
# Extract frames
ffmpeg -i video.mp4 -vf fps=1 frames/frame_%04d.png

# Per-frame stego
for f in frames/*.png; do zsteg -a "$f" 2>/dev/null | grep -i "flag\|ctf"; done

# Audio track
ffmpeg -i video.mp4 -vn audio.wav
# Then audio analysis
```

## 5. Text / Unicode

| Technique | Tool |
| --- | --- |
| Zero-width characters | `zwsp-steg`, manual unicode inspect |
| Whitespace stego | `snow`, `stegsnow` |
| Homoglyph substitution | unicode normalize + diff |
| Base-N nested encodings | `ciphey`, manual |
| Bacon / null cipher | manual + dcode.fr |

```bash
# Show every character including invisibles
python3 -c "import sys; [print(repr(c), hex(ord(c))) for c in open(sys.argv[1]).read()]" file.txt
```

## 6. Less common

- **PDF:** `pdf-parser`, `peepdf`, `qpdf --qdf` — check streams, annotations, JS, attachments
- **Office docs:** `oletools` (`olevba`, `oleid`), `oledump`, unzip the .docx/.xlsx
- **QR / barcode:** `zbarimg`, `zxing` — also try partial QR reconstruction
- **DNA/protein sequences:** ROT/encoding tricks, decode A/C/G/T as base-4

## 7. Default workflow

1. `exiftool` + `strings` + `binwalk -e` always first
2. If image → `zsteg -a` (PNG/BMP) OR `stegseek` (JPG)
3. If audio → spectrogram view
4. If nothing obvious → `stegsolve` GUI for visual analysis
5. If still nothing → metadata might encode the answer (look at GPS, comment, software field)

## 8. Don't waste time on

- LSB scripts when `zsteg` exists
- Manually viewing spectrograms in matplotlib when audacity/sonic-visualiser exist
- Reading the image with `Read` before validation (see step 0)

## After solve

Use the `writeup-template` skill.
