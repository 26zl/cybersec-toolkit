---
name: ctf-crypto
description: Use when solving a CTF cryptography challenge — RSA, AES, classical ciphers, ECC, hash crypto, PRNGs, or unknown ciphertext. Provides a decision tree, attack catalog, and tool ordering specific to this installer's crypto module. Triggers on "ctf crypto", "rsa challenge", "aes ctr", "decrypt", "crypto category".
---

# CTF crypto methodology

Tool-first: use `suggest_for_ctf("crypto")` first, then this checklist for depth.

## 0. Where the libraries live

Crypto work runs out of tools and into arithmetic fast. The installer puts the
Python side in a venv the server can hand to scripts:

```python
run_script(code, venv="crypto")   # ~/.ctf-venvs/crypto
```

Contents: `pycryptodome` (`from Crypto...`), `sympy`, `gmpy2`, `numpy`, `z3`,
`fpylll` (+`cysignals`), `cypari2`. Install with
`./install.sh --module crypto`; check with `check_installed("ctf-crypto-venv")`.

`run_script` is gated behind `CYBERSEC_MCP_ALLOW_SCRIPTS=1` and is off by
default. If a challenge needs solver code, say so and let the user enable it and
restart the server — do not route around the gate with a shell.

SageMath is not installed by default — it is packaged on Debian and Arch but
not in current Ubuntu, Fedora or openSUSE, and the image is 1.4 GB.
`--enable-docker` pulls `sagemath/sagemath:latest`. Reach for it only for what the venv cannot do:
Coppersmith with `small_roots`, Groebner bases, generic curve arithmetic.

## 1. Identify what you have

```bash
file <input>
xxd <input> | head -50
strings <input> | head -50
```

- `.pem`, `.pub` → public key crypto (RSA/ECC)
- `BEGIN CERTIFICATE` → x509 — extract pubkey with `openssl x509 -in cert -pubkey -noout`
- High entropy ~7.99 bits/byte → encrypted/compressed
- Repeating block patterns → ECB
- Base64/hex prefix → decode first

## 2. RSA — the decision tree

Extract `n, e, c`:

```bash
openssl rsa -in pubkey.pem -pubin -text -noout
```

Then route by what `n` and `e` look like:

| Symptom | Attack | Tool |
| --- | --- | --- |
| Small `e` (3, 5), small message | Cube root attack | `RsaCtfTool`, `python3 -c "from gmpy2 import iroot..."` |
| `n` factorable on FactorDB | Factor + decrypt | `RsaCtfTool --uncipher c -n n -e e` |
| Two ciphertexts, same `n`, coprime `e` | Common modulus | `RsaCtfTool --attack commonmodulus` |
| Multiple users, small `e=k`, k pubkeys | Håstad broadcast | `RsaCtfTool --attack hastads` |
| Close `p` and `q` | Fermat factorization | `RsaCtfTool --attack fermat` |
| Wiener-applicable (`d` small) | Wiener's | `RsaCtfTool --attack wiener` |
| Partial `p` known | Coppersmith | sage / `RsaCtfTool --attack boneh_durfee` |
| Same `m`, two keys | Common plaintext | manual gcd |

Default first move: throw `n` at FactorDB (`run_tool("curl", "http://factordb.com/api?query=<n>")`) and at `RsaCtfTool` with all attacks enabled.

## 3. Symmetric / block

| Symptom | Attack | Tool |
| --- | --- | --- |
| ECB mode (identical blocks) | Block-shuffle / chosen plaintext | manual python with `Crypto.Cipher` |
| CBC + bit-flipping with padding oracle | Padding oracle | `padbuster`, custom python |
| CTR/OFB with key reuse | XOR streams (crib drag) | `xortool` |
| Stream cipher reused key | Crib drag | `xortool -l <len>` |
| AES-GCM nonce reuse | Forbidden attack | `nonce-disrespect` (clone if not in registry) |

## 4. Classical / encoding

```bash
# Auto-detect
echo "ciphertext" | python3 -c "import sys; from cryptanalysis import all_decoders; ..."
```

Tools in registry: `cipey`, `ciphey` (auto-decode), `quipqiup` (substitution), `dcode.fr` (web), `cryptii.com` (web). For classical/Caesar/Vigenère: try `ciphey` first.

## 5. Hash crypto

| Symptom | Attack |
| --- | --- |
| Length-extension on MD5/SHA1/SHA256 | `hash_extender`, `hashpump` |
| Hash with collision (MD5 chosen-prefix) | `hashclash` |
| Weak hash + known structure | hashcat with mask |

## 6. Elliptic curve

- Custom curve with smooth order → Pohlig-Hellman (`sympy.ntheory` for the
  factorization, manual CRT recombination)
- Singular curve → reduce to additive/multiplicative group
- Unknown group order → `cypari2` for point counting: `pari.ellsea(E)` runs SEA
  in seconds where a generic order algorithm will not finish
- Coppersmith / `small_roots` and Groebner bases have no venv equivalent — that
  is the case for the SageMath image

## 7. Lattice / LLL territory

If you see modular linear equations, low-density knapsacks, or HNP-shaped
problems — build the basis and reduce with `fpylll`. The pattern: small
unknowns, lots of equations, modular constraint.

```python
from fpylll import IntegerMatrix, LLL
B = IntegerMatrix.from_matrix(rows)
LLL.reduction(B)
```

Two things that cost hours if you hit them blind:

- `import fpylll` raises `ModuleNotFoundError: cysignals` unless cysignals is
  installed alongside it. fpylll declares no dependencies at all, so pip will
  not pull it in. The `crypto` venv installs both.
- fpylll's GSO/Babai/CVP path is double-precision. Above roughly 2^256 entries
  it returns wrong vectors or segfaults outright (SIGSEGV on 2^768 targets is
  the normal failure). Reduce the basis with fpylll, then do the closest-vector
  step yourself in exact arithmetic — integer rounding or `fractions.Fraction`
  over the Gram-Schmidt coefficients.

## Verification before claiming solve

- Decrypt the actual flag, paste it (in writeup, not chat output if sensitive)
- Confirm format matches `<comp>{...}` or platform-specific format
- If wrong: don't fabricate — say what you actually got and what the next attack is

## After solve

Use the `writeup-template` skill.
