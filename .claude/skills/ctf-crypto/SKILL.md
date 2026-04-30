---
name: ctf-crypto
description: Use when solving a CTF cryptography challenge — RSA, AES, classical ciphers, ECC, hash crypto, PRNGs, or unknown ciphertext. Provides a decision tree, attack catalog, and tool ordering specific to this installer's crypto module. Triggers on "ctf crypto", "rsa challenge", "aes ctr", "decrypt", "crypto category".
---

# CTF crypto methodology

Tool-first: use `suggest_for_ctf("crypto")` first, then this checklist for depth.

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

- Custom curve with smooth order → Pohlig-Hellman (sage)
- Singular curve → reduce to additive/multiplicative group
- Use `sage` for any non-trivial ECC. Install if missing.

## 7. Lattice / LLL territory

If you see modular linear equations, low-density knapsacks, or HNP-shaped problems — go to sage with `fpylll` or `flatter`. The pattern: small unknowns, lots of equations, modular constraint.

## Verification before claiming solve

- Decrypt the actual flag, paste it (in writeup, not chat output if sensitive)
- Confirm format matches `<comp>{...}` or platform-specific format
- If wrong: don't fabricate — say what you actually got and what the next attack is

## After solve

Use the `writeup-template` skill.
