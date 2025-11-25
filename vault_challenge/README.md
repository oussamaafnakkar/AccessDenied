# 🔒 Vault Challenge v1.0

**Category:** Reverse Engineering  
**Difficulty:** ⭐⭐⭐ Intermediate  
**Flag Format:** `SBC{...}`

---

## Challenge Description

```
╔══════════════════════════════════════╗
║     🔒 THE VAULT CHALLENGE 🔒       ║
║                                      ║
║   Your files have been encrypted!    ║
║                                      ║
║   Reverse engineer this program to   ║
║   recover the hidden flag.           ║
║                                      ║
║   Hint: The key is in your machine   ║
╚══════════════════════════════════════╝
```

A ransomware-like binary that demonstrates real-world malware techniques. Your mission: crack it to recover the hidden flag.

---

## What You'll Learn

- Entropy analysis for packer detection
- UPX unpacking (automated & manual)
- Static analysis with Ghidra/IDA
- Weak cryptography exploitation
- Anti-debugging bypass techniques
- Python exploit development

---

## Quick Start

### Prerequisites

**Tools:**
- [Ghidra](https://ghidra-sre.org/) or [IDA Free](https://hex-rays.com/ida-free/)
- [x64dbg](https://x64dbg.com/) (Windows) or GDB (Linux)
- [Python 3.8+](https://www.python.org/)
- Hex editor (HxD, 010 Editor)
- [UPX](https://upx.github.io/) (optional)

**Knowledge:**
- Basic x86 assembly
- C programming
- Python scripting

**New to RE?** Read the [guide](https://www.sbytec.com/blog/reverse-engineering/) first.

### Running the Challenge

```bash
# Download the challenge
cd bin/

# Option 1: Windows
vault_challenge_packed.exe

# Option 2: Linux (with Wine)
wine vault_challenge_packed.exe

# The binary will display encrypted output
# Your goal: reverse engineer it to get the flag!
```

---

## Hints (Progressive Spoilers)

<details>
<summary>Hint 1: Packer Detection</summary>

Run `strings` on the binary. Look for telltale signatures.

```bash
strings vault_challenge_packed.exe | grep -i upx
```

High entropy (>7.0 bits/byte) also indicates packing.
</details>

<details>
<summary>Hint 2: Unpacking</summary>

The binary is packed with UPX. You can unpack it with:

```bash
upx -d vault_challenge_packed.exe -o unpacked.exe
```

Or analyze it manually by finding the Original Entry Point (OEP).
</details>

<details>
<summary>Hint 3: Key Functions</summary>

Look for these functions in Ghidra:
- `vault_logic()` - Main encryption logic
- `get_hardware_id()` - Key derivation source
- `derive_key()` - Key generation
- `xor_decrypt()` - Encryption routine
</details>

<details>
<summary>Hint 4: Crypto Weakness</summary>

The key is derived from:
```
Hardware ID ⊕ 0xDEADBEEF
```

This is NOT cryptographically secure. You can replicate this in Python!
</details>

<details>
<summary>Hint 5: Full Solution</summary>

Check `solution/vault_decryptor.py` for the complete automated solver.
</details>

---

## Solution

**SPOILER WARNING - Try solving first! **

See `solution/` directory for:
- `vault_decryptor.py` - Automated solver
- `walkthrough.md` - Detailed step-by-step guide

**Full writeup:** https://www.sbytec.com/accessdenied/vault-challenge/

---

## Technical Details

### Binary Specifications

```
File Type:      PE32 Executable (Console)
Architecture:   Intel 80386 (32-bit)
Compiler:       GCC (MinGW)
Packer:         UPX 4.x
Language:       C
Size (packed):  ~12 KB
Size (unpacked): ~45 KB
Entropy:        7.85 bits/byte (packed)
                5.42 bits/byte (unpacked)
```

### Protection Mechanisms

| Technique | Implementation | Bypass |
|-----------|----------------|--------|
| Packing | UPX compression | `upx -d` |
| Anti-Debug | `IsDebuggerPresent()` | Patch JNZ → NOP |
| Obfuscation | XOR-encoded flag | Reverse XOR |
| Key Derivation | HWID ⊕ 0xDEADBEEF | Replicate in Python |

### Vulnerabilities (Intentional)

- **Weak Key Derivation** - Hardware-based (predictable)
- **Weak Encryption** - XOR with 4-byte key
- **No Key Integrity** - No HMAC/authentication
- **Magic Constant** - 0xDEADBEEF is hardcoded

---

## Building from Source

```bash
# Compile (requires MinGW on Linux or GCC on Windows)
gcc src/vault_challenge.c -o bin/vault_challenge.exe -O2 -s -static

# Pack with UPX
upx --best -o bin/vault_challenge_packed.exe bin/vault_challenge.exe

# Verify checksums
cd bin && sha256sum vault_challenge*.exe > checksums.txt
```

---

## Detection

### YARA Rule

See `detection/vault.yar` for the full signature.

```yara
rule Vault_Challenge {
    meta:
        description = "Detects Vault Challenge binary"
    strings:
        $s1 = "THE VAULT CHALLENGE"
        $s2 = { EF BE AD DE }  // 0xDEADBEEF
    condition:
        all of them
}
```

### Behavioral Indicators

- Calls to `GetVolumeInformationA`
- `IsDebuggerPresent` anti-debugging
- XOR operations on buffers
- High file entropy (packed)

---

## Educational Value

This challenge teaches:

1. **Packer Detection** - Entropy analysis, signature identification
2. **Unpacking** - Automated (UPX) and manual techniques
3. **Static Analysis** - Ghidra decompilation, function identification
4. **Weak Crypto** - Why hardware-based keys + XOR is insecure
5. **Anti-Analysis** - Recognizing and bypassing anti-debug checks
6. **Exploit Dev** - Writing Python decryptors

---

## Real-World Parallels

Techniques demonstrated are used in:

- **Emotet** - UPX packing (early versions)
- **Petya/NotPetya** - Hardware-based key derivation
- **Zeus** - XOR obfuscation
- **Dridex** - Anti-debugging techniques

**Note:** Real ransomware uses proper cryptography (AES-256 + RSA-4096), making recovery without the attacker's private key mathematically impossible.

---

## Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This software demonstrates security concepts and is intended for:
- Learning reverse engineering
- Authorized security research
- CTF competitions
- Academic study

**DO NOT:**
- Use maliciously
- Test on unauthorized systems
- Violate applicable laws

---

## Support

- **Full Writeup:** https://www.sbytec.com/accessdenied/vault-challenge/
- **Issues:** https://github.com/oussamaafnakkar/AccessDenied/issues
- **Twitter:** [@Oafnakkar](https://twitter.com/Oafnakkar)
- **Email:** oussamaafnakkar2002@gmail.com

---

## License

MIT License - See [LICENSE](../LICENSE) for details.

**Author:** Oussama Afnakkar  
**Blog:** [Secure Byte Chronicles](https://www.sbytec.com)  
**Date:** 24/11/2025

---

<p align="center">
  <strong>Good luck cracking the vault! 🔓</strong>
</p>
