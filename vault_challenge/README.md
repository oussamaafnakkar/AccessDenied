# 🔒 Vault Challenge v1.0

**Category:** Reverse Engineering  
**Difficulty:** ⭐⭐⭐ Intermediate  
**Flag Format:** `SBC{...}`

---

## Challenge Description

```
╔══════════════════════════════════════╗
║     🔒 THE VAULT CHALLENGE 🔒        ║
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

## Challenge Design Philosophy

### Fixed Hardware ID Approach

This challenge uses a **fixed hardware ID** (`0xABCD1234`) instead of reading the actual system volume serial. This design choice ensures:

**Cross-platform compatibility** - Works on Windows, Linux, macOS  
**Reproducible results** - All participants get the same flag  
**Educational focus** - Teaches RE concepts without hardware-specific barriers  
**Fair CTF experience** - No dependency on specific system configurations

### Key Derivation

```
Hardware ID:  0xABCD1234  (Fixed value)
Magic XOR:    0xDEADBEEF  (Hardcoded constant)
             ___________
Derived Key:  0x7560ACDB  (Result)
```

**Educational Note:** Real-world ransomware would:
- Actually read system-specific identifiers (volume serial, MAC address, etc.)
- Use cryptographically secure random number generation (CSPRNG)
- Implement asymmetric encryption (RSA-4096+)
- Generate unique keys per victim
- Securely delete plaintext keys from memory

This challenge intentionally uses weak cryptography to be solvable for educational purposes.

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
- XOR encryption fundamentals

**New to RE?** Read the [comprehensive guide](https://www.sbytec.com/blog/reverse-engineering/) first.

### Running the Challenge

```bash
# Download the challenge
cd bin/

# Option 1: Windows
vault_challenge_packed.exe

# Option 2: Linux (with Wine)
wine vault_challenge_packed.exe

# Expected output:
# [*] Hardware ID: 0xABCD1234
# [*] Derived Key: 0x7560ACDB
# [*] Attempting decryption...
#
# The flag is encrypted - your goal: reverse engineer to decrypt it!
```

---

## Hints (Progressive Spoilers)

<details>
<summary>Hint 1: Packer Detection</summary>

Run `strings` on the binary. Look for telltale signatures.

```bash
strings vault_challenge_packed.exe | grep -i upx
```

High entropy (>7.0 bits/byte) also indicates packing. Use the entropy analyzer:

```bash
cd solution/
python3 entropy_analyzer.py ../bin/vault_challenge_packed.exe
```
</details>

<details>
<summary>Hint 2: Unpacking</summary>

The binary is packed with UPX. You can unpack it with:

```bash
upx -d vault_challenge_packed.exe -o unpacked.exe
```

Or analyze it manually by finding the Original Entry Point (OEP) in a debugger.
</details>

<details>
<summary>Hint 3: Key Functions</summary>

Look for these functions in Ghidra:
- `vault_logic()` - Main encryption logic
- `get_hardware_id()` - Returns fixed value 0xABCD1234
- `derive_key()` - XORs HWID with 0xDEADBEEF
- `xor_decrypt()` - 4-byte XOR decryption routine
</details>

<details>
<summary>Hint 4: Crypto Weakness</summary>

The key is derived from:
```
0xABCD1234 ⊕ 0xDEADBEEF = 0x7560ACDB
```

This is NOT cryptographically secure. You can replicate this in Python and decrypt the flag!
</details>

<details>
<summary>Hint 5: Full Solution</summary>

Check `solution/vault_decryptor.py` for the complete automated solver.

Run it:
```bash
cd solution/
python3 vault_decryptor.py
```
</details>

---

## Solution

**SPOILER WARNING - Try solving first!**

See `solution/` directory for:
- `vault_decryptor.py` - Automated solver
- `entropy_analyzer.py` - Packer detection tool

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

| Technique | Implementation | Bypass Method |
|-----------|----------------|---------------|
| **Packing** | UPX compression | `upx -d binary.exe` |
| **Anti-Debug** | `IsDebuggerPresent()` | Patch JNZ → NOP or use ScyllaHide |
| **Obfuscation** | XOR-encoded flag | Reverse the XOR operation |
| **Key Derivation** | Fixed HWID ⊕ 0xDEADBEEF | Replicate in Python |

### Vulnerabilities (Intentional)

✗ **Fixed Hardware ID** - Not reading actual system (CTF design choice)  
✗ **Weak Key Derivation** - Simple XOR with magic constant  
✗ **Weak Encryption** - XOR with 4-byte repeating key  
✗ **No Authentication** - No HMAC or integrity verification  
✗ **Magic Constant** - 0xDEADBEEF is hardcoded and easily found

**Comparison to Real Ransomware:**

| Aspect | Vault Challenge | Real Ransomware (e.g., WannaCry) |
|--------|----------------|----------------------------------|
| Key Generation | Fixed HWID | CryptGenRandom (CSPRNG) |
| File Encryption | 4-byte XOR | AES-256-CBC |
| Key Protection | None | RSA-4096 public key encryption |
| Unique Keys | No | Yes, per victim |
| Decryptable | Yes (by design) | No (mathematically) |

---

## Building from Source

### Compilation

```bash
# Install dependencies (Linux)
sudo apt-get install gcc mingw-w64 upx

# Compile for Windows (from Linux using MinGW)
i686-w64-mingw32-gcc src/vault_challenge.c -o bin/vault_challenge.exe -O2 -s -static

# Or compile on Windows
gcc src/vault_challenge.c -o bin/vault_challenge.exe -O2 -s

# Pack with UPX
upx --best -o bin/vault_challenge_packed.exe bin/vault_challenge.exe

# Verify the build
cd bin/
sha256sum vault_challenge*.exe > checksums.txt
cat checksums.txt
```

### Expected Output

```bash
$ ./vault_challenge.exe

  ╔══════════════════════════════════════╗
  ║     🔒 THE VAULT CHALLENGE 🔒        ║
  ║                                      ║
  ║   Your files have been encrypted!    ║
  ║                                      ║
  ║   Reverse engineer this program to   ║
  ║   recover the hidden flag.           ║
  ║                                      ║
  ║   Hint: The key is in your machine   ║
  ╚══════════════════════════════════════╝

[*] Hardware ID: 0xABCD1234
[*] Derived Key: 0x7560ACDB
[*] Attempting decryption...

╔═══════════════════════════════════════╗
║ DECRYPTED FLAG:                       ║
║ SBC{r3v3rs3_3ng1n33r1ng_m4st3r}       ║
╚═══════════════════════════════════════╝

[+] Congratulations! You've cracked the vault!
[+] Share your success: #VaultChallenge #ReverseEngineering
```

---

## Detection

### YARA Rule

See `detection/vault.yar` for the full signature.

```yara
rule Vault_Challenge {
    meta:
        description = "Detects Vault Challenge binary"
        author = "Oussama Afnakkar"
        date = "2025-11-24"
    
    strings:
        $banner = "THE VAULT CHALLENGE" ascii
        $magic1 = { EF BE AD DE }  // 0xDEADBEEF
        $magic2 = { 34 12 CD AB }  // 0xABCD1234 (little-endian)
        $api1 = "IsDebuggerPresent" ascii
    
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        all of them
}
```

### Behavioral Indicators

Monitor for:
- High file entropy (7.0+ bits/byte)
- UPX packer signatures in strings
- `IsDebuggerPresent` API calls
- XOR operations on buffers
- Magic constants: 0xDEADBEEF, 0xABCD1234

---

## Educational Value

This challenge teaches:

1. **Packer Detection** - Entropy analysis, signature identification
2. **Unpacking** - Automated (UPX) and manual OEP finding
3. **Static Analysis** - Ghidra decompilation workflow, function identification
4. **Weak Crypto** - Understanding why XOR + fixed keys is insecure
5. **Anti-Analysis** - Recognizing and bypassing anti-debug checks
6. **Exploit Development** - Writing Python decryptors

---

## Real-World Parallels

Techniques demonstrated are used in:

| Technique | Example Malware |
|-----------|----------------|
| **UPX Packing** | Emotet, Trickbot (early versions) |
| **Hardware-based Keys** | Petya/NotPetya (MBR encryption) |
| **XOR Obfuscation** | Zeus (config files), Maze |
| **Anti-Debugging** | Dridex, Locky, TrickBot |

**Critical Difference:** Real ransomware uses proper cryptography:
- **AES-256-CBC/GCM** for file encryption (not XOR)
- **RSA-4096** for key protection (not simple XOR)
- **CSPRNG** for key generation (not predictable values)
- **Unique keys per victim** (not fixed values)

Result: Mathematically unbreakable without the attacker's private key. **Backups are your only defense.**

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
- Violate applicable laws (CFAA, DMCA, etc.)

The author is not responsible for misuse of this software.

---

## Support & Community

- **Full Writeup:** https://www.sbytec.com/accessdenied/vault-challenge/
- **Report Issues:** https://github.com/oussamaafnakkar/AccessDenied/issues
- **Twitter:** [@Oafnakkar](https://twitter.com/Oafnakkar)
- **Email:** oussamaafnakkar2002@gmail.com
- **Blog:** [Secure Byte Chronicles](https://www.sbytec.com)

---

## License

MIT License - See [LICENSE](../LICENSE) for details.

**Author:** Oussama Afnakkar  
**Blog:** [Secure Byte Chronicles](https://www.sbytec.com)  
**Date:** November 26, 2025  
**Version:** 1.0

---

<p align="center">
  <strong>🔓 Good luck cracking the vault!</strong><br>
  <em>Remember: Real ransomware is unbreakable. Always maintain backups.</em>
</p>
