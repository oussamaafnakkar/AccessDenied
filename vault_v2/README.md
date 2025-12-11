# 🔒 Vault Challenge v2.0

**Category:** Reverse Engineering  
**Difficulty:** ⭐⭐⭐⭐ Advanced  
**Flag Format:** `SBC{d3crypt3d_53ss10n_<session_id>_v2}`

---

## Challenge Description

```
╔══════════════════════════════════════╗
║     🔒 THE VAULT CHALLENGE v2 🔒     ║
║                                      ║
║   Your files have been encrypted!    ║
║                                      ║
║   Reverse engineer this program to   ║
║   recover the hidden flag.           ║
║                                      ║
║   Hint: Nothing is as it seems...    ║
╚══════════════════════════════════════╝
```

The **Vault Challenge v2** is a significantly more advanced reverse engineering challenge that builds upon the concepts from v1. This time, you'll face:

- **Custom packer** (not UPX - manual unpacking required)
- **Multi-stage encryption** (XOR → RC4)
- **Complex key derivation** (HWID + username + timestamp)
- **Anti-analysis techniques** (VM detection, timing checks)
- **Encrypted strings** (all strings obfuscated at runtime)

Your mission: Unpack the binary, reverse the custom packer stub, reconstruct the key derivation algorithm, and decrypt the multi-layer encrypted flag.

---

## What You'll Learn

**Packer Analysis** - Custom packer detection and reversing  
**Manual Unpacking** - Finding OEP without automated tools  
**Assembly Analysis** - Reading and understanding x86 stub code  
**Multi-Stage Crypto** - XOR → RC4 decryption chain  
**Complex Key Derivation** - Multi-source key generation  
**Anti-Analysis Bypass** - VM detection and timing checks  
**String Deobfuscation** - Runtime XOR string decryption  
**Python Exploit Dev** - Writing comprehensive automated solvers

---

## Progression from v1

| Aspect | Vault v1 | Vault v2 |
|--------|----------|----------|
| **Packer** | UPX (automated) | Custom (manual required) |
| **Encryption** | XOR only | XOR → RC4 (layered) |
| **Key Derivation** | Simple HWID ⊕ magic | HWID + username_hash + timestamp |
| **Anti-Analysis** | `IsDebuggerPresent()` only | VM detect + timing + debugger |
| **String Obfuscation** | None | All strings XOR encrypted |
| **Unpacking** | `upx -d` | Custom stub analysis |
| **Difficulty** | ⭐⭐⭐ Intermediate | ⭐⭐⭐⭐ Advanced |

---

## Challenge Design Philosophy

### Why Custom Packer?

Real-world malware rarely uses off-the-shelf packers like UPX. Attackers write custom packers to:
- Evade signature-based detection
- Complicate analysis
- Protect intellectual property
- Add anti-debugging layers

This challenge teaches you to analyze unknown packers by:
- Identifying packer signatures (PUSHAD, decryption loops)
- Tracing execution to find OEP (Original Entry Point)
- Extracting and reversing the unpacking stub
- Reconstructing the packing algorithm

### Fixed Values for CTF Reproducibility

Like v1, this challenge uses **fixed values** to ensure all participants get the same flag:

| Component | Value | Reason |
|-----------|-------|--------|
| **Hardware ID** | `0xABCD1234` | Cross-platform consistency |
| **Username** | `"CTFPlayer"` | Reproducible hash |
| **Timestamp** | `0x65432100` | Deterministic session ID |

**Educational Note:** Real ransomware would:
- Actually read system-specific identifiers
- Generate unique keys per victim
- Use cryptographically secure RNG (not predictable XOR)
- Implement proper key management (RSA + AES)

This challenge intentionally uses weaker crypto to be solvable for educational purposes.

---

## Quick Start

### Prerequisites

**Tools:**
- [Ghidra](https://ghidra-sre.org/) or [IDA Free](https://hex-rays.com/ida-free/)
- [x64dbg](https://x64dbg.com/) (Windows) or GDB (Linux)
- [Python 3.8+](https://www.python.org/)
- Hex editor (HxD, 010 Editor)
- [NASM](https://www.nasm.us/) (if rebuilding)

**Knowledge:**
- Strong x86 assembly understanding
- PE file format internals
- Packer/unpacker concepts
- Stream cipher algorithms (RC4)
- Python scripting

**Prerequisite Challenges:**
-  [Vault Challenge v1](/vault_challenge/) - Complete this first!
-  [Reverse Engineering Guide](https://www.sbytec.com/blog/reverse-engineering/)

### Running the Challenge

```bash
# Download the challenge
cd bin/

# Option 1: Windows
vault_v2.exe

# Option 2: Linux (with Wine)
wine vault_v2.exe

# Expected output (without unpacking/analysis):
# [Encrypted/obfuscated output]
# The flag is hidden behind multiple layers - your goal: unpack and decrypt!
```

---

## Hints (Progressive Spoilers)

<details>
<summary>Hint 1: Packer Detection</summary>

Run basic reconnaissance:

```bash
# Check file type
file vault_v2.exe

# Extract strings (will be minimal due to packing)
strings vault_v2.exe | less

# Check entropy
python3 solution/entropy_analyzer.py bin/vault_v2.exe
```

High entropy in a specific section? Look for:
- **PUSHAD (0x60)** at entry point
- Uncommon section names (`.packer`, `.packed`)
- XOR decryption loops in disassembly
</details>

<details>
<summary>Hint 2: Finding the Unpacking Stub</summary>

Load in x64dbg or Ghidra:

1. Entry point should show **PUSHAD** instruction
2. Look for a loop with XOR operations
3. After the loop, find **POPAD** 
4. Followed by JMP to OEP (Original Entry Point)

**Pattern to look for:**
```nasm
PUSHAD
; ... setup code ...
decrypt_loop:
    XOR [esi], key_byte
    INC esi
    LOOP decrypt_loop
POPAD
JMP original_entry_point
```
</details>

<details>
<summary>Hint 3: Automated Unpacking</summary>

Use the provided unpacker:

```bash
cd solution/
python3 unpacker.py ../bin/vault_v2.exe unpacked.exe
```

This extracts and decrypts the `.text` section. Now analyze the unpacked binary in Ghidra.
</details>

<details>
<summary>Hint 4: Key Derivation Algorithm</summary>

In the unpacked binary, look for `derive_keys()` function:

```c
// Key derivation stages
stage1 = hwid ^ 0xDEADBEEF
stage2 = djb2_hash("CTFPlayer") ^ 0x65432100
xor_key = (stage1 + stage2) ^ 0x13371337
```

Constants to find:
- `0xDEADBEEF` (MAGIC_1)
- `0x13371337` (MAGIC_2)
- `0xABCD1234` (HWID)
- `"CTFPlayer"` (username)
</details>

<details>
<summary>Hint 5: Multi-Stage Decryption</summary>

The flag undergoes TWO encryption layers:

**Stage 1: XOR**
```python
xor_key = 0x08FDBF3D  # Derived from key derivation
xor_decrypt(encrypted_flag, xor_key)
```

**Stage 2: RC4**
```python
rc4_key = repeat_bytes(xor_key, 16)  # 3d bf fd 08 repeated
rc4_decrypt(xor_decrypted, rc4_key)
```

Use the provided scripts:
```bash
python3 decrypt_xor.py   # Stage 1
python3 decrypt_rc4.py   # Stage 2
```
</details>

<details>
<summary>Hint 6: Complete Automated Solution</summary>

For the full solution:

```bash
cd solution/
python3 full_solver.py ../bin/vault_v2.exe
```

This automates:
- Packer detection
- Key derivation replication
- XOR decryption
- RC4 decryption
- Flag extraction
</details>

---

## Solution

**SPOILER WARNING - Try solving first!**

See `solution/` directory for:
- `unpacker.py` - Automated unpacker
- `decrypt_xor.py` - Stage 1 (XOR) decryptor
- `decrypt_rc4.py` - Stage 2 (RC4) decryptor
- `full_solver.py` - Complete automated solver
- `entropy_analyzer.py` - Packer detection tool

**Full writeup:** https://www.sbytec.com/accessdenied/vault-v2/

---

## Technical Details

### Binary Specifications

```
File Type:      PE32 Executable (Console)
Architecture:   Intel 80386 (32-bit)
Compiler:       GCC (MinGW)
Packer:         Custom (XOR-based)
Language:       C + x86 Assembly (stub)
Size (packed):  ~65 KB
Size (unpacked): ~90 KB
Entropy:        6.58 bits/byte (packed .packer section)
                5.68 bits/byte (unpacked .text)
```

### Custom Packer Architecture

```
┌─────────────────────────────────────┐
│      Original Binary (.exe)         │
│  ┌──────────────────────────────┐   │
│  │  .text (executable code)     │   │
│  │  .data (initialized data)    │   │
│  │  .rdata (encrypted_flag[])   │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
              ↓ PACKER
┌─────────────────────────────────────┐
│      Packed Binary (vault_v2.exe)   │
│  ┌──────────────────────────────┐   │
│  │  .packer (NEW SECTION)       │◄──── New Entry Point
│  │    ├─ Unpacking stub (ASM)   │   │
│  │    ├─ Encrypted XOR key      │   │
│  │    └─ Encrypted .text        │   │
│  ├──────────────────────────────┤   │
│  │  .data (unchanged)           │   │
│  │  .rdata (still encrypted)    │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
```

### Packer Stub Behavior (Runtime)

```nasm
; Packer stub (simplified - see packer_stub.asm for full version)
_start:
    PUSHAD                          ; Save all registers
    
    ; Position-independent code
    CALL get_eip
get_eip:
    POP  EBP
    SUB  EBP, (get_eip - _start)    ; EBP = base address
    
    ; Decrypt the 16-byte XOR key
    LEA  ESI, [EBP + encrypted_xor_key]
    LEA  EDI, [EBP + decrypted_key_buffer]
    MOV  ECX, 16
decrypt_key_loop:
    LODSB
    XOR  AL, 0x42                   ; Key encryption byte
    STOSB
    LOOP decrypt_key_loop
    
    ; Decrypt packed .text section
    MOV  ECX, packed_size           ; Patched by packer.py
    MOV  EDI, dest_va               ; Patched by packer.py
    LEA  ESI, [EBP + packed_data]
    LEA  EBX, [EBP + decrypted_key_buffer]
    XOR  EDX, EDX                   ; Key index
    
decrypt_text_loop:
    LODSB
    XOR  AL, BYTE [EBX + EDX]       ; Rotating XOR with 16-byte key
    STOSB
    INC  EDX
    AND  EDX, 0x0F                  ; Wrap at 16
    LOOP decrypt_text_loop
    
    POPAD                           ; Restore registers
    JMP  original_entry_point       ; Patched by packer.py
```

### Protection Mechanisms

| Technique | Implementation | Bypass Method |
|-----------|----------------|---------------|
| **Custom Packer** | XOR-encrypted .text | Manual unpacking + stub analysis |
| **Encrypted Key** | XOR key encrypted with 0x42 | Reverse stub to extract key |
| **Anti-Debug** | `IsDebuggerPresent()` | Patch JNZ → NOP or use ScyllaHide |
| **Anti-VM** | Registry checks (VBox/VMware) | Patch checks or use bare metal |
| **Timing Check** | RDTSC delta threshold | Patch comparison or use hardware debugger |
| **String Obfuscation** | All strings XOR'd at runtime | Analyze `decrypt_string()` function |
| **Multi-Stage Crypto** | XOR → RC4 | Reverse both layers sequentially |

### Key Derivation Deep Dive

```c
// Stage 1: Hardware ID (fixed for CTF)
uint32_t hwid = 0xABCD1234;

// Stage 2: Username hash (DJB2 algorithm)
uint32_t username_hash = djb2_hash("CTFPlayer");
// Result: 0x7B8A4567

// Stage 3: Timestamp (fixed for CTF)
uint32_t timestamp = 0x65432100;

// Stage 4: Multi-stage derivation
uint32_t stage1 = hwid ^ 0xDEADBEEF;
// 0xABCD1234 ^ 0xDEADBEEF = 0x7560ACDB

uint32_t stage2 = username_hash ^ timestamp;
// 0x7B8A4567 ^ 0x65432100 = 0x1EC96467

uint32_t xor_key = (stage1 + stage2) ^ 0x13371337;
// (0x7560ACDB + 0x1EC96467) ^ 0x13371337 = 0x08FDBF3D

// Stage 5: RC4 key (repeat XOR key to 16 bytes)
uint8_t rc4_key[16] = {
    0x3d, 0xbf, 0xfd, 0x08,  // Little-endian XOR key
    0x3d, 0xbf, 0xfd, 0x08,  // Repeated
    0x3d, 0xbf, 0xfd, 0x08,
    0x3d, 0xbf, 0xfd, 0x08
};
```

### Flag Generation Logic

```c
// Session ID calculation
uint32_t session_id = FIXED_TIMESTAMP ^ SESSION_XOR;
// 0x65432100 ^ 0x12345678 = 0x77777778

// Flag format
sprintf(flag, "SBC{d3crypt3d_53ss10n_%08x_v2}", session_id);
// Result: SBC{d3crypt3d_53ss10n_77777778_v2}
```

### Vulnerabilities (Intentional)

 **Fixed Hardware ID** - Not reading actual system (CTF design choice)  
 **Predictable Username** - Hardcoded "CTFPlayer"  
 **Fixed Timestamp** - Not using actual time  
 **Weak Packer** - XOR encryption (not AES/ChaCha20)  
 **RC4 Stream Cipher** - Known biases and weaknesses  
 **No Key Stretching** - No PBKDF2/Argon2  
 **No Authentication** - No HMAC or authenticated encryption

**Comparison to Real Ransomware:**

| Aspect | Vault v2 | Real Ransomware (e.g., REvil) |
|--------|----------|-------------------------------|
| Packer | Custom XOR | Polymorphic/metamorphic |
| Key Generation | Fixed values | CryptGenRandom (CSPRNG) |
| File Encryption | XOR → RC4 | AES-256-GCM |
| Key Protection | None | RSA-4096 public key |
| Unique Keys | No | Yes, per victim + per file |
| Decryptable | Yes (by design) | No (mathematically) |
| Anti-Analysis | Basic | Advanced (sandbox detection, etc.) |

---

## Building from Source

### Prerequisites

```bash
# Linux (Debian/Ubuntu)
sudo apt-get install mingw-w64 nasm python3

# macOS (Homebrew)
brew install mingw-w64 nasm python3

# Verify installations
i686-w64-mingw32-gcc --version
nasm -v
python3 --version
```

### Compilation

```bash
# Option 1: Use Makefile (recommended)
make clean && make

# Option 2: Manual compilation
# Step 1: Compile unpacked binary
i686-w64-mingw32-gcc src/vault_v2.c -o bin/vault_v2_unpacked.exe -O2 -s -static -m32

# Step 2: Assemble packer stub
nasm -f bin src/packer_stub.asm -o bin/stub.bin

# Step 3: Pack the binary
python3 src/packer.py bin/vault_v2_unpacked.exe bin/vault_v2.exe bin/stub.bin

# Step 4: Generate checksums
cd bin/
sha256sum vault_v2*.exe > checksums.txt
```

### Expected Output

```bash
$ ./vault_v2_unpacked.exe

  ╔══════════════════════════════════════╗
  ║     🔒 THE VAULT CHALLENGE v2 🔒     ║
  ║                                      ║
  ║   Your files have been encrypted!    ║
  ║                                      ║
  ║   Reverse engineer this program to   ║
  ║   recover the hidden flag.           ║
  ║                                      ║
  ║   Hint: Nothing is as it seems...    ║
  ╚══════════════════════════════════════╝

[*] Hardware ID: 0xABCD1234
[*] Derived Key: 0x08FDBF3D
[*] Decrypting flag...

╔═══════════════════════════════════════╗
║ FLAG: SBC{d3crypt3d_53ss10n_77777778_v2} ║
╚═══════════════════════════════════════╝

[+] Congratulations! You've cracked the vault!
```

---

## Detection

### YARA Rule

See `detection/vault_v2.yar` for the complete signature.

```yara
rule Vault_Challenge_v2 {
    meta:
        description = "Detects Vault Challenge v2 (packed and unpacked)"
        author = "Oussama Afnakkar"
        date = "2025-01-01"
    
    strings:
        $banner = "Your files have been encrypted!" ascii
        $magic1 = { EF BE AD DE }  // 0xDEADBEEF
        $magic2 = { 37 13 37 13 }  // 0x13371337
        $hwid = { 34 12 CD AB }    // 0xABCD1234
        $user = "CTFPlayer" ascii
        $rc4_pattern = { 3D BF FD 08 3D BF FD 08 }
        $pushad = { 60 }           // Packer stub
        $stub_marker = { 13 37 DE AD BE EF CA FE BA BE F0 0D C0 DE 42 00 }
    
    condition:
        uint16(0) == 0x5A4D and
        (all of ($banner, $magic1, $magic2) or any of ($stub_marker, $pushad))
}
```

### Behavioral Indicators

Monitor for:
- High entropy in `.packer` or `.packed` sections
- PUSHAD instruction at entry point
- XOR decryption loops with rotating key
- Registry queries (VM detection)
- RDTSC timing checks
- Dynamic string decryption at runtime
- Magic constants: 0xDEADBEEF, 0x13371337, 0xABCD1234

---

## Educational Value

This challenge teaches:

1. **Custom Packer Analysis** - Understanding proprietary packing schemes
2. **Manual Unpacking** - Finding OEP without automated tools
3. **Assembly Debugging** - Tracing stub execution step-by-step
4. **Complex Key Derivation** - Multi-source key generation patterns
5. **Layered Cryptography** - Sequential XOR → RC4 decryption
6. **Anti-Analysis Techniques** - VM detection, timing checks, string obfuscation
7. **Python Reverse Engineering** - Writing comprehensive automated solvers
8. **Real-World Skills** - Techniques directly applicable to malware analysis

---

## Real-World Parallels

Techniques demonstrated are used in:

| Technique | Example Malware |
|-----------|----------------|
| **Custom Packers** | Emotet, TrickBot, APT malware |
| **XOR Obfuscation** | Zeus, CryptoLocker configs |
| **RC4 Encryption** | Petya (older variants), WannaCry (partial) |
| **Anti-VM** | Almost all modern malware families |
| **Timing Checks** | Dridex, Maze ransomware |
| **String Encryption** | Cobalt Strike beacons, APT tools |

**Critical Difference:** Real ransomware uses:
- **Polymorphic/metamorphic packers** (changes with each build)
- **AES-256-GCM** for file encryption (not RC4)
- **RSA-4096+** for key protection (not XOR)
- **CSPRNG** for key generation (not predictable values)
- **Unique keys per victim** (not reproducible)
- **Authenticated encryption** (GCM mode, not plain RC4)

Result: Mathematically unbreakable without the attacker's private key. **Air-gapped backups are your only defense.**

---

## Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This software demonstrates security concepts and is intended for:
- Learning reverse engineering
- Malware analysis training
- Authorized security research
- CTF competitions
- Academic study

**DO NOT:**
- Use maliciously
- Test on unauthorized systems
- Violate applicable laws (CFAA, DMCA, etc.)
- Deploy in production environments

The author is not responsible for misuse of this software.

---

## Support & Community

- **Full Writeup:** https://www.sbytec.com/accessdenied/vault-v2/
- **Report Issues:** https://github.com/oussamaafnakkar/AccessDenied/issues
- **Twitter:** [@Oafnakkar](https://twitter.com/Oafnakkar)
- **Email:** oussamaafnakkar2002@gmail.com
- **Blog:** [Secure Byte Chronicles](https://www.sbytec.com)

---

## Related Challenges

-  [Vault Challenge v1](/vault_challenge/) - Prerequisite (UPX packing, XOR crypto)
-  **Vault Challenge v3** - Coming Q1 2025 (Kernel-mode rootkit)
-  **Firmware Extractor** - Coming Q1 2025 (IoT security)

---

## License

MIT License - See [LICENSE](../LICENSE) for details.

**Author:** Oussama Afnakkar  
**Blog:** [Secure Byte Chronicles](https://www.sbytec.com)  
**Version:** 2.0

---

<p align="center">
  <strong>🔓 Good luck cracking the vault!</strong><br>
  <em>Remember: Real ransomware is unbreakable. Always maintain backups.</em>
</p>
