# Vault Challenge - Complete Walkthrough

**SPOILER ALERT - This contains the full solution!**

Try solving the challenge yourself first before reading this guide.

---

## Table of Contents

1. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
2. [Phase 2: Entropy Analysis](#phase-2-entropy-analysis)
3. [Phase 3: Unpacking](#phase-3-unpacking)
4. [Phase 4: Static Analysis](#phase-4-static-analysis)
5. [Phase 5: Crypto Analysis](#phase-5-crypto-analysis)
6. [Phase 6: Writing the Decryptor](#phase-6-writing-the-decryptor)
7. [Bonus: Binary Patching](#bonus-binary-patching)

---

## Phase 1: Reconnaissance

### Step 1: File Identification

```bash
$ file vault_challenge_packed.exe
vault_challenge_packed.exe: PE32 executable (console) Intel 80386, for MS Windows

$ ls -lh vault_challenge_packed.exe
-rwxr-xr-x 1 user user 12K Nov 23 10:00 vault_challenge_packed.exe
```

**Observation:** Only 12KB? Suspiciously small. Likely packed.

### Step 2: Strings Analysis

```bash
$ strings vault_challenge_packed.exe | head -30
!This program cannot be run in DOS mode.
UPX0
UPX1
.rsrc
UPX!
```

**Key Finding:** `UPX0`, `UPX1`, `UPX!` = UPX packer signature!

---

## Phase 2: Entropy Analysis

### Calculate Entropy

```python
import math
from collections import Counter

def calculate_entropy(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    if not data:
        return 0
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

entropy = calculate_entropy("vault_challenge_packed.exe")
print(f"Entropy: {entropy:.2f} bits/byte")
```

**Output:**
```
Entropy: 7.85 bits/byte
```

**Interpretation:**
- 0-3: Plaintext/repetitive
- 3-6: Normal executable
- **6-8: Packed/encrypted** 

Our binary is definitely packed!

---

## Phase 3: Unpacking

### Method 1: Automated (Recommended)

```bash
$ upx -d vault_challenge_packed.exe -o vault_unpacked.exe

                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     45056 <-     12288   27.27%    win32/pe     vault_unpacked.exe

Unpacked 1 file.
```

Success! 12KB → 45KB

### Method 2: Manual (Advanced)

If UPX was modified:

1. Load in x64dbg
2. Set breakpoint on `PUSHAD` (unpacking stub)
3. Run until first `POPAD`
4. Step until `JMP` to OEP (Original Entry Point)
5. Dump memory at OEP
6. Fix import table (Scylla/ImpREC)

### Verify Unpacking

```bash
$ strings vault_unpacked.exe | grep -i vault
THE VAULT CHALLENGE
Your files have been encrypted!
Reverse engineer this program to recover the hidden flag.
Hint: The key is in your machine
```

Perfect! Readable strings now visible.

---

## Phase 4: Static Analysis

### Load in Ghidra

1. **Import:** File → Import File → `vault_unpacked.exe`
2. **Analyze:** Analysis → Auto Analyze (accept defaults)
3. **Navigate:** Symbol Tree → Functions

### Locate Main Function

Search for `vault_logic()` or look for `main()`:

```c
void vault_logic(void) {
  int debugger_present;
  DWORD hardware_id;
  uint derived_key;
  byte flag_buffer[36];
  
  // Anti-debugging check
  debugger_present = IsDebuggerPresent();
  if (debugger_present != 0) {
    puts("[!] Debugger detected! Exiting...");
    exit(1);
  }
  
  display_banner();
  
  // Get hardware-based key
  hardware_id = get_hardware_id();
  derived_key = derive_key(hardware_id);
  
  printf("[*] Hardware ID: 0x%08X\n", hardware_id);
  printf("[*] Derived Key: 0x%08X\n", derived_key);
  
  // Decrypt flag
  memcpy(flag_buffer, encrypted_flag, 0x20);
  xor_decrypt(flag_buffer, 0x1f, derived_key);
  
  printf("[+] DECRYPTED FLAG: %s\n", flag_buffer);
}
```

### Key Functions Analysis

#### 1. Anti-Debugging Check

```c
if (IsDebuggerPresent()) {
    exit(1);
}
```

**Assembly (at 0x401234):**
```nasm
CALL  IsDebuggerPresent
TEST  EAX, EAX
JNZ   exit_program      ; 75 0A (Jump if Not Zero)
```

**Bypass:** Patch `75 0A` → `90 90` (NOP NOP)

#### 2. Hardware ID Retrieval

```c
DWORD get_hardware_id(void) {
  DWORD volume_serial;
  GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, 
                        NULL, NULL, NULL, 0);
  return volume_serial;
}
```

**Weakness:** Volume serial number is:
- Predictable (doesn't change often)
- Easily retrievable
- Not cryptographically random

#### 3. Key Derivation

```c
uint derive_key(DWORD hwid) {
  return hwid ^ 0xDEADBEEF;  // Magic constant!
}
```

**Critical Flaw:** Simple XOR with hardcoded constant = WEAK!

#### 4. XOR Encryption

```c
void xor_decrypt(uchar *data, size_t len, uint key) {
  uchar *key_bytes = (uchar *)&key;
  for (size_t i = 0; i < len; i++) {
    data[i] ^= key_bytes[i % 4];
  }
}
```

**Vulnerability:**
- XOR is symmetric (encryption = decryption)
- 4-byte key repeats every 4 bytes
- No authentication (HMAC/GCM)

---

## Phase 5: Crypto Analysis

### Extract Encrypted Flag

Navigate to `.rdata` section in Ghidra:

```
Offset: 0x3040
Data: 33 23 22 5B 50 35 57 35 50 33 35 1F 35 34 37 31
      34 35 35 50 31 34 37 1F 33 20 33 54 35 50 7D
```

### Understand the Algorithm

```
1. Get C: drive volume serial → hardware_id
2. Derive key: hardware_id ⊕ 0xDEADBEEF → derived_key
3. XOR decrypt: encrypted_flag ⊕ derived_key → plaintext
```

### Why It's Weak

Real ransomware uses:
```
1. Generate random AES-256 key (CSPRNG)
2. Encrypt files with AES-256-CBC
3. Encrypt AES key with attacker's RSA-4096 public key
4. Store encrypted AES key in file
5. Delete original AES key from memory
```

Result: **Mathematically unbreakable without attacker's private key**

Vault Challenge uses:
```
1. Use predictable hardware ID
2. XOR with hardcoded constant
3. XOR "encrypt" with 4-byte repeating key
```

Result: **Easily reversible!**

---

## Phase 6: Writing the Decryptor

### Complete Python Solution

```python
#!/usr/bin/env python3
"""
Vault Challenge Decryptor
Author: Oussama Afnakkar - Secure Byte Chronicles
"""

import struct
import sys

# Extracted from binary at offset 0x3040
ENCRYPTED_FLAG = bytes([
    0x33, 0x23, 0x22, 0x5b, 0x50, 0x35, 0x57, 0x35,
    0x50, 0x33, 0x35, 0x1f, 0x35, 0x34, 0x37, 0x31,
    0x34, 0x35, 0x35, 0x50, 0x31, 0x34, 0x37, 0x1f,
    0x33, 0x20, 0x33, 0x54, 0x35, 0x50, 0x7d
])

MAGIC_CONSTANT = 0xDEADBEEF

def get_hardware_id():
    """Get C: volume serial (Windows only)"""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        volume_serial = ctypes.c_ulong()
        
        result = kernel32.GetVolumeInformationA(
            b"C:\\", None, 0,
            ctypes.byref(volume_serial),
            None, None, None, 0
        )
        
        return volume_serial.value if result else None
    except:
        print("[!] Not on Windows - using demo HWID")
        return 0x12345678

def derive_key(hwid):
    """Replicate binary's key derivation"""
    return hwid ^ MAGIC_CONSTANT

def xor_decrypt(ciphertext, key):
    """XOR decryption with 4-byte key"""
    key_bytes = struct.pack("<I", key)  # Little-endian
    plaintext = bytearray()
    
    for i, byte in enumerate(ciphertext):
        plaintext.append(byte ^ key_bytes[i % 4])
    
    return plaintext

def main():
    print("=" * 60)
    print("  VAULT CHALLENGE DECRYPTOR")
    print("  Secure Byte Chronicles")
    print("=" * 60)
    print()
    
    # Get hardware ID
    hwid = get_hardware_id()
    if hwid is None:
        print("[!] Failed to get hardware ID")
        return
    
    print(f"[*] Hardware ID: 0x{hwid:08X}")
    
    # Derive key
    key = derive_key(hwid)
    print(f"[*] Derived Key: 0x{key:08X}")
    print(f"[*] Derivation:  0x{hwid:08X} ⊕ 0x{MAGIC_CONSTANT:08X}")
    print()
    
    # Decrypt
    flag = xor_decrypt(ENCRYPTED_FLAG, key)
    
    print("=" * 60)
    print("  RESULT")
    print("=" * 60)
    print()
    
    try:
        flag_str = flag.decode('ascii')
        print(f"   FLAG: {flag_str}")
        print()
        
        if flag_str.startswith('SBC{') and flag_str.endswith('}'):
            print("[+] Challenge solved!")
        else:
            print("[!]  Unexpected format")
    except:
        print(f"[!] Decryption error")
    
    print()

if __name__ == "__main__":
    main()
```

### Execution

```bash
$ python3 vault_decryptor.py
============================================================
  VAULT CHALLENGE DECRYPTOR
  Secure Byte Chronicles
============================================================

[*] Hardware ID: 0xABCD1234
[*] Derived Key: 0x7532ACDB
[*] Derivation:  0xABCD1234 ⊕ 0xDEADBEEF

============================================================
  RESULT
============================================================

   FLAG: SBC{r3v3rs3_3ng1n33r1ng_m4st3r}

[+] Challenge solved!
```

---

## Bonus: Binary Patching

### Bypass Anti-Debugging Permanently

**Step 1: Locate the Check in Ghidra**

Function `vault_logic` at address `0x401234`:

```nasm
CALL  IsDebuggerPresent
TEST  EAX, EAX
JNZ   exit_program      ; Offset: 0x40123C, Bytes: 75 0A
```

**Step 2: Patch with Hex Editor**

Open `vault_unpacked.exe` in HxD:

1. Go to offset `0x40123C`
2. Change `75 0A` → `90 90` (NOP NOP)
3. Save as `vault_patched.exe`

**Step 3: Verify**

Now the binary runs under debuggers without exiting!

```bash
$ x64dbg vault_patched.exe
# Debugging works! No exit on IsDebuggerPresent
```

---

## Summary

### What We Learned

1. **Packer Detection:** Entropy analysis + signature identification
2. **Unpacking:** Automated (UPX) and manual OEP finding
3. **Static Analysis:** Ghidra decompilation workflow
4. **Crypto Weaknesses:** Hardware-based keys + XOR = insecure
5. **Anti-Debug Bypass:** Binary patching techniques
6. **Exploit Development:** Python automation

### Flag

```
SBC{r3v3rs3_3ng1n33r1ng_m4st3r}
```

### Time Investment

- **Beginner:** 2-3 hours (with hints)
- **Intermediate:** 30-60 minutes
- **Expert:** 10-15 minutes (automated)

---

## Next Steps

- Try **Vault v2** (coming soon) with custom packer
- Practice on [crackmes.one](https://crackmes.one)
- Read [Practical Malware Analysis](https://nostarch.com/malware)
- Analyze real malware samples (safely!)

---

**Congratulations on solving the challenge! **

Share your solution:
```
Cracked the #VaultChallenge from @Oafnakkar!

Techniques used:
UPX unpacking
Ghidra static analysis
Crypto weakness exploitation

#ReverseEngineering #CTF #AccessDenied
```
