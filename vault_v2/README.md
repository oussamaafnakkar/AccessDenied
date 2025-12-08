#  **Vault Challenge v2 — Custom Packer, Multi-Stage Crypto & Reverse Engineering Challenge**

**Author:** Oussama Afnakkar — *Secure Byte Chronicles*

---

##  **Overview**

**Vault Challenge v2** is an advanced reverse-engineering and malware-analysis training challenge designed to simulate:

 Custom packer techniques
 Anti-analysis obfuscation
 Multi-stage encryption
 Key-derivation logic (hardware-ID + username + timestamp)
 XOR + RC4 layered cryptography
 PE unpacking and binary deobfuscation

Participants are required to unpack the binary, reverse the packer stub, reconstruct the key derivation algorithm, and decrypt the multi-layer encrypted flag.

This challenge is significantly more advanced than **Vault Challenge v1**, introducing:

* A **custom packer stub** written in x86 assembly
* XOR-encrypted `.text` section
* Encrypted embedded XOR key
* A scripted **Python unpacker** and automated solver

---

# **Challenge Goal**

Recover the final flag:

```
SBC{d3crypt3d_53ss10n_<SESSION_ID>_v2}
```

Example reference flag extracted during testing:

```
SBC{d3crypt3d_53ss10n_77777778_v2}
```

Your job:
**Analyze → Unpack → Reverse crypto → Derive keys → Decrypt flag.**

---

# **1. Building the Challenge (Reproduce the Pack)**

If you want to rebuild the packer process:

### **1. Build the original program**

```bash
make clean && make
```

This produces:

```
bin/vault_v2_unpacked.exe
```

### **2. Pack it using the custom packer**

```bash
python3 src/packer.py bin/vault_v2_unpacked.exe bin/vault_v2.exe
```

This:

* Encrypts `.text`
* Embeds encrypted XOR key
* Injects stub
* Produces the final packed executable

---

#  **2. Technical Architecture**

##  **Custom Packer Design**

### **Packer process**

```
[ vault_v2_unpacked.exe ]
        │
        ├─ XOR encrypt .text section (16-byte key)
        ├─ Encrypt key with 0x42
        ├─ Insert packer stub
        └─ Write packed vault_v2.exe
```

### **Packer stub behavior (runtime)**

Assembly stub (simplified):

```
PUSHAD                    ; Save registers
DecryptXORLoop:
    XOR byte ptr [esi], key[i % 16]
    INC esi
    LOOP DecryptXORLoop
POPAD                     ; Restore registers
JMP <OriginalEntryPoint>
```

Stub also contains:

* Obfuscated encrypted XOR key
* PUSHAD signature (allows packer detection)

---

# **3. Key Derivation Logic**

Inside `vault_v2.c`, the program derives a 32-bit XOR key from:

| Component       | Value         |
| --------------- | ------------- |
| **Hardware ID** | `0xABCD1234`  |
| **Username**    | `"CTFPlayer"` |
| **Timestamp**   | `0x65432100`  |
| **MAGIC_1**     | `0xDEADBEEF`  |
| **MAGIC_2**     | `0x13371337`  |

###  Derivation Steps

```
stage1 = hwid ^ MAGIC_1
stage2 = username_hash ^ timestamp
xor_key = (stage1 + stage2) ^ MAGIC_2
```

DJB2 hash is used for the username.

Final derived XOR key:

```
xor_key = 0x08FDBF3D
```

---

#  **4. Encryption Layers**

## **Stage 1 — XOR Encryption**

* 4-byte key
* Rotating key schedule (classic malware technique)

```
encrypted[i] ^ key[i % 4]
```

##  **Stage 2 — RC4 Encryption**

RC4 key = XOR-key repeated to 16 bytes:

```
3d bf fd 08 3d bf fd 08 3d bf fd 08 3d bf fd 08
```

Flag is encrypted as:

```
FLAG → XOR → RC4 → stored in .rdata
```

---

# **5. Solving the Challenge**

##  Option A — Full Automated Solver

```bash
cd vault_v2/solution
python3 full_solver.py ../bin/vault_v2.exe
```

Outputs:

```
FLAG: SBC{d3crypt3d_53ss10n_77777778_v2}
```

---

##  Option B — Manual Decryption

### **1. Extract encrypted flag**

From unpacked binary → `.rdata`.

Present in all solution scripts:

```python
ENCRYPTED_FLAG = [
  0xad, 0x61, 0xbf, 0x75, ...
]
```

### **2. XOR decrypt**

```bash
python3 decrypt_xor.py
```

### **3. RC4 decrypt**

```bash
python3 decrypt_rc4.py
```

---

# **6. Unpacking the Binary**

## Automated Unpacker

```bash
python3 unpacker.py bin/vault_v2.exe bin/vault_v2_unpacked_auto.exe
```

What it performs:

Parse PE headers
Locate `.packer` section
Extract encrypted XOR key
Decrypt key with byte `0x42`
Decrypt `.text`
Restore OEP (Original Entry Point)
Write recovered PE

Matches original `vault_v2_unpacked.exe`.

---

# **7. Reverse Engineering Notes**

### **Signatures**

* **PUSHAD (0x60)** at entry → packer stub
* High entropy → indicates packed code
* XOR decryption loop visible in dynamic trace

### **Ghidra Behavior**

* Packed binary appears obfuscated
* After unpacking → clean C-like decompilation
* Encrypted constant arrays visible (`encrypted_flag[]`)

### **Dynamic Debugging (x64dbg)**

Breakpoints of interest:

* After unpack loop (`POPAD`)
* Jump to OEP
* Decrypted `.text` in memory

---

# **8. License**

MIT License - See [LICENSE](../LICENSE)

---

# **9. Final Flag Format**

```
SBC{d3crypt3d_53ss10n_<SESSION>_v2}
```

Where:

```
SESSION = TIMESTAMP XOR 0x12345678
```

Example:

```
0x65432100 ^ 0x12345678 = 0x77777778
```

---

# **10. Credits**

Challenge design, packer implementation, research write-up:

**Oussama Afnakkar — Secure Byte Chronicles**
[https://www.sbytec.com](https://www.sbytec.com)

---

