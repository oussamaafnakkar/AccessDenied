#!/usr/bin/env python3
"""
Vault Challenge v2 - Stage 1: XOR Decryption
Decrypt the outer XOR layer from the flag

Usage: python3 decrypt_xor.py

This script demonstrates Stage 1 of the multi-stage decryption process.
After unpacking the binary and analyzing the key derivation, use this to
decrypt the XOR layer.

Author: Oussama Afnakkar - Secure Byte Chronicles
"""

import struct

# ============================================================================
# CONFIGURATION (Values from vault_v2.c)
# ============================================================================

FIXED_HWID = 0xABCD1234
FIXED_USERNAME = "CTFPlayer"
FIXED_TIMESTAMP = 0x65432100
MAGIC_1 = 0xDEADBEEF
MAGIC_2 = 0x13371337

# Encrypted flag (extract from binary or unpacked analysis)
# This is a placeholder - will be filled with actual bytes from binary
ENCRYPTED_FLAG = bytes([
    # Will be extracted from .rdata section of unpacked binary
    # For now, placeholder zeros
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

# ============================================================================
# KEY DERIVATION (Replicate from vault_v2.c)
# ============================================================================

def djb2_hash(s):
    """DJB2 hash algorithm"""
    hash_value = 5381
    for c in s:
        hash_value = ((hash_value << 5) + hash_value) + ord(c)
        hash_value &= 0xFFFFFFFF  # Keep 32-bit
    return hash_value


def derive_xor_key():
    """
    Replicate the complex key derivation from vault_v2.c
    
    Algorithm:
    1. Hardware ID (fixed)
    2. Username hash (DJB2)
    3. Timestamp (fixed)
    4. Multi-stage XOR and addition
    """
    # Stage 1: Hardware ID
    hwid = FIXED_HWID
    
    # Stage 2: Username hash
    username_hash = djb2_hash(FIXED_USERNAME)
    
    # Stage 3: Timestamp
    timestamp = FIXED_TIMESTAMP
    
    # Stage 4: Complex derivation
    stage1 = hwid ^ MAGIC_1
    stage2 = username_hash ^ timestamp
    xor_key = (stage1 + stage2) ^ MAGIC_2
    xor_key &= 0xFFFFFFFF  # Ensure 32-bit
    
    return xor_key, username_hash


# ============================================================================
# XOR DECRYPTION
# ============================================================================

def xor_decrypt(data, key):
    """
    XOR decrypt with 4-byte rotating key
    
    The key is split into 4 bytes (little-endian) and rotated:
    data[0] ^= key_bytes[0]
    data[1] ^= key_bytes[1]
    data[2] ^= key_bytes[2]
    data[3] ^= key_bytes[3]
    data[4] ^= key_bytes[0]  # Rotation
    ...
    """
    key_bytes = struct.pack('<I', key)  # Little-endian 32-bit
    decrypted = bytearray()
    
    for i, byte in enumerate(data):
        decrypted.append(byte ^ key_bytes[i % 4])
    
    return bytes(decrypted)


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 70)
    print("  VAULT CHALLENGE v2 - STAGE 1: XOR DECRYPTION")
    print("  Secure Byte Chronicles")
    print("=" * 70)
    print()
    
    print("[*] Deriving XOR key...")
    xor_key, username_hash = derive_xor_key()
    
    print(f"    Hardware ID:   0x{FIXED_HWID:08X}")
    print(f"    Username:      {FIXED_USERNAME}")
    print(f"    Username Hash: 0x{username_hash:08X} (DJB2)")
    print(f"    Timestamp:     0x{FIXED_TIMESTAMP:08X}")
    print()
    
    # Show derivation steps
    stage1 = FIXED_HWID ^ MAGIC_1
    stage2 = username_hash ^ FIXED_TIMESTAMP
    
    print("[*] Key Derivation Steps:")
    print(f"    Stage 1: 0x{FIXED_HWID:08X} ^ 0x{MAGIC_1:08X} = 0x{stage1:08X}")
    print(f"    Stage 2: 0x{username_hash:08X} ^ 0x{FIXED_TIMESTAMP:08X} = 0x{stage2:08X}")
    print(f"    XOR Key: (0x{stage1:08X} + 0x{stage2:08X}) ^ 0x{MAGIC_2:08X}")
    print(f"           = 0x{(stage1 + stage2) & 0xFFFFFFFF:08X} ^ 0x{MAGIC_2:08X}")
    print(f"           = 0x{xor_key:08X}")
    print()
    
    print("[*] XOR Key Bytes (little-endian):")
    key_bytes = struct.pack('<I', xor_key)
    print(f"    {' '.join(f'{b:02x}' for b in key_bytes)}")
    print()
    
    # Check if we have actual encrypted data
    if ENCRYPTED_FLAG == bytes(len(ENCRYPTED_FLAG)):
        print("[!] No encrypted flag data loaded")
        print("[!] Extract encrypted_flag[] from binary first")
        print()
        print("To extract:")
        print("  1. Unpack the binary (unpacker.py)")
        print("  2. Open in Ghidra")
        print("  3. Find encrypted_flag[] in .rdata section")
        print("  4. Copy bytes to this script")
        print()
        return
    
    print("[*] Decrypting with XOR...")
    xor_decrypted = xor_decrypt(ENCRYPTED_FLAG, xor_key)
    
    print(f"    Encrypted (hex): {ENCRYPTED_FLAG[:16].hex()}...")
    print(f"    XOR Decrypted:   {xor_decrypted[:16].hex()}...")
    print()
    
    # Try to decode (will fail if still RC4 encrypted)
    try:
        decoded = xor_decrypted.decode('ascii')
        print("[+] XOR Decryption Result:")
        print(f"    {decoded}")
        print()
        print("[!] Hmm, this looks like the final flag already?")
        print("[!] Check if RC4 layer exists or if key derivation changed")
    except UnicodeDecodeError:
        print("[*] XOR decryption complete, but data is not ASCII")
        print("[*] This is expected - Stage 2 (RC4) decryption needed")
        print()
        print("[*] Passing to Stage 2 (decrypt_rc4.py)...")
        print(f"    RC4-encrypted data: {xor_decrypted.hex()}")
    
    print()
    print("=" * 70)
    print("  STAGE 1 COMPLETE")
    print("=" * 70)
    print()
    print("Next: Run decrypt_rc4.py with the XOR-decrypted data")
    print()


if __name__ == "__main__":
    main()
