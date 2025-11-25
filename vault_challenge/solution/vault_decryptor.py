#!/usr/bin/env python3
"""
Vault Challenge Decryptor
Automatically cracks the challenge binary by reversing the key derivation

Author: Oussama Afnakkar
Blog: Secure Byte Chronicles (sbytec.com)
"""

import struct
import sys

# Encrypted flag extracted from binary (encrypted with HWID=0xABCD1234)
ENCRYPTED_FLAG = bytes([
    0x8c, 0xbf, 0xbe, 0x46, 0xa7, 0xf0, 0xa1, 0xeb,
    0xdb, 0xb4, 0xba, 0xda, 0x9e, 0xf1, 0xa9, 0xe7,
    0x9f, 0xf0, 0xad, 0xd2, 0x9e, 0xf0, 0xa1, 0xda,
    0x94, 0xbf, 0xba, 0x41, 0x9e, 0xf7, 0x78
])

# Magic constant from derive_key()
MAGIC_CONSTANT = 0xDEADBEEF

# Fixed hardware ID used in the binary
FIXED_HWID = 0xABCD1234


def get_volume_serial_windows():
    """Get C: drive volume serial on Windows (for reference)"""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        
        volume_serial = ctypes.c_ulong()
        result = kernel32.GetVolumeInformationA(
            b"C:\\",
            None, 0,
            ctypes.byref(volume_serial),
            None, None, None, 0
        )
        
        if result:
            return volume_serial.value
        else:
            print("[!] Failed to get volume serial")
            return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def get_hardware_id():
    """
    Get hardware ID to match the binary's behavior
    
    NOTE: The binary uses a FIXED value (0xABCD1234) for CTF consistency.
    This ensures all participants can decrypt the flag regardless of their machine.
    """
    # Always use the fixed HWID that matches the binary
    print(f"[*] Using fixed hardware ID: 0x{FIXED_HWID:08X}")
    return FIXED_HWID


def derive_key(hardware_id):
    """Replicate the binary's key derivation"""
    return hardware_id ^ MAGIC_CONSTANT


def xor_decrypt(ciphertext, key):
    """XOR decryption with 4-byte key"""
    key_bytes = struct.pack("<I", key)  # Little-endian uint32
    plaintext = bytearray()
    
    for i, byte in enumerate(ciphertext):
        plaintext.append(byte ^ key_bytes[i % 4])
    
    return plaintext


def brute_force_decrypt():
    """
    Alternative: Brute-force by checking for valid flag format
    Useful when hardware ID is unknown
    """
    print("[*] Attempting brute-force decryption...")
    print("[*] Searching for flags matching pattern: SBC{...}\n")
    
    # Try the known fixed HWID first
    known_hwids = [FIXED_HWID, 0x12345678]
    
    for hwid in known_hwids:
        key = derive_key(hwid)
        plaintext = xor_decrypt(ENCRYPTED_FLAG, key)
        
        # Check if it looks like a valid flag
        if plaintext.startswith(b'SBC{') and plaintext.endswith(b'}'):
            print(f"[+] Found valid flag with HWID: 0x{hwid:08X}")
            return plaintext, hwid
    
    # If not found in known values, try broader range
    print("[*] Not found in known values, expanding search...")
    for hwid in range(0xABCD0000, 0xABCE0000):
        key = derive_key(hwid)
        plaintext = xor_decrypt(ENCRYPTED_FLAG, key)
        
        if plaintext.startswith(b'SBC{') and plaintext.endswith(b'}'):
            print(f"[+] Found valid flag with HWID: 0x{hwid:08X}")
            return plaintext, hwid
    
    return None, None


def main():
    print("=" * 70)
    print("  VAULT CHALLENGE DECRYPTOR")
    print("  Secure Byte Chronicles - Reverse Engineering Series")
    print("=" * 70)
    print()
    
    # Get hardware ID (uses fixed value from binary)
    hardware_id = get_hardware_id()
    
    if hardware_id is None:
        print("[!] Could not determine hardware ID")
        print("[*] Switching to brute-force mode...\n")
        flag, found_hwid = brute_force_decrypt()
        if flag:
            hardware_id = found_hwid
        else:
            print("[!] Decryption failed")
            return
    
    # Derive the key
    derived_key = derive_key(hardware_id)
    print(f"[*] Derived key: 0x{derived_key:08X}")
    print(f"[*] Key derivation: 0x{hardware_id:08X} ⊕ 0x{MAGIC_CONSTANT:08X} = 0x{derived_key:08X}")
    print()
    
    # Decrypt the flag
    print("[*] Decrypting flag...")
    plaintext = xor_decrypt(ENCRYPTED_FLAG, derived_key)
    
    # Display result
    print("\n" + "=" * 70)
    print("  DECRYPTION RESULT")
    print("=" * 70)
    
    try:
        flag_str = plaintext.decode('ascii')
        print(f"\n  FLAG: {flag_str}\n")
        
        # Verify flag format
        if flag_str.startswith('SBC{') and flag_str.endswith('}'):
            print("[+] Valid flag format!")
            print("[+] Challenge completed successfully!")
        else:
            print("[!] Flag format unexpected - check your analysis")
    except UnicodeDecodeError:
        print("[!] Decryption produced non-ASCII data:")
        print(f"    Hex: {plaintext.hex()}")
        print("[!] This suggests an incorrect key or corrupted data")
    
    print("\n" + "=" * 70)
    print("  VULNERABILITY ANALYSIS")
    print("=" * 70)
    print("\n Why This Challenge is Vulnerable:")
    print("  • Fixed hardware ID (not actually reading system)")
    print("  • Weak key derivation (simple XOR with constant)")
    print("  • Simple XOR encryption (symmetric, no authentication)")
    print("  • Predictable magic constant (0xDEADBEEF)")
    print("  • No integrity checks (HMAC/GCM)")
    print()
    print(" Real Ransomware Defense Mechanisms:")
    print("  • Use cryptographically secure PRNG (CryptGenRandom)")
    print("  • Implement hybrid encryption (RSA-4096 + AES-256)")
    print("  • Add authenticated encryption (AES-GCM)")
    print("  • Generate unique keys per victim")
    print("  • Securely delete plaintext keys from memory")
    print("  • Use proper key derivation functions (PBKDF2/Argon2)")
    print()
    print(" Key Takeaway:")
    print("  Even with complete binary analysis, real ransomware using")
    print("  RSA-4096 + AES-256 is mathematically unbreakable without")
    print("  the attacker's private key. This is why backups are critical!")
    print()


if __name__ == "__main__":
    main()
