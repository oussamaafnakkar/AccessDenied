#!/usr/bin/env python3
"""
Vault Challenge Decryptor
Automatically cracks the challenge binary by reversing the key derivation
"""

import struct
import sys

# Encrypted flag extracted from binary
ENCRYPTED_FLAG = bytes([
    0x33, 0x23, 0x22, 0x5b, 0x50, 0x35, 0x57, 0x35,
    0x50, 0x33, 0x35, 0x1f, 0x35, 0x34, 0x37, 0x31,
    0x34, 0x35, 0x35, 0x50, 0x31, 0x34, 0x37, 0x1f,
    0x33, 0x20, 0x33, 0x54, 0x35, 0x50, 0x7d
])

# Magic constant from derive_key()
MAGIC_CONSTANT = 0xDEADBEEF


def get_volume_serial_windows():
    """Get C: drive volume serial on Windows"""
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


def get_volume_serial_linux():
    """For Linux/demo, use a fixed value or read from /proc"""
    print("[*] Linux detected - using demo value")
    return 0x12345678  # Demo hardware ID


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
    print("[*] Searching for flags matching pattern: SBC{...}")
    
    # Try all possible hardware IDs (this is still fast for demo purposes)
    # In reality, you'd narrow this down or use known hardware IDs
    for hwid in range(0x10000000, 0x10000100):  # Small range for demo
        key = derive_key(hwid)
        plaintext = xor_decrypt(ENCRYPTED_FLAG, key)
        
        # Check if it looks like a valid flag
        if plaintext.startswith(b'SBC{') and plaintext.endswith(b'}'):
            print(f"[+] Found valid flag with HWID: 0x{hwid:08X}")
            return plaintext, hwid
    
    return None, None


def main():
    print("=" * 60)
    print("  VAULT CHALLENGE DECRYPTOR")
    print("  Secure Byte Chronicles - Reverse Engineering Series")
    print("=" * 60)
    print()
    
    # Detect OS and get hardware ID
    if sys.platform.startswith('win'):
        hardware_id = get_volume_serial_windows()
    else:
        hardware_id = get_volume_serial_linux()
    
    if hardware_id is None:
        print("[!] Could not determine hardware ID")
        print("[*] Switching to brute-force mode...\n")
        flag, found_hwid = brute_force_decrypt()
        if flag:
            hardware_id = found_hwid
        else:
            print("[!] Decryption failed")
            return
    else:
        print(f"[*] Hardware ID detected: 0x{hardware_id:08X}")
    
    # Derive the key
    derived_key = derive_key(hardware_id)
    print(f"[*] Derived key: 0x{derived_key:08X}")
    print(f"[*] Key derivation: {hardware_id:08X} ⊕ {MAGIC_CONSTANT:08X} = {derived_key:08X}")
    print()
    
    # Decrypt the flag
    print("[*] Decrypting flag...")
    plaintext = xor_decrypt(ENCRYPTED_FLAG, derived_key)
    
    # Display result
    print("\n" + "=" * 60)
    print("  DECRYPTION RESULT")
    print("=" * 60)
    
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
        print(f"    {plaintext.hex()}")
        print("[!] This suggests an incorrect key or corrupted data")
    
    print("\n" + "=" * 60)
    print("  ANALYSIS SUMMARY")
    print("=" * 60)
    print("\n Vulnerability Assessment:")
    print("  • Weak key derivation (hardware-based)")
    print("  • Simple XOR encryption (symmetric)")
    print("  • No authentication/integrity checks")
    print("  • Predictable magic constant (0xDEADBEEF)")
    print("\n Real Ransomware Defense:")
    print("  • Use proper CSPRNG for key generation")
    print("  • Implement hybrid crypto (RSA + AES)")
    print("  • Add HMAC for integrity verification")
    print("  • Never derive keys from hardware IDs")
    print()


if __name__ == "__main__":
    main()
