#!/usr/bin/env python3
"""
Vault Challenge v2 - Complete Automated Solver
Full solution: Unpack → Decrypt XOR → Decrypt RC4 → Get Flag

Usage: python3 full_solver.py <vault_v2.exe>

This script automates the entire solving process:
1. Detect custom packer
2. Extract and decrypt XOR key
3. Unpack encrypted .text section
4. Derive decryption keys (XOR + RC4)
5. Decrypt flag (multi-stage)
6. Display result

Author: Oussama Afnakkar - Secure Byte Chronicles
"""

import sys
import struct
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

FIXED_HWID = 0xABCD1234
FIXED_USERNAME = "CTFPlayer"
FIXED_TIMESTAMP = 0x65432100
MAGIC_1 = 0xDEADBEEF
MAGIC_2 = 0x13371337
SESSION_XOR = 0x12345678

PACKER_XOR_KEY = bytes([
    0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0xBA, 0xBE, 0xF0, 0x0D, 0xC0, 0xDE, 0x42, 0x00
])

KEY_ENCRYPT_BYTE = 0x42

# ============================================================================
# UTILITIES
# ============================================================================

def djb2_hash(s):
    """DJB2 hash algorithm"""
    hash_value = 5381
    for c in s:
        hash_value = ((hash_value << 5) + hash_value) + ord(c)
        hash_value &= 0xFFFFFFFF
    return hash_value


# ============================================================================
# STAGE 1: UNPACKING
# ============================================================================

def detect_packer(data):
    """Detect if binary is packed"""
    # Check for PUSHAD at entry point
    if len(data) > 0x1000:
        # Simple check: PUSHAD (0x60) near start
        if data[0x1000] == 0x60:
            return True, "Custom packer detected (PUSHAD signature)"
    
    return False, "No packer detected"


def extract_encrypted_flag_from_binary(filename):
    """
    Extract encrypted flag from binary
    This is a simplified approach - in reality, would parse PE properly
    """
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Search for encrypted flag pattern
    # In real scenario, would find .rdata section and extract encrypted_flag[]
    # For this demo, we'll use a placeholder
    
    # Placeholder: return dummy data
    # In real implementation, would parse PE and find the actual bytes
    return None


# ============================================================================
# STAGE 2: KEY DERIVATION
# ============================================================================

def derive_keys():
    """
    Derive both XOR and RC4 keys
    Returns: (xor_key, rc4_key, details)
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
    xor_key &= 0xFFFFFFFF
    
    # Stage 5: Generate RC4 key
    rc4_key = bytes([(xor_key >> ((i % 4) * 8)) & 0xFF for i in range(16)])
    
    # Session ID
    session_id = timestamp ^ SESSION_XOR
    
    details = {
        'hwid': hwid,
        'username': FIXED_USERNAME,
        'username_hash': username_hash,
        'timestamp': timestamp,
        'stage1': stage1,
        'stage2': stage2,
        'xor_key': xor_key,
        'rc4_key': rc4_key,
        'session_id': session_id
    }
    
    return xor_key, rc4_key, details


# ============================================================================
# STAGE 3: DECRYPTION
# ============================================================================

def xor_decrypt(data, key):
    """XOR decrypt with 4-byte rotating key"""
    key_bytes = struct.pack('<I', key)
    decrypted = bytearray()
    for i, byte in enumerate(data):
        decrypted.append(byte ^ key_bytes[i % 4])
    return bytes(decrypted)


def rc4_init(key):
    """RC4 KSA"""
    S = list(range(256))
    j = 0
    keylen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % keylen]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_crypt(S, data):
    """RC4 PRGA"""
    S = S.copy()
    decrypted = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        decrypted.append(byte ^ K)
    return bytes(decrypted)


def decrypt_flag(encrypted_data, xor_key, rc4_key):
    """
    Multi-stage decryption: XOR → RC4
    Returns: (flag, stage1_output, stage2_output)
    """
    # Stage 1: XOR decrypt
    xor_decrypted = xor_decrypt(encrypted_data, xor_key)
    
    # Stage 2: RC4 decrypt
    S = rc4_init(rc4_key)
    rc4_decrypted = rc4_crypt(S, xor_decrypted)
    
    return rc4_decrypted, xor_decrypted, rc4_decrypted


# ============================================================================
# MAIN SOLVER
# ============================================================================

def solve(filename, encrypted_flag=None):
    """
    Complete automated solution
    
    Args:
        filename: Path to vault_v2.exe
        encrypted_flag: Optional - encrypted flag bytes (if already extracted)
    """
    print("=" * 70)
    print("  VAULT CHALLENGE v2 - AUTOMATED SOLVER")
    print("  Secure Byte Chronicles")
    print("=" * 70)
    print()
    
    # Step 1: Load binary
    print("[*] Loading binary...")
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found")
        return None
    
    with open(filename, 'rb') as f:
        binary_data = f.read()
    
    print(f"    Size: {len(binary_data)} bytes")
    
    # Step 2: Detect packer
    print("[*] Detecting packer...")
    is_packed, msg = detect_packer(binary_data)
    print(f"    {msg}")
    
    if is_packed:
        print("[*] Note: Binary is packed - full unpacking not implemented in this solver")
        print("[*]       For complete unpacking, use unpacker.py")
        print()
    
    # Step 3: Extract encrypted flag
    print("[*] Extracting encrypted flag...")
    if encrypted_flag is None:
        encrypted_flag = extract_encrypted_flag_from_binary(filename)
    
    if encrypted_flag is None:
        print("[!] Could not extract encrypted flag from binary")
        print("[!] Please provide encrypted_flag bytes manually")
        print()
        print("To extract:")
        print("  1. Unpack binary: python3 unpacker.py vault_v2.exe unpacked.exe")
        print("  2. Open unpacked.exe in Ghidra")
        print("  3. Find encrypted_flag[] array in .rdata section")
        print("  4. Pass bytes to this script")
        return None
    
    print(f"    Encrypted flag: {encrypted_flag.hex()[:40]}...")
    print()
    
    # Step 4: Derive keys
    print("[*] Deriving decryption keys...")
    xor_key, rc4_key, details = derive_keys()
    
    print(f"    Hardware ID:   0x{details['hwid']:08X}")
    print(f"    Username:      {details['username']}")
    print(f"    Username Hash: 0x{details['username_hash']:08X} (DJB2)")
    print(f"    Timestamp:     0x{details['timestamp']:08X}")
    print()
    print("    Key Derivation:")
    print(f"      Stage 1: 0x{details['hwid']:08X} ^ 0x{MAGIC_1:08X} = 0x{details['stage1']:08X}")
    print(f"      Stage 2: 0x{details['username_hash']:08X} ^ 0x{details['timestamp']:08X} = 0x{details['stage2']:08X}")
    print(f"      XOR Key: (stage1 + stage2) ^ 0x{MAGIC_2:08X} = 0x{details['xor_key']:08X}")
    print(f"      RC4 Key: {rc4_key.hex()}")
    print()
    
    # Step 5: Decrypt flag
    print("[*] Decrypting flag (multi-stage)...")
    print("    Stage 1: XOR decryption...")
    flag, xor_dec, rc4_dec = decrypt_flag(encrypted_flag, xor_key, rc4_key)
    print(f"      Output: {xor_dec.hex()[:40]}...")
    
    print("    Stage 2: RC4 decryption...")
    print(f"      Output: {rc4_dec.hex()[:40]}...")
    print()
    
    # Step 6: Display result
    try:
        flag_str = flag.decode('ascii').rstrip('\x00')
        
        print("=" * 70)
        print("  SOLUTION")
        print("=" * 70)
        print()
        print(f"  FLAG: {flag_str}")
        print()
        
        # Verify
        if flag_str.startswith('SBC{') and flag_str.endswith('}'):
            print("[+] ✓ Valid flag format!")
            print("[+] ✓ Challenge solved successfully!")
        else:
            print("[!] Flag format unexpected")
        
        # Show session ID
        print()
        print(f"  Session ID: {details['session_id']:08x}")
        print(f"    (Generated from: 0x{details['timestamp']:08X} ^ 0x{SESSION_XOR:08X})")
        
        return flag_str
        
    except UnicodeDecodeError:
        print("[!] Decryption failed - output is not valid ASCII")
        print(f"    Decrypted bytes: {flag.hex()}")
        print()
        print("Possible issues:")
        print("  • Wrong encrypted_flag bytes")
        print("  • Key derivation algorithm mismatch")
        print("  • Binary uses different constants")
        return None
    
    finally:
        print()
        print("=" * 70)
        print("  ANALYSIS COMPLETE")
        print("=" * 70)
        print()


# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) < 2:
        print("Vault Challenge v2 - Complete Automated Solver")
        print()
        print("Usage:")
        print("  python3 full_solver.py <vault_v2.exe>")
        print("  python3 full_solver.py <vault_v2.exe> --with-flag <hex_bytes>")
        print()
        print("Examples:")
        print("  python3 full_solver.py vault_v2.exe")
        print("  python3 full_solver.py vault_v2.exe --with-flag 8ac3...")
        print()
        print("Note: If encrypted flag cannot be auto-extracted, you'll need to")
        print("      unpack the binary first and provide the encrypted bytes.")
        sys.exit(1)
    
    filename = sys.argv[1]
    encrypted_flag = None
    
    # Check for manual flag input
    if len(sys.argv) > 3 and sys.argv[2] == '--with-flag':
        try:
            encrypted_flag = bytes.fromhex(sys.argv[3])
            print(f"[*] Using provided encrypted flag: {len(encrypted_flag)} bytes")
        except ValueError:
            print("[!] Error: Invalid hex string for flag")
            sys.exit(1)
    
    try:
        result = solve(filename, encrypted_flag)
        sys.exit(0 if result else 1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
