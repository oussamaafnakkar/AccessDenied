#!/usr/bin/env python3
"""
Vault Challenge v2 - Complete Automated Solver
Full solution: Unpack → Decrypt XOR → Decrypt RC4 → Get Flag

Usage: python3 full_solver.py <vault_v2.exe>

This script automates the entire solving process:
1. Detect custom packer
2. Extract encrypted flag from binary
3. Derive decryption keys (XOR + RC4)
4. Decrypt flag (multi-stage)
5. Display result

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

# Hardcoded encrypted flag (from vault_v2.c)
# This ensures the solver works even without unpacking
ENCRYPTED_FLAG = bytes([
    0xad, 0x61, 0xbf, 0x75, 0xe1, 0x91, 0x32, 0x41,
    0x79, 0xdb, 0x35, 0xac, 0x78, 0x7a, 0x10, 0x22,
    0xe1, 0xec, 0x2f, 0x2c, 0x32, 0xf8, 0x14, 0x36,
    0x34, 0x78, 0x62, 0x1e, 0xbd, 0x18, 0xa5, 0x10,
    0x28, 0x7c
])

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


def read_u16(data, offset):
    """Read 16-bit little-endian"""
    return struct.unpack_from('<H', data, offset)[0]


def read_u32(data, offset):
    """Read 32-bit little-endian"""
    return struct.unpack_from('<I', data, offset)[0]


# ============================================================================
# STAGE 1: PACKER DETECTION & FLAG EXTRACTION
# ============================================================================

def detect_packer(data):
    """Detect if binary is packed"""
    if len(data) < 0x1000:
        return False, "Binary too small"
    
    # Check for MZ header
    if data[0:2] != b'MZ':
        return False, "Not a PE file"
    
    # Parse PE header
    try:
        e_lfanew = read_u32(data, 0x3C)
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return False, "Invalid PE signature"
        
        # Get entry point
        opt_header_offset = e_lfanew + 24
        entry_point_rva = read_u32(data, opt_header_offset + 16)
        
        # Find section containing entry point
        opt_header_size = read_u16(data, e_lfanew + 20)
        section_table = e_lfanew + 24 + opt_header_size
        num_sections = read_u16(data, e_lfanew + 6)
        
        entry_section = None
        for i in range(num_sections):
            offset = section_table + (i * 40)
            section_name = data[offset:offset+8].rstrip(b'\x00').decode(errors='ignore')
            virtual_addr = read_u32(data, offset + 12)
            virtual_size = read_u32(data, offset + 8)
            raw_ptr = read_u32(data, offset + 20)
            
            if virtual_addr <= entry_point_rva < virtual_addr + virtual_size:
                entry_section = {
                    'name': section_name,
                    'raw_ptr': raw_ptr,
                    'offset': entry_point_rva - virtual_addr + raw_ptr
                }
                break
        
        if not entry_section:
            return False, "Could not locate entry point section"
        
        # Check for PUSHAD (0x60) at entry
        entry_offset = entry_section['offset']
        if entry_offset < len(data) and data[entry_offset] == 0x60:
            return True, f"Custom packer detected (PUSHAD in {entry_section['name']} section)"
        
        # Check for .packer section name
        if entry_section['name'] == '.packer':
            return True, "Custom packer detected (.packer section)"
        
        # Check for packer stub signature
        if PACKER_XOR_KEY in data:
            return True, "Custom packer detected (stub signature found)"
        
        return False, "No packer detected"
        
    except Exception as e:
        return False, f"Error parsing PE: {e}"


def extract_encrypted_flag_from_binary(filename):
    """
    Extract encrypted flag from binary
    
    Strategy:
    1. Try to find it in .rdata section (unpacked)
    2. Use hardcoded value as fallback
    """
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Search for the encrypted flag pattern
    # The flag starts with specific bytes after encryption
    search_pattern = bytes([0xad, 0x61, 0xbf, 0x75])  # First 4 bytes
    
    offset = data.find(search_pattern)
    if offset != -1 and offset + 34 <= len(data):
        extracted = data[offset:offset+34]
        if extracted == ENCRYPTED_FLAG:
            print(f"    Found encrypted flag at offset: 0x{offset:08X}")
            return extracted
    
    # Fallback to hardcoded
    print("    Using hardcoded encrypted flag (from vault_v2.c)")
    return ENCRYPTED_FLAG


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
    print()
    
    if is_packed:
        print("[*] Note: Binary appears to be packed")
        print("[*]       For complete unpacking, use: python3 unpacker.py")
        print()
    
    # Step 3: Extract encrypted flag
    print("[*] Extracting encrypted flag...")
    if encrypted_flag is None:
        encrypted_flag = extract_encrypted_flag_from_binary(filename)
    
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
        print("  python3 full_solver.py bin/vault_v2.exe")
        print("  python3 full_solver.py bin/vault_v2_unpacked.exe")
        print("  python3 full_solver.py vault_v2.exe --with-flag ad61bf75...")
        print()
        print("Note: The solver uses hardcoded encrypted flag as fallback,")
        print("      so it works even without unpacking the binary.")
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
