#!/usr/bin/env python3
"""
Vault Challenge v2 - Custom Packer
Packs the unpacked binary with XOR encryption

Usage: python3 packer.py <input.exe> <output.exe>

Algorithm:
1. Read unpacked PE binary
2. Extract .text section
3. XOR encrypt with 16-byte rotating key
4. Create new PE with .packer (stub) and .packed (encrypted) sections
5. Patch stub with encrypted data and OEP
6. Write packed binary

Author: Oussama Afnakkar - Secure Byte Chronicles
"""

import sys
import struct
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

XOR_KEY = bytes([
    0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0xBA, 0xBE, 0xF0, 0x0D, 0xC0, 0xDE, 0x42, 0x00
])

KEY_ENCRYPT_BYTE = 0x42  # XOR key to encrypt the key itself (meta!)

# ============================================================================
# PE PARSING UTILITIES
# ============================================================================

def read_pe_header(data):
    """Extract PE header information"""
    # DOS header
    if data[0:2] != b'MZ':
        raise ValueError("Not a valid PE file (missing MZ signature)")
    
    e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
    
    # PE signature
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        raise ValueError("Not a valid PE file (missing PE signature)")
    
    # COFF header
    coff_offset = e_lfanew + 4
    machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
    num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
    
    # Optional header
    opt_header_offset = coff_offset + 20
    magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]
    
    if magic == 0x10b:  # PE32
        entry_point_rva = struct.unpack('<I', data[opt_header_offset+16:opt_header_offset+20])[0]
        image_base = struct.unpack('<I', data[opt_header_offset+28:opt_header_offset+32])[0]
        section_align = struct.unpack('<I', data[opt_header_offset+32:opt_header_offset+36])[0]
        file_align = struct.unpack('<I', data[opt_header_offset+36:opt_header_offset+40])[0]
    else:
        raise ValueError("Only PE32 (32-bit) binaries supported")
    
    return {
        'e_lfanew': e_lfanew,
        'entry_point_rva': entry_point_rva,
        'image_base': image_base,
        'section_align': section_align,
        'file_align': file_align,
        'num_sections': num_sections,
        'opt_header_offset': opt_header_offset
    }


def find_section(data, pe_info, section_name):
    """Find a section by name"""
    # Section table starts after optional header
    opt_header_size = struct.unpack('<H', 
        data[pe_info['e_lfanew']+20:pe_info['e_lfanew']+22])[0]
    section_table_offset = pe_info['e_lfanew'] + 24 + opt_header_size
    
    for i in range(pe_info['num_sections']):
        section_offset = section_table_offset + (i * 40)
        name = data[section_offset:section_offset+8].rstrip(b'\x00')
        
        if name == section_name.encode():
            virtual_size = struct.unpack('<I', data[section_offset+8:section_offset+12])[0]
            virtual_addr = struct.unpack('<I', data[section_offset+12:section_offset+16])[0]
            raw_size = struct.unpack('<I', data[section_offset+16:section_offset+20])[0]
            raw_addr = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]
            
            return {
                'name': name,
                'virtual_size': virtual_size,
                'virtual_addr': virtual_addr,
                'raw_size': raw_size,
                'raw_addr': raw_addr,
                'data': data[raw_addr:raw_addr+raw_size]
            }
    
    return None


# ============================================================================
# ENCRYPTION
# ============================================================================

def xor_encrypt(data, key):
    """XOR encrypt data with rotating key"""
    encrypted = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % key_len])
    
    return bytes(encrypted)


def encrypt_key(key, encrypt_byte):
    """Encrypt the XOR key itself (meta-encryption for anti-analysis)"""
    return bytes([b ^ encrypt_byte for b in key])


# ============================================================================
# PACKER
# ============================================================================

def pack_binary(input_file, output_file, stub_file='stub.bin'):
    """Main packing function"""
    
    print("[*] Reading unpacked binary...")
    with open(input_file, 'rb') as f:
        unpacked_data = f.read()
    
    print("[*] Parsing PE headers...")
    pe_info = read_pe_header(unpacked_data)
    print(f"    Entry Point RVA: 0x{pe_info['entry_point_rva']:08X}")
    print(f"    Image Base: 0x{pe_info['image_base']:08X}")
    
    print("[*] Finding .text section...")
    text_section = find_section(unpacked_data, pe_info, '.text')
    if not text_section:
        print("[!] Error: .text section not found!")
        return False
    
    print(f"    .text Virtual Addr: 0x{text_section['virtual_addr']:08X}")
    print(f"    .text Size: {len(text_section['data'])} bytes")
    
    print("[*] Encrypting .text section...")
    encrypted_text = xor_encrypt(text_section['data'], XOR_KEY)
    print(f"    Encrypted: {len(encrypted_text)} bytes")
    
    print("[*] Reading packer stub...")
    if os.path.exists(stub_file):
        with open(stub_file, 'rb') as f:
            stub_data = f.read()
        print(f"    Stub size: {len(stub_data)} bytes")
    else:
        print(f"[!] Warning: {stub_file} not found, using minimal stub")
        # Minimal stub for testing
        stub_data = bytes([
            0x60,  # PUSHAD
            0xE8, 0x00, 0x00, 0x00, 0x00,  # CALL $+5
            0x5D,  # POP EBP
            # ... (simplified for now)
            0x61,  # POPAD
            0xE9, 0x00, 0x00, 0x00, 0x00   # JMP to OEP
        ])
    
    print("[*] Encrypting XOR key...")
    encrypted_xor_key = encrypt_key(XOR_KEY, KEY_ENCRYPT_BYTE)
    
    print("[*] Building packed binary...")
    # For now, create a simplified packed version
    # Full PE reconstruction would be more complex
    
    # Copy original PE structure
    packed_data = bytearray(unpacked_data)
    
    # Replace .text with encrypted version
    if text_section:
        start = text_section['raw_addr']
        end = start + len(encrypted_text)
        packed_data[start:end] = encrypted_text
    
    # Add stub at entry point (simplified approach)
    # In full implementation, would add new .packer section
    
    print("[*] Writing packed binary...")
    with open(output_file, 'wb') as f:
        f.write(packed_data)
    
    print(f"[+] Packing complete!")
    print(f"[+] Output: {output_file}")
    print(f"[+] Original size: {len(unpacked_data)} bytes")
    print(f"[+] Packed size: {len(packed_data)} bytes")
    print(f"[+] Ratio: {len(packed_data)/len(unpacked_data)*100:.1f}%")
    
    return True


# ============================================================================
# FLAG ENCRYPTION HELPER
# ============================================================================

def encrypt_flag_for_binary(flag_plaintext, xor_key_int, rc4_key):
    """
    Encrypt the flag with RC4 → XOR (reverse order of decryption)
    This generates the bytes to put in encrypted_flag[] array
    """
    from Crypto.Cipher import ARC4
    
    # Stage 1: RC4 encrypt
    cipher = ARC4.new(rc4_key)
    rc4_encrypted = cipher.encrypt(flag_plaintext.encode())
    
    # Stage 2: XOR encrypt
    xor_key_bytes = struct.pack('<I', xor_key_int)
    final_encrypted = bytearray()
    for i, byte in enumerate(rc4_encrypted):
        final_encrypted.append(byte ^ xor_key_bytes[i % 4])
    
    return bytes(final_encrypted)


def generate_flag_array():
    """Generate the C array for encrypted_flag[]"""
    
    # Calculate keys (must match vault_v2.c logic)
    FIXED_HWID = 0xABCD1234
    FIXED_TIMESTAMP = 0x65432100
    FIXED_USERNAME = "CTFPlayer"
    MAGIC_1 = 0xDEADBEEF
    MAGIC_2 = 0x13371337
    SESSION_XOR = 0x12345678
    
    # DJB2 hash
    def djb2_hash(s):
        h = 5381
        for c in s:
            h = ((h << 5) + h) + ord(c)
            h &= 0xFFFFFFFF
        return h
    
    username_hash = djb2_hash(FIXED_USERNAME)
    stage1 = FIXED_HWID ^ MAGIC_1
    stage2 = username_hash ^ FIXED_TIMESTAMP
    xor_key = (stage1 + stage2) ^ MAGIC_2
    xor_key &= 0xFFFFFFFF
    
    # Generate RC4 key
    rc4_key = bytes([(xor_key >> ((i % 4) * 8)) & 0xFF for i in range(16)])
    
    # Generate session ID
    session_id = FIXED_TIMESTAMP ^ SESSION_XOR
    
    # Create flag
    flag = f"SBC{{d3crypt3d_53ss10n_{session_id:08x}_v2}}"
    
    print(f"\n[*] Flag: {flag}")
    print(f"[*] XOR Key: 0x{xor_key:08X}")
    print(f"[*] RC4 Key: {rc4_key.hex()}")
    
    # Encrypt
    encrypted = encrypt_flag_for_binary(flag, xor_key, rc4_key)
    
    print(f"\n[*] Encrypted flag bytes (for vault_v2.c):")
    print("uint8_t encrypted_flag[] = {")
    for i in range(0, len(encrypted), 8):
        chunk = encrypted[i:i+8]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        if i + 8 < len(encrypted):
            print(f"    {hex_str},")
        else:
            print(f"    {hex_str}")
    print("};")
    
    return encrypted


# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) < 2:
        print("Vault Challenge v2 - Custom Packer")
        print()
        print("Usage:")
        print("  python3 packer.py <input.exe> <output.exe>  # Pack binary")
        print("  python3 packer.py --generate-flag          # Generate encrypted flag")
        print()
        print("Example:")
        print("  python3 packer.py vault_v2_unpacked.exe vault_v2.exe")
        sys.exit(1)
    
    if sys.argv[1] == '--generate-flag':
        print("[*] Generating encrypted flag bytes...")
        generate_flag_array()
        sys.exit(0)
    
    if len(sys.argv) < 3:
        print("[!] Error: Output file not specified")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    if not os.path.exists(input_file):
        print(f"[!] Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    try:
        success = pack_binary(input_file, output_file)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
