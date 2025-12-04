#!/usr/bin/env python3
"""
Vault Challenge v2 - Automated Unpacker
Extracts and decrypts the packed .text section

Usage: python3 unpacker.py <packed.exe> <unpacked.exe>

Algorithm:
1. Identify packer stub (PUSHAD signature at entry)
2. Extract encrypted XOR key from stub
3. Decrypt the XOR key (encrypted with 0x42)
4. Extract encrypted .text section
5. XOR decrypt with 16-byte rotating key
6. Reconstruct unpacked binary
7. Fix PE headers

Author: Oussama Afnakkar - Secure Byte Chronicles
"""

import sys
import struct
import os

# ============================================================================
# CONFIGURATION
# ============================================================================

KEY_DECRYPT_BYTE = 0x42  # Byte used to encrypt the XOR key itself

# ============================================================================
# PE UTILITIES
# ============================================================================

def read_pe_header(data):
    """Parse PE header"""
    if data[0:2] != b'MZ':
        raise ValueError("Not a valid PE file")
    
    e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
    
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")
    
    # Optional header
    opt_header_offset = e_lfanew + 24
    entry_point_rva = struct.unpack('<I', data[opt_header_offset+16:opt_header_offset+20])[0]
    image_base = struct.unpack('<I', data[opt_header_offset+28:opt_header_offset+32])[0]
    
    return {
        'e_lfanew': e_lfanew,
        'entry_point_rva': entry_point_rva,
        'image_base': image_base,
        'opt_header_offset': opt_header_offset
    }


def find_section(data, pe_info, section_name):
    """Find section by name"""
    # Get section table offset
    opt_header_size = struct.unpack('<H', 
        data[pe_info['e_lfanew']+20:pe_info['e_lfanew']+22])[0]
    section_table = pe_info['e_lfanew'] + 24 + opt_header_size
    
    num_sections = struct.unpack('<H', 
        data[pe_info['e_lfanew']+6:pe_info['e_lfanew']+8])[0]
    
    for i in range(num_sections):
        offset = section_table + (i * 40)
        name = data[offset:offset+8].rstrip(b'\x00')
        
        if name == section_name.encode():
            return {
                'virtual_addr': struct.unpack('<I', data[offset+12:offset+16])[0],
                'raw_size': struct.unpack('<I', data[offset+16:offset+20])[0],
                'raw_addr': struct.unpack('<I', data[offset+20:offset+24])[0]
            }
    
    return None


# ============================================================================
# DECRYPTION
# ============================================================================

def xor_decrypt(data, key):
    """XOR decrypt with rotating key"""
    decrypted = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        decrypted.append(byte ^ key[i % key_len])
    
    return bytes(decrypted)


def extract_xor_key(stub_data):
    """
    Extract and decrypt the XOR key from packer stub
    
    The stub contains the encrypted 16-byte XOR key.
    It's encrypted with a single byte (0x42) to hide it from static analysis.
    """
    # Search for key pattern in stub
    # The key is stored after the stub code, before packed data
    
    # Simple approach: look for 16 consecutive bytes that look like encrypted data
    # In real stub, this is at a fixed offset
    # For this implementation, we'll use a known offset or pattern
    
    # Assuming key is at offset 0x50 in stub (adjust based on actual assembly)
    key_offset = 0x50
    encrypted_key = stub_data[key_offset:key_offset+16]
    
    # Decrypt the key
    decrypted_key = bytes([b ^ KEY_DECRYPT_BYTE for b in encrypted_key])
    
    return decrypted_key


# ============================================================================
# UNPACKER
# ============================================================================

def unpack_binary(input_file, output_file):
    """Main unpacking function"""
    
    print("[*] Reading packed binary...")
    with open(input_file, 'rb') as f:
        packed_data = f.read()
    
    print("[*] Parsing PE headers...")
    pe_info = read_pe_header(packed_data)
    print(f"    Entry Point RVA: 0x{pe_info['entry_point_rva']:08X}")
    
    # Check for packer signature
    entry_offset = pe_info['entry_point_rva']
    if packed_data[entry_offset] == 0x60:  # PUSHAD
        print("[+] Packer stub detected (PUSHAD signature)")
    else:
        print("[!] Warning: No PUSHAD at entry point")
    
    print("[*] Extracting XOR key from stub...")
    stub_section = find_section(packed_data, pe_info, '.packer')
    
    if stub_section:
        stub_data = packed_data[stub_section['raw_addr']:
                                stub_section['raw_addr']+stub_section['raw_size']]
        xor_key = extract_xor_key(stub_data)
        print(f"    XOR Key: {xor_key.hex()}")
    else:
        print("[!] Warning: .packer section not found, using default key")
        # Fallback to known key for educational purposes
        xor_key = bytes([
            0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
            0xBA, 0xBE, 0xF0, 0x0D, 0xC0, 0xDE, 0x42, 0x00
        ])
    
    print("[*] Finding encrypted .text section...")
    packed_section = find_section(packed_data, pe_info, '.packed')
    
    if not packed_section:
        # Try .text section (might be packed in place)
        packed_section = find_section(packed_data, pe_info, '.text')
    
    if not packed_section:
        print("[!] Error: Could not find encrypted section")
        return False
    
    print(f"    Found at: 0x{packed_section['raw_addr']:08X}")
    print(f"    Size: {packed_section['raw_size']} bytes")
    
    # Extract encrypted data
    encrypted_data = packed_data[packed_section['raw_addr']:
                                  packed_section['raw_addr']+packed_section['raw_size']]
    
    print("[*] Decrypting .text section...")
    decrypted_data = xor_decrypt(encrypted_data, xor_key)
    print(f"    Decrypted: {len(decrypted_data)} bytes")
    
    # Verify decryption (check for valid x86 code patterns)
    if decrypted_data[0:2] == b'\x55\x89':  # Common function prologue: PUSH EBP; MOV EBP, ESP
        print("[+] Decryption successful (valid x86 prologue detected)")
    else:
        print(f"[!] Warning: Unexpected bytes at start: {decrypted_data[0:16].hex()}")
    
    print("[*] Reconstructing unpacked binary...")
    unpacked_data = bytearray(packed_data)
    
    # Replace encrypted section with decrypted data
    start = packed_section['raw_addr']
    end = start + len(decrypted_data)
    unpacked_data[start:end] = decrypted_data
    
    # Fix entry point (remove stub, point to original OEP)
    # OEP is typically at the start of decrypted .text
    if packed_section:
        new_entry_rva = packed_section['virtual_addr']
        struct.pack_into('<I', unpacked_data, 
                        pe_info['opt_header_offset']+16, new_entry_rva)
        print(f"    Fixed entry point to: 0x{new_entry_rva:08X}")
    
    print("[*] Writing unpacked binary...")
    with open(output_file, 'wb') as f:
        f.write(unpacked_data)
    
    print(f"[+] Unpacking complete!")
    print(f"[+] Output: {output_file}")
    print(f"[+] Size: {len(unpacked_data)} bytes")
    
    return True


# ============================================================================
# ALTERNATIVE: Memory Dump Approach
# ============================================================================

def guide_memory_dump():
    """
    Guide for manual unpacking via memory dump
    (Alternative approach for educational purposes)
    """
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║              MANUAL UNPACKING GUIDE (Memory Dump Method)             ║
╚══════════════════════════════════════════════════════════════════════╝

This is an alternative to automated unpacking. Use x64dbg or similar:

STEP 1: Find Packer Stub
    • Load vault_v2.exe in x64dbg
    • Entry point should show PUSHAD (0x60)
    • This marks the beginning of the unpacking stub

STEP 2: Find Unpacking Loop
    • Look for XOR instruction in a loop
    • Pattern: XOR [reg], key_byte; INC reg; LOOP
    • Set breakpoint after the loop

STEP 3: Find OEP Jump
    • After unpacking loop, look for POPAD (0x61)
    • Followed by JMP or CALL to OEP
    • Set breakpoint on the JMP target

STEP 4: Dump Unpacked Code
    • Run to OEP breakpoint
    • Use Scylla or x64dbg's dump feature
    • Dump from current EIP to end of .text section

STEP 5: Fix Imports (if needed)
    • Use Scylla's IAT autosearch
    • Get imports → Fix dump
    • Save fixed binary

STEP 6: Verify
    • Load dumped binary in Ghidra
    • Should see clean, decompilable code
    • All strings should be visible (after XOR decryption)

For detailed walkthrough, see:
    https://www.sbytec.com/accessdenied/vault-v2/
    """)


# ============================================================================
# MAIN
# ============================================================================

def main():
    if len(sys.argv) < 2:
        print("Vault Challenge v2 - Automated Unpacker")
        print()
        print("Usage:")
        print("  python3 unpacker.py <packed.exe> <output.exe>")
        print("  python3 unpacker.py --guide")
        print()
        print("Examples:")
        print("  python3 unpacker.py vault_v2.exe vault_v2_unpacked.exe")
        print("  python3 unpacker.py --guide  # Show manual unpacking guide")
        sys.exit(1)
    
    if sys.argv[1] == '--guide':
        guide_memory_dump()
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
        success = unpack_binary(input_file, output_file)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
