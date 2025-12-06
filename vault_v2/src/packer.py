#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vault Challenge v2 — packer that creates .packer section and patches stub immediates.

Usage:
  python3 src/packer.py <input.exe> <output.exe> <stub.bin>

Behavior:
 - Reads input PE (PE32)
 - Extracts .text raw bytes and XOR-encrypts them
 - Patches stub:
     * MOV ECX, imm32  -> set packed_size
     * MOV EDI, imm32  -> set image_base + text_virtual_addr (destination VA)
     * JMP rel32       -> set rel32 to jump to original OEP
 - Creates new section ".packer" containing [patched stub][encrypted_text]
 - Sets AddressOfEntryPoint -> RVA of stub in new section
 - Updates SizeOfImage and NumberOfSections
"""
import sys, os, struct

XOR_KEY = bytes([
    0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0xBA, 0xBE, 0xF0, 0x0D, 0xC0, 0xDE, 0x42, 0x00
])

def read_u16(b, off): return struct.unpack_from('<H', b, off)[0]
def read_u32(b, off): return struct.unpack_from('<I', b, off)[0]
def pack_u16(b, off, v): struct.pack_into('<H', b, off, v)
def pack_u32(b, off, v): struct.pack_into('<I', b, off, v)

def align_up(x, a):
    return ((x + a - 1) // a) * a

def parse_headers(data):
    if data[0:2] != b'MZ':
        raise ValueError("Not MZ")
    e_lfanew = read_u32(data, 0x3C)
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        raise ValueError("Not PE")
    coff_off = e_lfanew + 4
    num_sections = read_u16(data, coff_off + 2)
    opt_hdr_size = read_u16(data, coff_off + 16)
    opt_off = coff_off + 20
    magic = read_u16(data, opt_off)
    if magic != 0x10b:
        raise ValueError("Only PE32 supported")
    address_of_entry_point = read_u32(data, opt_off + 16)
    image_base = read_u32(data, opt_off + 28)
    section_align = read_u32(data, opt_off + 32)
    file_align = read_u32(data, opt_off + 36)
    size_of_image = read_u32(data, opt_off + 56)
    size_of_headers = read_u32(data, opt_off + 60)
    section_table_off = e_lfanew + 24 + opt_hdr_size
    return {
        'e_lfanew': e_lfanew,
        'coff_off': coff_off,
        'opt_off': opt_off,
        'num_sections': num_sections,
        'opt_hdr_size': opt_hdr_size,
        'address_of_entry_point': address_of_entry_point,
        'image_base': image_base,
        'section_align': section_align,
        'file_align': file_align,
        'size_of_image': size_of_image,
        'size_of_headers': size_of_headers,
        'section_table_off': section_table_off
    }

def read_sections(data, hdr):
    secs = []
    off = hdr['section_table_off']
    for i in range(hdr['num_sections']):
        name = data[off:off+8].rstrip(b'\x00').decode(errors='ignore')
        virtual_size = read_u32(data, off+8)
        virtual_addr = read_u32(data, off+12)
        raw_size = read_u32(data, off+16)
        raw_ptr = read_u32(data, off+20)
        characteristics = read_u32(data, off+36)
        secs.append({
            'name': name,
            'virtual_size': virtual_size,
            'virtual_addr': virtual_addr,
            'raw_size': raw_size,
            'raw_ptr': raw_ptr,
            'characteristics': characteristics,
            'header_off': off
        })
        off += 40
    return secs

def xor_encrypt(data, key):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

def build_section_header(name, virtual_size, virtual_addr, raw_size, raw_ptr, characteristics):
    name_field = name.encode('ascii')[:8].ljust(8, b'\x00')
    h = bytearray(40)
    h[0:8] = name_field
    struct.pack_into('<I', h, 8, virtual_size)
    struct.pack_into('<I', h, 12, virtual_addr)
    struct.pack_into('<I', h, 16, raw_size)
    struct.pack_into('<I', h, 20, raw_ptr)
    struct.pack_into('<I', h, 36, characteristics)
    return h

def patch_stub_for_sizes_and_addrs(stub, packed_size, dest_va, oep_rva, stub_rva):
    """
    - Find first MOV ECX, imm32 (opcode B9 imm32) and set imm32=packed_size
    - Find first MOV EDI, imm32 (opcode BF imm32) and set imm32=dest_va
    - Find first JMP rel32 (opcode E9 rel32) with a "placeholder" rel and patch it to jump to oep_rva
      (we compute rel32 = oep_rva - (stub_rva + jmp_offset_in_stub + 5))
    """
    # patch MOV ECX (B9 imm32)
    patched_ecx = False
    for i in range(len(stub)-4):
        if stub[i] == 0xB9:
            struct.pack_into('<I', stub, i+1, packed_size)
            patched_ecx = True
            break
    if not patched_ecx:
        raise RuntimeError("Failed to find MOV ECX (B9) in stub to patch packed_size")

    # patch MOV EDI (BF imm32)
    patched_edi = False
    for i in range(len(stub)-4):
        if stub[i] == 0xBF:
            struct.pack_into('<I', stub, i+1, dest_va & 0xFFFFFFFF)
            patched_edi = True
            break
    if not patched_edi:
        raise RuntimeError("Failed to find MOV EDI (BF) in stub to patch destination VA")

    # find JMP rel32 (E9 rel32) and patch to jump to oep_rva
    jmp_off_in_stub = None
    for i in range(len(stub)-4):
        if stub[i] == 0xE9:
            # compute rel placeholder (we accept first E9)
            jmp_off_in_stub = i
            break
    if jmp_off_in_stub is None:
        raise RuntimeError("Failed to find JMP (E9) in stub to patch OEP jump")
    # compute rel32 relative to the instruction's RVA when stub is loaded at stub_rva
    rel32 = oep_rva - (stub_rva + jmp_off_in_stub + 5)
    # ensure signed 32-bit range
    if not -0x80000000 <= rel32 <= 0x7FFFFFFF:
        raise RuntimeError("Computed rel32 out of range for JMP: 0x{0:X}".format(rel32 & 0xFFFFFFFF))
    struct.pack_into('<i', stub, jmp_off_in_stub+1, int(rel32))
    return stub

def pack_binary(input_file, output_file, stub_file):
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    hdr = parse_headers(data)
    sections = read_sections(data, hdr)

    # locate .text
    text = None
    for s in sections:
        if s['name'] == '.text':
            text = s
            break
    if not text:
        raise RuntimeError(".text not found")

    text_raw_off = text['raw_ptr']
    text_raw_size = text['raw_size']
    if text_raw_off + text_raw_size > len(data):
        text_raw_size = max(0, len(data) - text_raw_off)
    text_raw = bytes(data[text_raw_off:text_raw_off + text_raw_size])
    encrypted_text = xor_encrypt(text_raw, XOR_KEY)
    packed_size = len(encrypted_text)

    with open(stub_file, 'rb') as f:
        stub = bytearray(f.read())

    # compute dest VA (absolute): image_base + text_virtual_addr
    dest_va = (hdr['image_base'] + text['virtual_addr']) & 0xFFFFFFFF
    original_oep = hdr['address_of_entry_point']  # RVA w.r.t image_base

    # We'll build a new section .packer placed after last section
    last = sections[-1]
    last_end_va = last['virtual_addr'] + align_up(last['virtual_size'], hdr['section_align'])
    new_va = align_up(last_end_va, hdr['section_align'])
    file_align = hdr['file_align'] or 0x200
    new_raw_ptr = align_up(len(data), file_align)

    # patch stub: we need stub_rva (RVA where stub will be mapped). We'll use new_va (stub offset 0 within new section)
    stub_rva = new_va

    # patch stub in-memory to set sizes/addrs
    patched_stub = patch_stub_for_sizes_and_addrs(stub, packed_size, dest_va, original_oep, stub_rva)

    # build appended bytes = patched_stub + encrypted_text
    appended = bytearray()
    appended.extend(patched_stub)
    appended.extend(encrypted_text)
    appended_len = len(appended)
    raw_size = align_up(appended_len, file_align)
    virtual_size = appended_len

    # pad to new_raw_ptr if needed
    pad_before = new_raw_ptr - len(data)
    if pad_before > 0:
        data.extend(b'\x00' * pad_before)

    # append and pad
    data.extend(appended)
    if raw_size - appended_len > 0:
        data.extend(b'\x00' * (raw_size - appended_len))

    # prepare section header .packer
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ

    sec_hdr = build_section_header = None
    name_field = ".packer"
    sec_hdr = bytearray(40)
    sec_hdr[0:8] = name_field.encode('ascii')[:8].ljust(8, b'\x00')
    struct.pack_into('<I', sec_hdr, 8, virtual_size)
    struct.pack_into('<I', sec_hdr, 12, new_va)
    struct.pack_into('<I', sec_hdr, 16, raw_size)
    struct.pack_into('<I', sec_hdr, 20, new_raw_ptr)
    struct.pack_into('<I', sec_hdr, 36, characteristics)

    # insert section header at end of section table
    sec_table_off = hdr['section_table_off']
    new_section_off = sec_table_off + (hdr['num_sections'] * 40)
    data[new_section_off:new_section_off] = sec_hdr

    # update NumberOfSections
    new_num_sections = hdr['num_sections'] + 1
    pack_u16(data, hdr['coff_off'] + 2, new_num_sections)

    # AddressOfEntryPoint -> RVA of stub (new_va + 0)
    pack_u32(data, hdr['opt_off'] + 16, new_va & 0xFFFFFFFF)

    # update SizeOfImage
    new_end = new_va + align_up(virtual_size, hdr['section_align'])
    new_size_of_image = align_up(new_end, hdr['section_align'])
    pack_u32(data, hdr['opt_off'] + 56, new_size_of_image & 0xFFFFFFFF)

    # write output
    with open(output_file, 'wb') as f:
        f.write(data)

    print("[+] Packed written:", output_file)
    print("    New section .packer RVA: 0x{0:08X}".format(new_va))
    print("    New NumberOfSections: ", new_num_sections)
    print("    AddressOfEntryPoint -> 0x{0:08X}".format(new_va))
    print("    SizeOfImage -> 0x{0:08X}".format(new_size_of_image))
    print("    Raw pointer (PointerToRawData) -> 0x{0:08X}".format(new_raw_ptr))
    print("    Appended bytes (stub + encrypted_text):", appended_len)

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 src/packer.py <input.exe> <output.exe> <stub.bin>")
        sys.exit(1)
    inp = sys.argv[1]; out = sys.argv[2]; stub = sys.argv[3]
    if not os.path.exists(inp):
        print("Input not found:", inp); sys.exit(1)
    if not os.path.exists(stub):
        print("Stub not found:", stub); sys.exit(1)
    try:
        pack_binary(inp, out, stub)
    except Exception as e:
        print("Packing failed:", e)
        import traceback; traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()

