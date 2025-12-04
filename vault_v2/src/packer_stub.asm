; ============================================================================
; VAULT CHALLENGE v2 - Custom Packer Stub
; ============================================================================
; Purpose: Unpacks the XOR-encrypted .packed section at runtime
;
; Algorithm:
;   1. Save all registers (PUSHAD)
;   2. Get base address (CALL trick)
;   3. Decrypt XOR key (16 bytes)
;   4. XOR decrypt .packed section
;   5. Copy to original .text location
;   6. Fix imports dynamically (LoadLibrary + GetProcAddress)
;   7. Restore registers (POPAD)
;   8. Jump to Original Entry Point (OEP)
;
; Detection Signatures:
;   - PUSHAD at entry (0x60)
;   - CALL $+5 (position-independent code)
;   - XOR decryption loop
;   - POPAD before OEP jump (0x61)
;
; Assemble: nasm -f bin packer_stub.asm -o stub.bin
; ============================================================================

BITS 32
ORG 0x00401000  ; Default PE entry point

; ============================================================================
; ENTRY POINT
; ============================================================================

_start:
    PUSHAD                      ; Save all registers (signature: 0x60)
    
    ; Get current EIP (position-independent code trick)
    CALL get_eip
get_eip:
    POP  EBP                    ; EBP = current EIP
    SUB  EBP, (get_eip - _start)  ; EBP = base address of stub
    
    ; Setup pointers
    LEA  ESI, [EBP + xor_key]           ; ESI = encrypted XOR key
    LEA  EDI, [EBP + decrypted_key]     ; EDI = decrypted key buffer
    MOV  ECX, 16                        ; Key length
    MOV  AL, 0x42                       ; Decrypt key for the key
    
    ; Decrypt the XOR key itself
decrypt_key_loop:
    LODSB                       ; AL = [ESI++]
    XOR  AL, 0x42               ; Decrypt with simple XOR
    STOSB                       ; [EDI++] = AL
    LOOP decrypt_key_loop
    
    ; Setup for main decryption
    LEA  ESI, [EBP + packed_data]       ; ESI = encrypted .packed section
    MOV  EDI, 0x00402000                ; EDI = destination (.text location)
    MOV  ECX, packed_size               ; ECX = size of packed data
    LEA  EBX, [EBP + decrypted_key]     ; EBX = XOR key (16 bytes)
    XOR  EDX, EDX                       ; EDX = key index
    
    ; Main decryption loop (XOR with rotating 16-byte key)
decrypt_main_loop:
    LODSB                       ; AL = [ESI++]
    XOR  AL, BYTE [EBX + EDX]   ; XOR with key[index]
    STOSB                       ; [EDI++] = AL
    INC  EDX                    ; index++
    AND  EDX, 0x0F              ; index %= 16 (wrap around)
    LOOP decrypt_main_loop
    
    ; Fix imports (simplified - assumes LoadLibrary/GetProcAddress available)
    ; In real implementation, would dynamically resolve all imports
    ; For CTF simplicity, imports are handled by unpacked code
    
    ; Cleanup and jump to OEP
    POPAD                       ; Restore all registers (signature: 0x61)
    
    ; Jump to Original Entry Point (will be patched by packer.py)
    JMP  original_entry_point
    
; ============================================================================
; DATA SECTION (Will be filled by packer.py)
; ============================================================================

xor_key:
    ; 16-byte XOR key (encrypted with 0x42)
    ; Will be filled: { 0x13^0x42, 0x37^0x42, 0xDE^0x42, ... }
    DB 0x51, 0x75, 0x9C, 0xEF, 0xFC, 0xAD, 0x88, 0xBC
    DB 0xF8, 0xFC, 0xB2, 0x4F, 0x82, 0x9C, 0x00, 0x42

decrypted_key:
    ; Buffer for decrypted key (16 bytes)
    TIMES 16 DB 0x00

packed_data:
    ; Encrypted .text section data (will be appended by packer.py)
    ; Format: XOR encrypted with the 16-byte key
    ; This is a placeholder - actual data appended during packing

packed_size EQU 0x1000  ; Will be patched by packer.py with actual size

original_entry_point:
    ; Will be patched by packer.py to point to real OEP
    ; Placeholder: infinite loop for safety
    JMP $

; ============================================================================
; STUB END MARKER (for packer.py to find data insertion point)
; ============================================================================
stub_end:
    DB "STUB_END_MARKER"
