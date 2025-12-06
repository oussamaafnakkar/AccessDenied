; ============================================================================
; VAULT CHALLENGE v2 - Packer Stub (explicit E9 placeholder)
; - Contains MOV ECX, imm32 (B9 imm32) for packed_size (patched by packer.py)
; - Contains MOV EDI, imm32 (BF imm32) for dest VA (patched by packer.py)
; - Contains explicit E9 00 00 00 00 placeholder for original OEP jump (patched)
; - Decrypts 16-byte XOR key (XOR with 0x42), XOR-decrypts payload with rotating key
;
; Assemble: nasm -f bin src/packer_stub.asm -o bin/stub.bin
; ============================================================================

BITS 32
ORG 0x00401000

_start:
    PUSHAD                      ; save regs

    ; position independent base
    CALL get_eip
get_eip:
    POP  EBP
    SUB  EBP, (get_eip - _start)

    ; --- decrypt XOR key (16 bytes) ---
    LEA  ESI, [EBP + xor_key]       ; encrypted key bytes
    LEA  EDI, [EBP + decrypted_key] ; dest buffer for decrypted key
    MOV  ECX, 16
decrypt_key_loop:
    LODSB
    XOR  AL, KEY_XOR_BYTE
    STOSB
    LOOP decrypt_key_loop

    ; --- packed size (patched by packer.py via B9 imm32) ---
    ; mov ecx, <packed_size>
    mov ecx, 0x00001000      ; B9 imm32 placeholder -> patched to actual packed_size

    ; --- destination VA (patched by packer.py via BF imm32) ---
    ; mov edi, <dest_va>
    mov edi, 0x00402000      ; BF imm32 placeholder -> patched to target VA

    ; EBX -> pointer to decrypted key (16 bytes)
    LEA  EBX, [EBP + decrypted_key]
    XOR  EDX, EDX            ; key index = 0

decrypt_main_loop:
    LODSB
    XOR  AL, BYTE [EBX + EDX]
    STOSB                     ; store to [EDI]
    INC  EDI
    INC  EDX
    AND  EDX, 0x0F
    LOOP decrypt_main_loop

    POPAD

    ; --- explicit JMP placeholder (E9 rel32) to patch to original OEP ---
    ; packer.py searches for 0xE9 and writes rel32 after it.
    db 0xE9, 0x00, 0x00, 0x00, 0x00

; ---------------------------------------------------------------------------
; DATA (patched / appended by packer.py)
; ---------------------------------------------------------------------------

KEY_XOR_BYTE equ 0x42

xor_key:
    ; encrypted XOR key (16 bytes) - can be overwritten by packer.py if desired
    db 0x51,0x75,0x9C,0xEF,0xFC,0xAD,0x88,0xBC,0xF8,0xFC,0xB2,0x4F,0x82,0x9C,0x00,0x42

decrypted_key:
    times 16 db 0x00

; packed_data label: actual encrypted bytes are appended by packer.py after the stub
packed_data:
    ; (no static bytes here — packer.py appends encrypted .text bytes after the stub)

stub_end:
    db "STUB_END_MARKER"

