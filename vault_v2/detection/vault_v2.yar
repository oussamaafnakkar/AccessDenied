rule Vault_Challenge_v2
{
    meta:
        name = "Vault Challenge v2"
        author = "Oussama Afnakkar - Secure Byte Chronicles"
        date = "2025-01-01"
        description = "Detects both packed and unpacked versions of Vault Challenge v2"
        version = "1.0"
        category = "CTF / Educational / Reverse Engineering"
    
    strings:
        // ASCII banner from unpacked binary
        $banner = "Your files have been encrypted!" ascii
        
        // XOR/RC4 key derivation constants
        $magic1 = { EF BE AD DE }    // 0xDEADBEEF (little endian)
        $magic2 = { 37 13 37 13 }    // 0x13371337 (little endian)

        // Fixed HWID constant (0xABCD1234)
        $hwid = { 34 12 CD AB }

        // Username "CTFPlayer"
        $user = "CTFPlayer" ascii

        // RC4 key repetition pattern (3d bf fd 08 repeated)
        $rc4_pattern = { 3D BF FD 08 3D BF FD 08 3D BF FD 08 3D BF FD 08 }

        // Packer stub signature: PUSHAD (0x60)
        $pushad = { 60 } wide ascii

        // Known stub marker (found in stub.bin)
        $stub_marker = { 13 37 DE AD BE EF CA FE BA BE F0 0D C0 DE 42 00 }

    condition:
        uint16(0) == 0x5A4D and
        (
            // Match unpacked binary (banner + constants)
            all of ($banner, $magic1, $magic2) or
            
            // Match packed binary (stub + pushad)
            any of ($stub_marker, $pushad)
        )
}

