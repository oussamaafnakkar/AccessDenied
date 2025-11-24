/*
   YARA Rules for Vault Challenge Detection
   
   Author: Oussama Afnakkar (@Oafnakkar)
   Blog: Secure Byte Chronicles (sbytec.com)
   Date: 2025-11-24
   Version: 1.0
   
   Purpose: Detect Vault Challenge educational ransomware binary
   
   Usage:
     yara vault.yar /vault_challenge/bin/vault_challenge.exe
     yara -r vault.yar vault_challenge/bin/
*/

import "math" 

rule Vault_Challenge_Packed {
    meta:
        description = "Detects packed Vault Challenge binary"
        author = "Oussama Afnakkar"
        date = "2024-11-23"
        reference = "https://sbytec.com/accessdenied/vault-challenge/"
        severity = "Medium"
        category = "Educational Malware"
        hash_md5 = "ac461b8a14d97c46ac073ab14c4c7fbc" 
        hash_sha256 = "59a37a62cee9ab2ebdb55f1a3899089816069d1ddbab0118fd25d7ca76c32341"
        
    strings:
        // UPX packer signatures
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        
        // Challenge banner (might be obfuscated in packed version)
        $banner1 = "THE VAULT CHALLENGE" ascii wide
        $banner2 = "Your files have been encrypted" ascii wide nocase
        
        // Magic constant (little-endian: 0xDEADBEEF)
        $const = { EF BE AD DE }
        
        // Encrypted flag pattern (starts with 0x33 0x23 0x22)
        $encrypted_flag = { 33 23 22 5B 50 35 57 35 }
        
    condition:
        // PE file signature
        uint16(0) == 0x5A4D and
        
        // File size constraints (packed version ~12KB)
        filesize < 20KB and
        
        // Detection logic
        (
            // Strong indicator: UPX signatures + constant
            (2 of ($upx*) and $const) or
            
            // Alternative: Banner + encrypted flag
            ($banner1 and $encrypted_flag)
        ) and
        
        // High entropy check (UPX packed)
        math.entropy(0, filesize) > 7.0
}


rule Vault_Challenge_Unpacked {
    meta:
        description = "Detects unpacked Vault Challenge binary"
        author = "Oussama Afnakkar"
        date = "2024-11-24"
        reference = "https://sbytec.com/accessdenied/vault-challenge/"
        severity = "Medium"
        category = "Educational Malware"
        
    strings:
        // Banner strings (clearly visible when unpacked)
        $banner1 = "THE VAULT CHALLENGE" ascii
        $banner2 = "Your files have been encrypted!" ascii
        $banner3 = "Reverse engineer this program" ascii
        $banner4 = "Hint: The key is in your machine" ascii
        
        // Debug/status messages
        $debug1 = "Debugger detected! Exiting..." ascii
        $debug2 = "Hardware ID:" ascii
        $debug3 = "Derived Key:" ascii
        $debug4 = "DECRYPTED FLAG:" ascii
        
        // API function names
        $api1 = "IsDebuggerPresent" ascii nocase
        $api2 = "GetVolumeInformationA" ascii nocase
        $api3 = "GetVolumeInformationW" ascii nocase
        
        // Magic constant
        $const = { EF BE AD DE }
        
        // Function names (if not stripped)
        $func1 = "vault_logic" ascii
        $func2 = "get_hardware_id" ascii
        $func3 = "derive_key" ascii
        $func4 = "xor_decrypt" ascii
        $func5 = "display_banner" ascii
        
    condition:
        // PE file
        uint16(0) == 0x5A4D and
        
        // File size constraints (unpacked ~45KB)
        filesize > 30KB and filesize < 60KB and
        
        // Detection logic
        (
            // Strong: Multiple banner strings + APIs
            (2 of ($banner*) and 2 of ($api*)) or
            
            // Alternative: Debug messages + constant + APIs
            (2 of ($debug*) and $const and 1 of ($api*)) or
            
            // High confidence: Function names present
            (3 of ($func*))
        ) and
        
        // Normal entropy (unpacked)
        math.entropy(0, filesize) < 7.0
}


rule Vault_Challenge_Source_Code {
    meta:
        description = "Detects Vault Challenge C source code"
        author = "Oussama Afnakkar"
        date = "2025-11-24"
        
    strings:
        $comment1 = "VAULT CHALLENGE - Educational Ransomware Simulation"
        $comment2 = "For Secure Byte Chronicles Blog"
        $author = "Oussama Afnakkar"
        $disclaimer = "FOR EDUCATIONAL PURPOSES ONLY"
        
        // Key function definitions
        $func1 = "void vault_logic(void)"
        $func2 = "uint32_t get_hardware_id()"
        $func3 = "uint32_t derive_key(uint32_t hwid)"
        $func4 = "void xor_decrypt("
        
    condition:
        // Text file or C source
        (uint16(0) == 0x2F2A or  // /* comment
         uint16(0) == 0x2F2F or  // // comment
         uint32(0) == 0x6E692F2F or  // //in
         uint32(0) == 0x636E6923) and  // #inc
        
        // Multiple identifiers
        2 of ($comment*) or
        3 of ($func*)
}


rule Generic_XOR_Weak_Crypto {
    meta:
        description = "Generic detection for weak XOR-based encryption"
        author = "Oussama Afnakkar"
        severity = "Medium"
        
    strings:
        // XOR operation patterns in assembly
        $xor_loop1 = { 8A ?? ?? 32 ?? ?? 88 ?? ?? }  // MOV AL, []; XOR AL, []; MOV [], AL
        $xor_loop2 = { 32 ?? ?? 88 ?? ?? 40 }        // XOR reg, []; MOV [], reg; INC
        
        // Hardcoded XOR constants
        $xor_const1 = { 33 C0 }  // XOR EAX, EAX
        $xor_const2 = { 35 }     // XOR EAX, imm32
        
        // Common "magic" constants (often used as keys)
        $magic1 = { EF BE AD DE }  // 0xDEADBEEF
        $magic2 = { BE BA FE CA }  // 0xCAFEBABE
        $magic3 = { EF BE ED FE }  // 0xFEEDBEEF
        
    condition:
        uint16(0) == 0x5A4D and
        (
            1 of ($xor_loop*) and
            1 of ($magic*)
        ) and
        math.entropy(0, filesize) > 6.5
}


rule Vault_Challenge_Detection_Suite {
    meta:
        description = "Comprehensive detection for any Vault Challenge variant"
        author = "Oussama Afnakkar"
        
    condition:
        Vault_Challenge_Packed or
        Vault_Challenge_Unpacked or
        Vault_Challenge_Source_Code
}
