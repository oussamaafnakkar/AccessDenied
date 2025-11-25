rule Vault_Challenge {
    meta:
        description = "Detects Vault Challenge binary"
        author = "Oussama Afnakkar"
        date = "2025-11-24"
    
    strings:
        $banner = "THE VAULT CHALLENGE" ascii
        $magic1 = { EF BE AD DE }  // 0xDEADBEEF
        $magic2 = { 34 12 CD AB }  // 0xABCD1234 (little-endian)
        $api1 = "IsDebuggerPresent" ascii
    
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        all of them
}
