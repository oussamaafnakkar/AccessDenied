/*
 * VAULT CHALLENGE - Educational Ransomware Simulation
 * For Secure Byte Chronicles Blog
 * 
 * DISCLAIMER: For educational purposes only. Do not use maliciously.
 * 
 * Compile: gcc vault_challenge.c -o vault_challenge.exe -O2 -s
 * Pack: upx --best vault_challenge.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Obfuscated flag (XOR encoded)
unsigned char encrypted_flag[] = {
    0x33, 0x23, 0x22, 0x5b, 0x50, 0x35, 0x57, 0x35,
    0x50, 0x33, 0x35, 0x1f, 0x35, 0x34, 0x37, 0x31,
    0x34, 0x35, 0x35, 0x50, 0x31, 0x34, 0x37, 0x1f,
    0x33, 0x20, 0x33, 0x54, 0x35, 0x50, 0x7d, 0x00
};

// Anti-debugging check
int check_debugger() {
#ifdef _WIN32
    // Simple IsDebuggerPresent check
    if (IsDebuggerPresent()) {
        return 1;
    }
#endif
    return 0;
}

// Simulate getting hardware ID (for key derivation)
uint32_t get_hardware_id() {
#ifdef _WIN32
    DWORD volume_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, 
                          NULL, NULL, NULL, 0);
    return volume_serial;
#else
    // For Linux/demo purposes, use a fixed value
    return 0x12345678;
#endif
}

// Derive encryption key from hardware ID
uint32_t derive_key(uint32_t hwid) {
    // Weak key derivation (intentionally vulnerable)
    return hwid ^ 0xDEADBEEF;
}

// XOR encryption/decryption
void xor_decrypt(unsigned char *data, size_t len, uint32_t key) {
    unsigned char *key_bytes = (unsigned char *)&key;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key_bytes[i % sizeof(key)];
    }
}

// Display banner
void display_banner() {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║     🔒 THE VAULT CHALLENGE 🔒       ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Your files have been encrypted!    ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Reverse engineer this program to   ║\n");
    printf("  ║   recover the hidden flag.           ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Hint: The key is in your machine   ║\n");
    printf("  ╚══════════════════════════════════════╝\n");
    printf("\n");
}

// Obfuscated main logic
void vault_logic() {
    // Anti-debug check
    if (check_debugger()) {
        printf("[!] Debugger detected! Exiting...\n");
        exit(1);
    }
    
    display_banner();
    
    // Get hardware-based key
    uint32_t hwid = get_hardware_id();
    uint32_t key = derive_key(hwid);
    
    printf("[*] Hardware ID: 0x%08X\n", hwid);
    printf("[*] Derived Key: 0x%08X\n", key);
    printf("[*] Attempting decryption...\n\n");
    
    // Decrypt the flag
    unsigned char flag_buffer[sizeof(encrypted_flag)];
    memcpy(flag_buffer, encrypted_flag, sizeof(encrypted_flag));
    xor_decrypt(flag_buffer, sizeof(encrypted_flag) - 1, key);
    
    // Display result
    printf("╔═══════════════════════════════════════╗\n");
    printf("║ DECRYPTED FLAG:                       ║\n");
    printf("║ %s ║\n", flag_buffer);
    printf("╚═══════════════════════════════════════╝\n\n");
    
    printf("[+] Congratulations! You've cracked the vault!\n");
    printf("[+] Share your success: #VaultChallenge #ReverseEngineering\n\n");
}

int main() {
    vault_logic();
    return 0;
}

/*
 * LEARNING OBJECTIVES:
 * 
 * 1. Unpacking: Binary is packed with UPX
 *    - Tool: upx -d vault_challenge.exe
 * 
 * 2. Anti-Debugging: IsDebuggerPresent() check
 *    - Bypass: Patch JE to JMP, or use anti-anti-debug plugins
 * 
 * 3. Key Derivation: Hardware-based (weak)
 *    - Analyze: GetVolumeInformation → XOR with 0xDEADBEEF
 * 
 * 4. Encryption: Simple XOR (easily reversible)
 *    - Reverse: Write Python decryptor
 * 
 * 5. Flag Format: SBC{r3v3rs3_3ng1n33r1ng_m4st3r}
 * 
 * DETECTION SIGNATURES:
 * - Imports: IsDebuggerPresent, GetVolumeInformationA
 * - Strings: "Debugger detected", "THE VAULT CHALLENGE"
 * - Entropy: High (due to UPX packing)
 */
