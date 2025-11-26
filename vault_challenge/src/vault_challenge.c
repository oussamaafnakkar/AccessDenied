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


// Obfuscated flag (XOR encoded with HWID=0xABCD1234)
// Flag: SBC{r3v3rs3_3ng1n33r1ng_m4st3r}
unsigned char encrypted_flag[] = {
    0x88, 0xee, 0x23, 0x0e, 0xa9, 0x9f, 0x16, 0x46,
    0xa9, 0xdf, 0x53, 0x2a, 0xe8, 0xc2, 0x07, 0x44,
    0xb5, 0x9f, 0x53, 0x07, 0xea, 0xc2, 0x07, 0x2a,
    0xb6, 0x98, 0x13, 0x01, 0xe8, 0xde, 0x1d
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
// IMPORTANT: This uses a FIXED value for CTF consistency
uint32_t get_hardware_id() {
    // For CTF/educational purposes, use a fixed hardware ID
    // This ensures all participants can decrypt the flag regardless of their machine
    return 0xABCD1234;  // Fixed hardware ID
    
    /* Original implementation (commented out for reference):
     * This would make the challenge machine-specific, which is bad for CTFs
     * 
#ifdef _WIN32
    DWORD volume_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &volume_serial, 
                          NULL, NULL, NULL, 0);
    return volume_serial;
#else
    return 0x12345678;
#endif
    */
}

// Derive encryption key from hardware ID
uint32_t derive_key(uint32_t hwid) {
    // Weak key derivation (intentionally vulnerable)
    // Real ransomware would use CryptGenRandom + proper KDF
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
    printf("║ %-37s ║\n", flag_buffer);
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
 *    - Bypass: Patch JNZ to NOP, or use ScyllaHide plugin
 * 
 * 3. Key Derivation: Fixed hardware ID (0xABCD1234)
 *    - Analyze: Fixed value XOR 0xDEADBEEF = 0x7532ACDB
 *    - Note: Real malware would use actual system HWID
 * 
 * 4. Encryption: Simple XOR (easily reversible)
 *    - Reverse: Write Python decryptor
 * 
 * 5. Flag Format: SBC{r3v3rs3_3ng1n33r1ng_m4st3r}
 * 
 * KEY DERIVATION EXAMPLE:
 *   Hardware ID:  0xABCD1234
 *   Magic XOR:    0xDEADBEEF
 *                 ___________
 *   Derived Key:  0x7532ACDB
 * 
 * DETECTION SIGNATURES:
 * - Imports: IsDebuggerPresent
 * - Strings: "Debugger detected", "THE VAULT CHALLENGE"
 * - Entropy: High (due to UPX packing)
 * - Constants: 0xDEADBEEF, 0xABCD1234
 * 
 * WHY FIXED HWID FOR CTF?
 * - Ensures all participants can solve the challenge
 * - Cross-platform compatibility (Windows/Linux/macOS)
 * - Reproducible results for verification
 * - Still teaches the same RE concepts
 * 
 * REAL-WORLD COMPARISON:
 * Real ransomware would:
 * - Actually read system volume serial
 * - Use CryptGenRandom for proper randomness
 * - Implement AES-256 + RSA-4096 hybrid encryption
 * - Generate unique keys per victim
 * - Store encrypted keys, delete plaintext keys
 */
