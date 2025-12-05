/*
 * VAULT CHALLENGE v2 - Educational Malware Simulation
 * For Secure Byte Chronicles Blog
 *
 * DISCLAIMER: For educational purposes only. Do not use maliciously.
 *
 * Minor fixes: Null-terminate flag buffer before printing, safer djb2, portable RDTSC.
 *
 * Compile: i686-w64-mingw32-gcc vault_v2.c -o vault_v2_unpacked.exe -O2 -s -static
 * Pack: python3 packer.py vault_v2_unpacked.exe vault_v2.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
/* prefer MSVC intrinsic when available; otherwise fallback to inline asm */
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#else
#include <unistd.h>
#endif

// ============================================================================
// CONFIGURATION (Fixed for CTF reproducibility)
// ============================================================================
#define FIXED_HWID       0xABCD1234
#define FIXED_USERNAME   "CTFPlayer"
#define FIXED_TIMESTAMP  0x65432100
#define MAGIC_1          0xDEADBEEF
#define MAGIC_2          0x13371337
#define SESSION_XOR      0x12345678
#define TIMING_THRESHOLD 100000

// ============================================================================
// ENCRYPTED DATA (will be encrypted at compile time by packer)
// ============================================================================

// Flag format: SBC{d3crypt3d_53ss10n_<session_id>_v2}
// Session ID: timestamp ^ SESSION_XOR
uint8_t encrypted_flag[] = {
    0xad, 0x61, 0xbf, 0x75, 0xe1, 0x91, 0x32, 0x41,
    0x79, 0xdb, 0x35, 0xac, 0x78, 0x7a, 0x10, 0x22,
    0xe1, 0xec, 0x2f, 0x2c, 0x32, 0xf8, 0x14, 0x36,
    0x34, 0x78, 0x62, 0x1e, 0xbd, 0x18, 0xa5, 0x10,
    0x28, 0x7c
};
size_t encrypted_flag_len = sizeof(encrypted_flag);

// Encrypted strings (XOR encrypted at runtime)
typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t key;
} encrypted_string_t;

/* String storage (encrypted) */
/* Note: arrays do not contain trailing NUL; lengths used when printing */
uint8_t str_banner[] = {0x2b, 0x2d, 0x36, 0x5e, 0x23, 0x34, 0x3f, 0x3b, 0x5e, 0x30, 0x2d, 0x34, 0x3f, 0x3f, 0x36, 0x3d, 0x38, 0x36, 0x5e, 0x27, 0x4a};  // "THE VAULT CHALLENGE v2" ^ 0x42
uint8_t str_hwid[] = {0x18, 0x71, 0x1f, 0x35, 0x05, 0x0b, 0x13, 0x08, 0x16, 0x04, 0x35, 0x0a, 0x09, 0x62, 0x35, 0x63, 0x49, 0x62, 0x6e};  // "[*] Hardware ID: 0x%08X\n" ^ 0x55
uint8_t str_key[] = {0x18, 0x71, 0x1f, 0x35, 0x09, 0x04, 0x13, 0x02, 0x17, 0x04, 0x03, 0x35, 0x0e, 0x04, 0x10, 0x62, 0x35, 0x63, 0x49, 0x62, 0x6e};  // "[*] Derived Key: 0x%08X\n" ^ 0x55
uint8_t str_decrypt[] = {0x18, 0x71, 0x1f, 0x35, 0x08, 0x04, 0x02, 0x13, 0x10, 0x11, 0x15, 0x02, 0x3f, 0x35, 0x05, 0x3f, 0x00, 0x08, 0x60, 0x60, 0x60, 0x6e};  // "[*] Decrypting flag...\n" ^ 0x55
uint8_t str_flag_label[] = {0x05, 0x3f, 0x00, 0x08, 0x62, 0x35};  // "FLAG: " ^ 0x55
uint8_t str_congrats[] = {0x18, 0x71, 0x1f, 0x35, 0x02, 0x3e, 0x3f, 0x08, 0x13, 0x00, 0x15, 0x16, 0x3f, 0x00, 0x15, 0x02, 0x3e, 0x3f, 0x14, 0x60, 0x35, 0x30, 0x3e, 0x16, 0x6a, 0x17, 0x04, 0x35, 0x02, 0x13, 0x00, 0x02, 0x0a, 0x04, 0x03, 0x35, 0x15, 0x07, 0x04, 0x35, 0x17, 0x00, 0x16, 0x3f, 0x15, 0x60, 0x6e};  // "[+] Congratulations! You've cracked the vault!\n" ^ 0x55
uint8_t str_debug[] = {0x18, 0x60, 0x1f, 0x35, 0x09, 0x04, 0x01, 0x16, 0x08, 0x08, 0x04, 0x13, 0x35, 0x03, 0x04, 0x15, 0x04, 0x02, 0x15, 0x04, 0x03, 0x60, 0x35, 0x04, 0x19, 0x02, 0x15, 0x02, 0x3f, 0x08, 0x60, 0x60, 0x60, 0x6e};  // "[!] Debugger detected! Exiting...\n" ^ 0x55
uint8_t str_vm[] = {0x18, 0x60, 0x1f, 0x35, 0x17, 0x02, 0x13, 0x15, 0x16, 0x00, 0x3f, 0x35, 0x3c, 0x00, 0x02, 0x07, 0x02, 0x3f, 0x04, 0x35, 0x03, 0x04, 0x15, 0x04, 0x02, 0x15, 0x04, 0x03, 0x60, 0x35, 0x04, 0x19, 0x02, 0x15, 0x02, 0x3f, 0x08, 0x60, 0x60, 0x60, 0x6e};  // "[!] Virtual Machine detected! Exiting...\n" ^ 0x55

// ============================================================================
// HELPER: portable RDTSC
// ============================================================================
#ifdef _WIN32
static inline uint64_t read_tsc(void) {
  #if defined(_MSC_VER)
    return __rdtsc();
  #else
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
  #endif
}
#else
static inline uint64_t read_tsc(void) {
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif

// ============================================================================
// STRING DECRYPTION
// ============================================================================

void decrypt_string(uint8_t *str, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

void print_encrypted(const uint8_t *str, size_t len, uint8_t key) {
    uint8_t *temp = (uint8_t *)malloc(len + 1);
    if (!temp) return;
    memcpy(temp, str, len);
    decrypt_string(temp, len, key);
    temp[len] = '\0';
    printf("%s", temp);
    free(temp);
}

// ============================================================================
// ANTI-ANALYSIS: VM DETECTION
// ============================================================================

#ifdef _WIN32
int check_vm_registry() {
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);

    // Check VirtualBox
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;  // VirtualBox detected
    }

    // Check VMware
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\VMware, Inc.\\VMware Tools",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;  // VMware detected
    }

    // Check SCSI identifier
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "Identifier", NULL, NULL,
                             (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if (strstr(buffer, "VBOX") || strstr(buffer, "VMware")) {
                RegCloseKey(hKey);
                return 1;  // VM detected in SCSI identifier
            }
        }
        RegCloseKey(hKey);
    }

    return 0;  // No VM detected
}
#else
int check_vm_registry() {
    // Stub for Linux - always return 0 (no VM)
    (void)0;
    return 0;
}
#endif

// ============================================================================
// ANTI-ANALYSIS: TIMING-BASED ANTI-DEBUG
// ============================================================================
int check_timing() {
#ifdef _WIN32
    uint64_t start = read_tsc();

    // Dummy operations
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }

    uint64_t end = read_tsc();
    uint64_t delta = end - start;

    // If too slow, debugger likely present (single-stepping)
    if (delta > TIMING_THRESHOLD) {
        return 1;  // Debugger detected
    }
#endif
    return 0;
}

// ============================================================================
// ANTI-ANALYSIS: IsDebuggerPresent (from v1)
// ============================================================================
int check_debugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        return 1;
    }
#endif
    return 0;
}

// ============================================================================
// KEY DERIVATION (Complex, multi-stage)
// ============================================================================

// DJB2 hash algorithm (use unsigned char to avoid sign-extension issues)
uint32_t djb2_hash(const char *s) {
    uint32_t hash = 5381;
    unsigned char c;
    while ((c = (unsigned char)*s++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

uint32_t get_hardware_id() {
    // Fixed for CTF reproducibility (same as v1)
    return FIXED_HWID;
}

uint32_t get_timestamp() {
    // Fixed for CTF reproducibility
    return FIXED_TIMESTAMP;
}

void derive_keys(uint32_t *xor_key_out, uint8_t *rc4_key_out) {
    // Stage 1: Hardware ID
    uint32_t hwid = get_hardware_id();

    // Stage 2: Username hash
    uint32_t username_hash = djb2_hash(FIXED_USERNAME);

    // Stage 3: Timestamp
    uint32_t timestamp = get_timestamp();

    // Stage 4: Complex derivation
    uint32_t stage1 = hwid ^ MAGIC_1;           // 0x7560ACDB (same as v1)
    uint32_t stage2 = username_hash ^ timestamp;
    uint32_t xor_key = (stage1 + stage2) ^ MAGIC_2;

    *xor_key_out = xor_key;

    // Stage 5: Generate RC4 key from XOR key
    for (int i = 0; i < 16; i++) {
        rc4_key_out[i] = (xor_key >> ((i % 4) * 8)) & 0xFF;
    }
}

// ============================================================================
// ENCRYPTION: XOR (Stage 1)
// ============================================================================
void xor_decrypt(uint8_t *data, size_t len, uint32_t key) {
    uint8_t *key_bytes = (uint8_t *)&key;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key_bytes[i % 4];
    }
}

// ============================================================================
// ENCRYPTION: RC4 (Stage 2)
// ============================================================================
void rc4_init(uint8_t *S, const uint8_t *key, size_t keylen) {
    // Initialize S-box
    for (int i = 0; i < 256; i++) {
        S[i] = (uint8_t)i;
    }

    // Key Scheduling Algorithm (KSA)
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        // Swap
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void rc4_crypt(uint8_t *S, uint8_t *data, size_t len) {
    // Pseudo-Random Generation Algorithm (PRGA)
    int i = 0, j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        // Swap
        uint8_t temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        uint8_t K = S[(S[i] + S[j]) & 0xFF];
        data[k] ^= K;
    }
}

// ============================================================================
// DISPLAY BANNER
// ============================================================================
void display_banner() {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║     🔒 ");
    print_encrypted(str_banner, sizeof(str_banner), 0x42);
    printf(" 🔒      ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Your files have been encrypted!    ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Reverse engineer this program to   ║\n");
    printf("  ║   recover the hidden flag.           ║\n");
    printf("  ║                                      ║\n");
    printf("  ║   Hint: Nothing is as it seems...    ║\n");
    printf("  ╚══════════════════════════════════════╝\n");
    printf("\n");
}

// ============================================================================
// MAIN LOGIC
// ============================================================================
void vault_logic() {
    // Anti-analysis checks
    if (check_debugger()) {
        print_encrypted(str_debug, sizeof(str_debug), 0x55);
        exit(1);
    }

    if (check_vm_registry()) {
        print_encrypted(str_vm, sizeof(str_vm), 0x55);
        exit(1);
    }

    if (check_timing()) {
        print_encrypted(str_debug, sizeof(str_debug), 0x55);
        exit(1);
    }

    // Display banner
    display_banner();

    // Derive keys
    uint32_t xor_key;
    uint8_t rc4_key[16];
    derive_keys(&xor_key, rc4_key);

    uint32_t hwid = get_hardware_id();
    print_encrypted(str_hwid, sizeof(str_hwid) - 1, 0x55);
    printf("0x%08X\n", hwid);

    print_encrypted(str_key, sizeof(str_key) - 1, 0x55);
    printf("0x%08X\n", xor_key);

    print_encrypted(str_decrypt, sizeof(str_decrypt), 0x55);

    // Decrypt flag (multi-stage)
    uint8_t *flag_buffer = (uint8_t *)malloc(encrypted_flag_len + 1);
    if (!flag_buffer) {
        fprintf(stderr, "[!] Out of memory\n");
        return;
    }
    memcpy(flag_buffer, encrypted_flag, encrypted_flag_len);

    // Stage 1: XOR decrypt
    xor_decrypt(flag_buffer, encrypted_flag_len, xor_key);

    // Stage 2: RC4 decrypt
    uint8_t S[256];
    rc4_init(S, rc4_key, 16);
    rc4_crypt(S, flag_buffer, encrypted_flag_len);

    // NUL-terminate for safe printing
    flag_buffer[encrypted_flag_len] = '\0';

    // Display result (use a width-limited print to avoid UB)
    printf("\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("║ ");
    print_encrypted(str_flag_label, sizeof(str_flag_label), 0x55);
    printf("%-33s ║\n", (char *)flag_buffer);
    printf("╚═══════════════════════════════════════╝\n");
    printf("\n");

    print_encrypted(str_congrats, sizeof(str_congrats), 0x55);
    printf("\n");

    free(flag_buffer);
}

int main() {
    vault_logic();
    return 0;
}

/*
 * LEARNING OBJECTIVES: (unchanged)
 * 1. Custom Packer: Manual unpacking, OEP finding, IAT reconstruction
 * 2. Multi-Stage Crypto: XOR → RC4 decryption
 * 3. Complex Key Derivation: HWID + username + timestamp
 * 4. Anti-VM: Registry-based detection
 * 5. Anti-Debug: Timing checks (RDTSC)
 * 6. Encrypted Strings: XOR string obfuscation
 *
 * FLAG GENERATION:
 * Session ID: FIXED_TIMESTAMP ^ SESSION_XOR = 0x65432100 ^ 0x12345678 = 0x77777778
 * Flag: SBC{d3crypt3d_53ss10n_77777778_v2}
 */


