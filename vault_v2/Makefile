# ============================================================================
# Vault Challenge v2 - Build System
# ============================================================================

# Compiler settings
CC = i686-w64-mingw32-gcc
CFLAGS = -O2 -s -static -m32
NASM = nasm
PYTHON = python3

# Directories
SRC_DIR = src
BIN_DIR = bin
SOL_DIR = solution

# Targets
UNPACKED = $(BIN_DIR)/vault_v2_unpacked.exe
PACKED = $(BIN_DIR)/vault_v2.exe
STUB = $(BIN_DIR)/stub.bin

# ============================================================================
# Main Targets
# ============================================================================

.PHONY: all clean test generate-flag help

all: $(PACKED)
	@echo ""
	@echo "===================================="
	@echo "Build complete!"
	@echo "===================================="
	@echo "Unpacked: $(UNPACKED)"
	@echo "Packed:   $(PACKED)"
	@echo ""

# Step 1: Generate encrypted flag bytes
generate-flag:
	@echo "[*] Generating encrypted flag..."
	$(PYTHON) $(SRC_DIR)/packer.py --generate-flag

# Step 2: Compile unpacked binary
$(UNPACKED): $(SRC_DIR)/vault_v2.c
	@echo "[*] Compiling unpacked binary..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@
	@echo "[+] Unpacked binary created: $@"

# Step 3: Assemble packer stub (auto-rebuild if missing or changed)
$(STUB): $(SRC_DIR)/packer_stub.asm
	@echo "[*] Assembling packer stub..."
	@mkdir -p $(BIN_DIR)
	$(NASM) -f bin $< -o $@
	@echo "[+] Stub created: $@"

# Step 4: Pack the binary (depends on unpacked binary AND stub)
$(PACKED): $(UNPACKED) $(STUB) $(SRC_DIR)/packer.py
	@echo "[*] Packing binary..."
	$(PYTHON) $(SRC_DIR)/packer.py $(UNPACKED) $@ $(STUB)
	@echo "[+] Packed binary created: $@"

# ============================================================================
# Testing
# ============================================================================

test: $(PACKED)
	@echo ""
	@echo "[*] Testing packed binary..."
	@echo "===================================="
	wine $(PACKED) || echo "[!] Binary requires Windows or Wine"
	@echo "===================================="

test-unpacked: $(UNPACKED)
	@echo ""
	@echo "[*] Testing unpacked binary..."
	@echo "===================================="
	wine $(UNPACKED) || echo "[!] Binary requires Windows or Wine"
	@echo "===================================="

# ============================================================================
# File Analysis
# ============================================================================

entropy: $(PACKED)
	@echo "[*] Analyzing entropy..."
	$(PYTHON) $(SOL_DIR)/entropy_analyzer.py $(PACKED)

strings: $(PACKED)
	@echo "[*] Extracting strings..."
	strings $(PACKED) | head -30

file-info: $(PACKED)
	@echo "[*] File information..."
	file $(PACKED)
	@ls -lh $(PACKED)

checksums: $(PACKED) $(UNPACKED)
	@echo "[*] Generating checksums..."
	@cd $(BIN_DIR) && sha256sum vault_v2*.exe > checksums.txt
	@cd $(BIN_DIR) && md5sum vault_v2*.exe >> checksums.txt
	@echo "[+] Checksums saved to $(BIN_DIR)/checksums.txt"
	@cat $(BIN_DIR)/checksums.txt

# ============================================================================
# Cleanup
# ============================================================================

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f $(BIN_DIR)/*.exe
	rm -f $(BIN_DIR)/checksums.txt
	rm -f $(BIN_DIR)/*.png
	@echo "[+] Cleanup complete"
	@echo "[*] Note: stub.bin preserved (needed for packing)"

clean-all: clean
	@echo "[*] Removing stub and bin directory..."
	rm -f $(STUB)
	rm -rf $(BIN_DIR)

# ============================================================================
# Help
# ============================================================================

help:
	@echo "Vault Challenge v2 - Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  make                  - Build everything (default)"
	@echo "  make generate-flag    - Generate encrypted flag bytes"
	@echo "  make test             - Test packed binary"
	@echo "  make test-unpacked    - Test unpacked binary"
	@echo "  make entropy          - Analyze entropy"
	@echo "  make strings          - Extract strings"
	@echo "  make file-info        - Show file information"
	@echo "  make checksums        - Generate SHA256/MD5 checksums"
	@echo "  make clean            - Remove build artifacts (keeps stub.bin)"
	@echo "  make clean-all        - Remove everything including stub.bin"
	@echo "  make help             - Show this help"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - MinGW cross-compiler: i686-w64-mingw32-gcc"
	@echo "  - NASM assembler"
	@echo "  - Python 3.8+"
	@echo "  - Wine (for testing on Linux)"
	@echo ""

# ============================================================================
# Dependencies
# ============================================================================

$(SRC_DIR)/vault_v2.c: | check-compiler
$(SRC_DIR)/packer_stub.asm: | check-nasm
$(SRC_DIR)/packer.py: | check-python

.PHONY: check-compiler check-nasm check-python

check-compiler:
	@which $(CC) > /dev/null || (echo "[!] Error: $(CC) not found. Install mingw-w64" && exit 1)

check-nasm:
	@which $(NASM) > /dev/null || (echo "[!] Error: $(NASM) not found. Install nasm" && exit 1)

check-python:
	@which $(PYTHON) > /dev/null || (echo "[!] Error: $(PYTHON) not found. Install Python 3" && exit 1)
