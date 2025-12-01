#!/bin/bash
#
# Build and test fexecve loader
#

set -e

echo "======================================="
echo " Building fexecve Test Case"
echo "======================================="

# Build the payload
echo "[1/3] Compiling payload binary..."
gcc -o test_loaders/fexecve_payload test_loaders/fexecve_payload.c -static
echo "      [✓] Payload binary: test_loaders/fexecve_payload"
echo "      Size: $(stat -c%s test_loaders/fexecve_payload) bytes"

# Create XOR'd version with embedded payload
echo "[2/3] Creating XOR'd loader with embedded payload..."
xxd -i test_loaders/fexecve_payload > test_loaders/payload_embedded.h

# Build the loader with embedded encrypted payload
cat > test_loaders/test_fexecve_final.c << 'LOADER_EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>

#define XOR_KEY 0x42

// Include the embedded payload (as C array from xxd)
#include "payload_embedded.h"

void xor_decrypt(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

int main(int argc, char** argv, char** envp) {
    printf("[LOADER] XOR'd ELF Loader Test\n");
    printf("[*] Creating memfd...\n");
    
    int memfd = syscall(__NR_memfd_create, "memfd_xor_payload", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        return 1;
    }
    
    printf("[*] Decrypting embedded ELF (%u bytes)...\n", test_loaders_fexecve_payload_len);
    
    // Make a copy for decryption
    unsigned char* decrypted = malloc(test_loaders_fexecve_payload_len);
    memcpy(decrypted, test_loaders_fexecve_payload, test_loaders_fexecve_payload_len);
    
    // XOR decrypt
    xor_decrypt(decrypted, test_loaders_fexecve_payload_len);
    
    printf("[*] Writing decrypted ELF to memfd...\n");
    if (write(memfd, decrypted, test_loaders_fexecve_payload_len) != (ssize_t)test_loaders_fexecve_payload_len) {
        perror("write");
        return 1;
    }
    free(decrypted);
    
    printf("[*] Executing ELF via fexecve...\n");
    fflush(stdout);
    
    // Execute the memfd
    char* new_argv[] = { "xor_payload", NULL };
    syscall(__NR_execveat, memfd, "", new_argv, envp, AT_EMPTY_PATH);
    
    perror("fexecve failed");
    return 1;
}
LOADER_EOF

# XOR encrypt the payload in the header file
python3 << 'PYTHON_EOF'
import sys

# Read the header file
with open('test_loaders/payload_embedded.h', 'r') as f:
    content = f.read()

# Extract the array data and encrypt it
lines = content.split('\n')
output_lines = []
xor_key = 0x42

for line in lines:
    if line.strip().startswith('0x'):
        # This is a data line, XOR each byte
        bytes_str = line.strip().rstrip(',').split(',')
        encrypted_bytes = []
        for b in bytes_str:
            b = b.strip()
            if b.startswith('0x'):
                val = int(b, 16)
                encrypted_val = val ^ xor_key
                encrypted_bytes.append(f'0x{encrypted_val:02x}')
        output_lines.append('  ' + ', '.join(encrypted_bytes) + ',')
    else:
        output_lines.append(line)

# Write back
with open('test_loaders/payload_embedded.h', 'w') as f:
    f.write('\n'.join(output_lines))

print("[✓] Payload encrypted with XOR key 0x42")
PYTHON_EOF

gcc -o test_loaders/test_fexecve_final test_loaders/test_fexecve_final.c
echo "      [✓] Loader binary: test_loaders/test_fexecve_final"
echo "      Size: $(stat -c%s test_loaders/test_fexecve_final) bytes"

echo ""
echo "[3/3] Test run (non-monitored)..."
./test_loaders/test_fexecve_final
exit_code=$?

echo ""
echo "======================================="
echo " Build Complete"
echo "======================================="
echo "Test binary: test_loaders/test_fexecve_final"
echo "Exit code: $exit_code (expected 42)"
echo ""
echo "To test with monitoring:"
echo "  sudo ./run_integrated.sh test_loaders/test_fexecve_final"
echo ""
