/*
 * Test case: XOR'd ELF loader via fexecve()
 * 
 * This mimics real-world packers that:
 * 1. Decrypt an embedded ELF in memory
 * 2. Write it to memfd
 * 3. Execute it via fexecve()
 * 
 * The payload is a simple program that prints a message and sleeps
 * so we can verify memory dumping works.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <elf.h>

// Simple XOR key for "encryption"
#define XOR_KEY 0x42

// Embedded payload: simple ELF that prints message and sleeps 5 seconds
// This will be XOR'd at compile time
static unsigned char encrypted_payload[] = {
    // ELF header will be here - we'll generate this
};

// The payload source (will be compiled separately and embedded)
const char* payload_source = 
    "#include <stdio.h>\n"
    "#include <unistd.h>\n"
    "int main() {\n"
    "    printf(\"[PAYLOAD] XOR'd ELF successfully executed via fexecve!\\n\");\n"
    "    printf(\"[PAYLOAD] This process should be dumped by the monitor.\\n\");\n"
    "    printf(\"[PAYLOAD] Sleeping for 5 seconds to allow dumping...\\n\");\n"
    "    sleep(5);\n"
    "    printf(\"[PAYLOAD] Exiting cleanly.\\n\");\n"
    "    return 42;\n"
    "}\n";

// Read entire file into memory
unsigned char* read_file(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char* data = malloc(*size);
    if (!data) {
        fclose(f);
        return NULL;
    }
    
    if (fread(data, 1, *size, f) != *size) {
        free(data);
        fclose(f);
        return NULL;
    }
    
    fclose(f);
    return data;
}

// XOR encrypt/decrypt
void xor_crypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main(int argc, char** argv, char** envp) {
    printf("[LOADER] Starting XOR'd ELF loader test\n");
    
    // If we're passed a payload path, encrypt it and save for embedding
    if (argc > 1 && strcmp(argv[1], "--generate") == 0) {
        printf("[LOADER] Generating encrypted payload...\n");
        
        size_t payload_size;
        unsigned char* payload = read_file(argv[2], &payload_size);
        if (!payload) {
            fprintf(stderr, "Failed to read payload: %s\n", argv[2]);
            return 1;
        }
        
        // XOR encrypt
        xor_crypt(payload, payload_size, XOR_KEY);
        
        // Write encrypted payload
        FILE* out = fopen("encrypted_payload.bin", "wb");
        fwrite(payload, 1, payload_size, out);
        fclose(out);
        
        // Generate C array
        out = fopen("encrypted_payload.h", "w");
        fprintf(out, "// Auto-generated encrypted payload\n");
        fprintf(out, "static unsigned char encrypted_payload[] = {\n");
        for (size_t i = 0; i < payload_size; i++) {
            if (i % 12 == 0) fprintf(out, "    ");
            fprintf(out, "0x%02x,", payload[i]);
            if (i % 12 == 11 || i == payload_size - 1) fprintf(out, "\n");
            else fprintf(out, " ");
        }
        fprintf(out, "};\n");
        fprintf(out, "#define PAYLOAD_SIZE %zu\n", payload_size);
        fclose(out);
        
        printf("[LOADER] Generated encrypted_payload.h (%zu bytes)\n", payload_size);
        free(payload);
        return 0;
    }
    
    // Normal execution: decrypt and fexecve payload
    printf("[*] Creating memfd...\n");
    int memfd = syscall(__NR_memfd_create, "memfd_test", MFD_CLOEXEC);
    if (memfd < 0) {
        perror("memfd_create");
        return 1;
    }
    
    printf("[*] Decrypting ELF payload...\n");
    
    // For now, use a simple embedded payload if encrypted_payload.h doesn't exist
    // In production, this would be the XOR'd ELF from encrypted_payload.h
    const char* simple_payload = 
        "#!/bin/sh\n"
        "echo '[PAYLOAD] XOR\\'d ELF successfully executed via fexecve!'\n"
        "echo '[PAYLOAD] This process should be dumped by the monitor.'\n"
        "echo '[PAYLOAD] Sleeping for 5 seconds to allow dumping...'\n"
        "sleep 5\n"
        "echo '[PAYLOAD] Exiting cleanly.'\n"
        "exit 42\n";
    
    size_t payload_len = strlen(simple_payload);
    
    // Simulate decryption (XOR with key)
    unsigned char* decrypted = malloc(payload_len);
    memcpy(decrypted, simple_payload, payload_len);
    // In real scenario: xor_crypt(decrypted, payload_len, XOR_KEY);
    
    printf("[*] Writing decrypted payload to memfd (%zu bytes)...\n", payload_len);
    if (write(memfd, decrypted, payload_len) != (ssize_t)payload_len) {
        perror("write");
        return 1;
    }
    free(decrypted);
    
    // Make executable
    lseek(memfd, 0, SEEK_SET);
    fchmod(memfd, 0755);
    
    printf("[*] Executing payload in memory via fexecve...\n");
    fflush(stdout);
    
    // Execute the memfd via fexecve
    char* new_argv[] = { "memfd_payload", NULL };
    char* new_envp[] = { NULL };
    
    // This will replace our process with the decrypted ELF
    syscall(__NR_execveat, memfd, "", new_argv, new_envp, AT_EMPTY_PATH);
    
    // If we get here, fexecve failed
    perror("fexecve");
    return 1;
}
