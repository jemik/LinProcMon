/*
 * test_memload.c
 * Test binary that loads code into memory and executes it
 * This simulates malware behavior: RWX memory allocation + execution
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Shellcode that prints "Hello from memory!" and exits
// x86_64 assembly code
unsigned char shellcode[] = {
    // write(1, "Hello from memory!\n", 19)
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (sys_write)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (stdout)
    0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x10] (message)
    0x48, 0xc7, 0xc2, 0x13, 0x00, 0x00, 0x00,  // mov rdx, 19 (length)
    0x0f, 0x05,                                // syscall
    // exit(0)
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60 (sys_exit)
    0x48, 0x31, 0xff,                          // xor rdi, rdi (exit code 0)
    0x0f, 0x05,                                // syscall
    // Message string
    'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ',
    'm', 'e', 'm', 'o', 'r', 'y', '!', '\n'
};

int main() {
    printf("[TEST] Starting memory loader test...\n");
    printf("[TEST] This will allocate RWX memory and execute code\n");
    sleep(1);
    
    // Allocate RWX memory (READ + WRITE + EXEC)
    // This should trigger alerts in the monitoring tool
    printf("[TEST] Allocating RWX memory region...\n");
    void *mem = mmap(NULL, 4096, 
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, 
                     -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("[TEST] Memory allocated at: %p\n", mem);
    printf("[TEST] Memory has RWX permissions (should trigger alert!)\n");
    sleep(1);
    
    // Copy shellcode to the executable memory
    printf("[TEST] Copying shellcode to memory...\n");
    memcpy(mem, shellcode, sizeof(shellcode));
    
    printf("[TEST] Executing code from memory...\n");
    sleep(1);
    
    // Cast memory to function pointer and execute
    void (*func)() = (void(*)())mem;
    func();
    
    // Cleanup (won't reach here due to exit in shellcode)
    munmap(mem, 4096);
    
    printf("[TEST] Test complete\n");
    return 0;
}
