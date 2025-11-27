/*
 * Test Case 2: RWX Memory Injection Loader
 * 
 * This loader demonstrates code injection via RWX memory:
 * 1. Allocate memory with RWX permissions (mmap)
 * 2. Write shellcode directly to RWX region
 * 3. Keep process alive with payload in memory
 * 
 * Detection: Should trigger "RWX regions" alerts
 * Memory Dump: Payload should be captured from RWX anonymous mapping
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

// Meterpreter reverse shell placeholder
// Using simple shellcode for testing - will be replaced with meterpreter
unsigned char payload[] = 
    "\x48\x31\xd2"                          // xor rdx, rdx
    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  // mov rbx, '/bin/sh'
    "\x48\xc1\xeb\x08"                      // shr rbx, 8
    "\x53"                                  // push rbx
    "\x48\x89\xe7"                          // mov rdi, rsp
    "\x50"                                  // push rax
    "\x57"                                  // push rdi
    "\x48\x89\xe6"                          // mov rsi, rsp
    "\xb0\x3b"                              // mov al, 59 (execve)
    "\x0f\x05"                              // syscall
    "\xc3";                                 // ret

unsigned int payload_len = sizeof(payload) - 1;

// Linux meterpreter signature patterns for YARA detection testing
unsigned char meterpreter_signature1[] = "linux/x64/meterpreter";
unsigned char meterpreter_signature2[] = "core_loadlib";
unsigned char meterpreter_signature3[] = "\x7f\x45\x4c\x46\x02\x01\x01";  // ELF x64 signature

int main(int argc, char **argv) {
    printf("[*] Test Case 2: RWX Memory Injection\n");
    printf("[*] This simulates malware injecting code into RWX memory\n");
    
    // Allocate RWX memory - highly suspicious!
    void *rwx_mem = mmap(NULL, 4096, 
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (rwx_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("[+] Allocated RWX memory at: %p\n", rwx_mem);
    
    // Write payload to RWX region
    memcpy(rwx_mem, payload, payload_len);
    printf("[+] Copied %d bytes of shellcode to RWX region\n", payload_len);
    
    // Add meterpreter signatures for YARA detection
    memcpy(rwx_mem + 256, meterpreter_signature1, sizeof(meterpreter_signature1));
    memcpy(rwx_mem + 512, meterpreter_signature2, sizeof(meterpreter_signature2));
    memcpy(rwx_mem + 768, meterpreter_signature3, sizeof(meterpreter_signature3));
    
    printf("[+] Added meterpreter signature patterns for YARA detection\n");
    printf("[+] Sleeping 30 seconds to allow memory dump...\n");
    printf("[!] Monitor should detect: RWX memory region\n");
    printf("[!] Memory dump should contain shellcode + meterpreter signatures\n");
    printf("[!] YARA should match meterpreter patterns\n");
    
    sleep(30);
    
    // Optional: Execute shellcode (commented for safety)
    // void (*func)() = (void(*)())rwx_mem;
    // func();
    
    printf("[*] Test complete - payload remained in RWX memory without execution\n");
    munmap(rwx_mem, 4096);
    
    return 0;
}
