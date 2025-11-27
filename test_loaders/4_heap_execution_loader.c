/*
 * Test Case 4: Heap Execution Loader
 * 
 * This loader demonstrates heap-based shellcode execution:
 * 1. Allocate memory on heap (malloc)
 * 2. Copy shellcode to heap
 * 3. Change heap memory protection to executable
 * 4. Keep process alive with executable heap
 * 
 * Detection: Should trigger "Executable heap" alerts
 * Memory Dump: Payload should be captured from executable heap region
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

// Meterpreter reverse shell placeholder
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

// Linux meterpreter stage markers
unsigned char metsrv_marker[] = "meterpreter_x64_linux\x00";
unsigned char core_lib[] = "core_loadlib\x00";
unsigned char socket_marker[] = "socket_connect\x00";
unsigned char meterpreter_config[] = {
    0x00, 0x01, 0x00, 0x02,  // Version
    0x7f, 0x00, 0x00, 0x01,  // IP: 127.0.0.1
    0x11, 0x5c,              // Port: 4444
};

int main(int argc, char **argv) {
    printf("[*] Test Case 4: Heap Execution\n");
    printf("[*] This simulates malware executing shellcode from executable heap\n");
    
    // Allocate large heap buffer
    size_t heap_size = 8192;
    void *heap_mem = malloc(heap_size);
    
    if (!heap_mem) {
        perror("malloc");
        return 1;
    }
    
    printf("[+] Allocated heap memory at: %p (size: %zu bytes)\n", heap_mem, heap_size);
    
    // Zero out heap
    memset(heap_mem, 0, heap_size);
    
    // Copy payload to heap
    memcpy(heap_mem, payload, payload_len);
    printf("[+] Copied %d bytes of shellcode to heap\n", payload_len);
    
    // Add meterpreter signatures throughout heap for YARA detection
    memcpy(heap_mem + 256, metsrv_marker, sizeof(metsrv_marker));
    memcpy(heap_mem + 512, core_lib, sizeof(core_lib));
    memcpy(heap_mem + 1024, socket_marker, sizeof(socket_marker));
    memcpy(heap_mem + 2048, meterpreter_config, sizeof(meterpreter_config));
    
    // Add more realistic meterpreter patterns
    char *stage_info = "windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444";
    memcpy(heap_mem + 4096, stage_info, strlen(stage_info));
    
    printf("[+] Embedded meterpreter signatures and configuration\n");
    
    // Make heap executable - this is highly suspicious!
    // Align to page boundary
    uintptr_t page_start = ((uintptr_t)heap_mem) & ~(sysconf(_SC_PAGESIZE) - 1);
    size_t page_size = heap_size + ((uintptr_t)heap_mem - page_start);
    
    if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        printf("[+] Changed heap to RWX - HIGHLY SUSPICIOUS!\n");
    } else {
        perror("mprotect");
        // Continue anyway - the heap still contains payload
    }
    
    printf("[+] Sleeping 30 seconds to allow memory dump...\n");
    printf("[!] Monitor should detect: Executable heap\n");
    printf("[!] Memory dump should contain shellcode + meterpreter markers\n");
    printf("[!] YARA should match multiple meterpreter signatures\n");
    
    sleep(30);
    
    // Optional: Execute shellcode (commented for safety)
    // void (*func)() = (void(*)())heap_mem;
    // func();
    
    printf("[*] Test complete - payload remained in heap without execution\n");
    free(heap_mem);
    
    return 0;
}
