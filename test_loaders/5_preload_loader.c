/*
 * Test Case 5: LD_PRELOAD Hijacking Loader
 * 
 * This loader demonstrates library preloading attack:
 * 1. Create malicious shared library with payload
 * 2. Use LD_PRELOAD to inject into legitimate process
 * 3. Execute hooked function containing shellcode
 * 
 * Detection: Should trigger "LD_PRELOAD" environment variable alerts
 * Memory Dump: Payload should be captured from preloaded library memory
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

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

// Meterpreter stage signatures
static unsigned char meterpreter_magic[] = {
    0x4d, 0x53, 0x53, 0x46,  // MSSF (Metasploit Stream Socket Format)
};

static char meterpreter_urls[] = 
    "http://127.0.0.1:8080/stage"
    "\x00"
    "https://malicious.example.com/payload"
    "\x00";

static char meterpreter_config_block[] =
    "PAYLOAD: windows/meterpreter/reverse_tcp\x00"
    "LHOST: 192.168.1.100\x00"
    "LPORT: 4444\x00"
    "ARCH: x64\x00"
    "ENCODING: x64/xor\x00";

void run_payload() {
    printf("[PRELOAD] Malicious library loaded!\n");
    printf("[PRELOAD] Payload embedded in library code section\n");
    printf("[PRELOAD] Meterpreter configuration loaded at: %p\n", meterpreter_config_block);
    printf("[PRELOAD] Stage URLs at: %p\n", meterpreter_urls);
    
    // Keep references to payload in memory
    volatile unsigned char *p = payload;
    volatile unsigned char *m = meterpreter_magic;
    (void)p;
    (void)m;
}

// Hook common function (constructor runs before main)
__attribute__((constructor))
void preload_init() {
    printf("[PRELOAD] ===============================================\n");
    printf("[PRELOAD] Malicious library constructor executing...\n");
    printf("[PRELOAD] This simulates LD_PRELOAD hijacking attack\n");
    printf("[PRELOAD] ===============================================\n");
    
    run_payload();
    
    printf("[PRELOAD] Sleeping 30 seconds to allow memory dump...\n");
    printf("[!] Monitor should detect: LD_PRELOAD environment variable\n");
    printf("[!] Memory dump should contain shellcode + meterpreter config\n");
    
    sleep(30);
    
    printf("[PRELOAD] Constructor complete\n");
}

int main(int argc, char **argv) {
    printf("[*] Test Case 5: LD_PRELOAD Hijacking\n");
    printf("[*] Legitimate victim process - should have been hijacked by preload\n");
    
    // This process thinks it's legitimate
    printf("[+] Running as legitimate process: PID %d\n", getpid());
    printf("[+] But we have malicious library loaded via LD_PRELOAD\n");
    
    // Display environment
    extern char **environ;
    for (char **env = environ; *env; env++) {
        if (strncmp(*env, "LD_", 3) == 0) {
            printf("[ENV] %s\n", *env);
        }
    }
    
    printf("[+] Waiting for memory dump analysis...\n");
    sleep(5);
    
    printf("[*] Victim process exiting\n");
    return 0;
}
