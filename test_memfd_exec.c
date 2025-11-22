/*
 * test_memfd_exec.c
 * Test binary that creates anonymous memory file (memfd) and executes it
 * This simulates fileless malware execution technique
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <fcntl.h>

// Simple ELF binary that prints "Loaded from memfd!" (precompiled bytes)
// This is a minimal x86_64 ELF that does: write(1, msg, len) + exit(0)
unsigned char elf_binary[] = {
    // ELF header
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,  // ELF magic + 64-bit
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,  // executable, x86_64
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // entry point
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // program header offset
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,  // sizes
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Program header
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,  // PT_LOAD, R+X
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // vaddr
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,  // paddr
    0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // filesz
    0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // memsz
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // align
    // Code section (at offset 0x78)
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,        // mov rax, 1 (write)
    0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,        // mov rdi, 1 (stdout)
    0x48, 0x8d, 0x35, 0x1b, 0x00, 0x00, 0x00,        // lea rsi, [rip+27] (adjusted offset)
    0x48, 0xc7, 0xc2, 0x13, 0x00, 0x00, 0x00,        // mov rdx, 19
    0x0f, 0x05,                                      // syscall
    // sleep(2) - nanosleep syscall
    0x48, 0xc7, 0xc0, 0x23, 0x00, 0x00, 0x00,        // mov rax, 35 (sys_nanosleep)
    0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00,        // lea rdi, [rip+16] (timespec)
    0x48, 0x31, 0xf6,                                // xor rsi, rsi (NULL)
    0x0f, 0x05,                                      // syscall
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,        // mov rax, 60 (exit)
    0x48, 0x31, 0xff,                                // xor rdi, rdi
    0x0f, 0x05,                                      // syscall
    // Timespec: {tv_sec=2, tv_nsec=0}
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 2 seconds
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0 nanoseconds
    // Message
    'L', 'o', 'a', 'd', 'e', 'd', ' ', 'f', 'r', 'o', 'm', ' ',
    'm', 'e', 'm', 'f', 'd', '!', '\n'
};

int main() {
    printf("[TEST] Starting memfd execution test...\n");
    printf("[TEST] This simulates fileless malware execution\n");
    //sleep(1);
    
    // Create anonymous memory file (memfd_create)
    printf("[TEST] Creating memfd...\n");
    int fd = syscall(SYS_memfd_create, "malware", MFD_CLOEXEC);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }
    
    printf("[TEST] Writing ELF binary to memfd...\n");
    if (write(fd, elf_binary, sizeof(elf_binary)) != sizeof(elf_binary)) {
        perror("write");
        close(fd);
        return 1;
    }
    
    // Seek back to start
    lseek(fd, 0, SEEK_SET);
    
    printf("[TEST] Executing from memfd (should trigger alert!)...\n");
    
    // Give monitoring tool time to set up event listening
    sleep(2);
    
    // Fork so parent can continue monitoring while child executes memfd
    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        close(fd);
        return 1;
    }
    
    if (child == 0) {
        // Child: Execute the memfd (fileless execution)
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        
        char *args[] = {fd_path, NULL};
        char *env[] = {NULL};
        
        execve(fd_path, args, env);
        
        // If execve fails
        perror("execve");
        exit(1);
    }
    
    // Parent: wait for child and then exit
    printf("[TEST] Child PID %d executing memfd...\n", child);
    int status;
    waitpid(child, &status, 0);
    printf("[TEST] Child exited with status %d\n", WEXITSTATUS(status));
    
    // Cleanup
    return 1;
}
