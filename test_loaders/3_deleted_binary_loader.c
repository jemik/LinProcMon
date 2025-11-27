/*
 * Test Case 3: Deleted Binary Replacement Loader
 * 
 * This loader demonstrates binary replacement technique:
 * 1. Copy itself to /tmp with payload embedded
 * 2. Execute the copy
 * 3. Delete the binary while it's running
 * 4. Process continues running from (deleted) file
 * 
 * Detection: Should trigger "running from deleted file" alerts
 * Memory Dump: Should capture payload from process running from (deleted) binary
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

// Meterpreter-like payload embedded in binary
unsigned char embedded_payload[] = 
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

// Meterpreter signatures
char meterpreter_marker[] = "METERPRETER_PAYLOAD_MARKER_12345";
char stage_signature[] = "windows/meterpreter/reverse_tcp";

void child_process() {
    printf("[CHILD] Running as child process PID: %d\n", getpid());
    
    // Self-delete by removing our own binary
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
        printf("[CHILD] Deleting own binary: %s\n", exe_path);
        
        if (unlink(exe_path) == 0) {
            printf("[CHILD] Successfully deleted binary - now running from (deleted)\n");
        } else {
            perror("[CHILD] unlink failed");
        }
    }
    
    // Allocate memory and copy payload
    void *payload_mem = malloc(4096);
    if (payload_mem) {
        memcpy(payload_mem, embedded_payload, sizeof(embedded_payload));
        memcpy(payload_mem + 512, meterpreter_marker, sizeof(meterpreter_marker));
        memcpy(payload_mem + 1024, stage_signature, sizeof(stage_signature));
        printf("[CHILD] Payload loaded in memory at: %p\n", payload_mem);
    }
    
    printf("[CHILD] Sleeping 30 seconds to allow memory dump...\n");
    printf("[!] Monitor should detect: process running from (deleted) file\n");
    printf("[!] Memory dump should contain embedded payload + meterpreter markers\n");
    
    sleep(30);
    
    if (payload_mem) free(payload_mem);
    printf("[CHILD] Test complete\n");
    exit(0);
}

int main(int argc, char **argv) {
    // Check if we're the child (re-executed) process
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        child_process();
        return 0;
    }
    
    printf("[*] Test Case 3: Deleted Binary Replacement\n");
    printf("[*] This simulates malware replacing its binary and running from (deleted)\n");
    
    // Read our own binary
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        perror("readlink");
        return 1;
    }
    exe_path[len] = '\0';
    
    // Copy to /tmp
    char tmp_path[] = "/tmp/legitimate_update_XXXXXX";
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1) {
        perror("mkstemp");
        return 1;
    }
    
    printf("[+] Created temporary binary: %s\n", tmp_path);
    
    // Copy binary content
    int src_fd = open(exe_path, O_RDONLY);
    if (src_fd == -1) {
        perror("open source");
        close(tmp_fd);
        unlink(tmp_path);
        return 1;
    }
    
    char buf[4096];
    ssize_t bytes;
    while ((bytes = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(tmp_fd, buf, bytes) != bytes) {
            perror("write");
            close(src_fd);
            close(tmp_fd);
            unlink(tmp_path);
            return 1;
        }
    }
    
    close(src_fd);
    close(tmp_fd);
    
    // Make executable
    if (chmod(tmp_path, 0755) == -1) {
        perror("chmod");
        unlink(tmp_path);
        return 1;
    }
    
    printf("[+] Copied binary to temp location\n");
    printf("[+] Executing copy with --child flag...\n");
    
    // Execute the copy
    char *args[] = { tmp_path, "--child", NULL };
    char *env[] = { NULL };
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child executes the copied binary
        execve(tmp_path, args, env);
        perror("execve");
        exit(1);
    } else if (pid > 0) {
        printf("[+] Spawned child process: %d\n", pid);
        printf("[+] Waiting for child to complete test...\n");
        
        int status;
        waitpid(pid, &status, 0);
        
        // Cleanup (child already deleted it, but try anyway)
        unlink(tmp_path);
        
        printf("[*] Parent process complete\n");
    } else {
        perror("fork");
        unlink(tmp_path);
        return 1;
    }
    
    return 0;
}
