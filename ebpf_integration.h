/*
 * eBPF Integration for realtime_memdump_tool
 * Triggers immediate memory scanning when eBPF detects suspicious syscalls
 */

#ifndef EBPF_INTEGRATION_H
#define EBPF_INTEGRATION_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

// Must match ebpf_monitor.c
#define EVENT_MMAP_EXEC 1
#define EVENT_MPROTECT_EXEC 2
#define EVENT_MEMFD_CREATE 3
#define EVENT_EXECVE 4

struct ebpf_event {
    uint32_t pid;
    uint32_t tid;
    uint64_t addr;
    uint64_t len;
    uint32_t prot;
    uint32_t flags;
    uint8_t event_type;
    char comm[16];
};

// Socket path for IPC
#define EBPF_SOCKET_PATH "/tmp/linprocmon_ebpf.sock"

// Global state
static int ebpf_sock = -1;
static pthread_t ebpf_listener_thread;
static volatile int ebpf_running = 0;

// Forward declaration - implemented in realtime_memdump_tool.c
extern void queue_push(void *queue, pid_t pid, int event_type);
extern void *event_queue_ptr;

// eBPF event listener thread
static void *ebpf_listener(void *arg) {
    struct sockaddr_un addr;
    int listen_sock, client_sock;
    struct ebpf_event event;
    
    printf("[eBPF] Listener thread started\n");
    
    // Create socket
    listen_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        fprintf(stderr, "[eBPF] Failed to create socket: %s\n", strerror(errno));
        return NULL;
    }
    
    // Remove old socket file
    unlink(EBPF_SOCKET_PATH);
    
    // Bind
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, EBPF_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[eBPF] Failed to bind socket: %s\n", strerror(errno));
        close(listen_sock);
        return NULL;
    }
    
    // Listen
    if (listen(listen_sock, 5) < 0) {
        fprintf(stderr, "[eBPF] Failed to listen: %s\n", strerror(errno));
        close(listen_sock);
        return NULL;
    }
    
    printf("[eBPF] Waiting for eBPF monitor connection on %s\n", EBPF_SOCKET_PATH);
    
    // Accept connection
    client_sock = accept(listen_sock, NULL, NULL);
    if (client_sock < 0) {
        fprintf(stderr, "[eBPF] Failed to accept connection: %s\n", strerror(errno));
        close(listen_sock);
        return NULL;
    }
    
    printf("[eBPF] eBPF monitor connected!\n");
    ebpf_sock = client_sock;
    
    // Receive events
    while (ebpf_running) {
        ssize_t n = recv(client_sock, &event, sizeof(event), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "[eBPF] Receive error: %s\n", strerror(errno));
            break;
        }
        if (n == 0) {
            printf("[eBPF] Connection closed\n");
            break;
        }
        if (n != sizeof(event)) {
            fprintf(stderr, "[eBPF] Invalid event size: %zd\n", n);
            continue;
        }
        
        // Print event
        const char *event_name;
        switch (event.event_type) {
            case EVENT_MMAP_EXEC:
                event_name = "mmap(PROT_EXEC)";
                printf("[eBPF] %s detected! PID=%u addr=0x%lx len=%lu\n",
                       event_name, event.pid, event.addr, event.len);
                break;
            case EVENT_MPROTECT_EXEC:
                event_name = "mprotect(PROT_EXEC)";
                printf("[eBPF] %s detected! PID=%u addr=0x%lx len=%lu\n",
                       event_name, event.pid, event.addr, event.len);
                break;
            case EVENT_MEMFD_CREATE:
                event_name = "memfd_create()";
                printf("[eBPF] %s detected! PID=%u\n", event_name, event.pid);
                break;
            case EVENT_EXECVE:
                event_name = "execve()";
                printf("[eBPF] %s detected! PID=%u\n", event_name, event.pid);
                break;
            default:
                event_name = "unknown";
                break;
        }
        
        // Queue PID for immediate scanning
        if (event_queue_ptr) {
            queue_push(event_queue_ptr, event.pid, event.event_type);
            printf("[eBPF] Queued PID %u for immediate scanning\n", event.pid);
        }
    }
    
    close(client_sock);
    close(listen_sock);
    unlink(EBPF_SOCKET_PATH);
    
    printf("[eBPF] Listener thread stopped\n");
    return NULL;
}

// Start eBPF integration
static int start_ebpf_integration(void) {
    ebpf_running = 1;
    
    if (pthread_create(&ebpf_listener_thread, NULL, ebpf_listener, NULL) != 0) {
        fprintf(stderr, "[eBPF] Failed to create listener thread\n");
        return -1;
    }
    
    return 0;
}

// Stop eBPF integration
static void stop_ebpf_integration(void) {
    ebpf_running = 0;
    
    if (ebpf_listener_thread) {
        pthread_cancel(ebpf_listener_thread);
        pthread_join(ebpf_listener_thread, NULL);
    }
    
    if (ebpf_sock >= 0) {
        close(ebpf_sock);
        ebpf_sock = -1;
    }
    
    unlink(EBPF_SOCKET_PATH);
}

#endif // EBPF_INTEGRATION_H
