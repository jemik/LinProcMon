/*
 * eBPF Loader for LinProcMon
 * Loads and manages eBPF syscall monitoring programs
 */

#ifndef EBPF_LOADER_H
#define EBPF_LOADER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>

// Event types (must match ebpf_monitor.c)
#define EVENT_MMAP_EXEC 1
#define EVENT_MPROTECT_EXEC 2
#define EVENT_MEMFD_CREATE 3
#define EVENT_EXECVE 4

// Event structure (must match ebpf_monitor.c)
struct exec_event {
    uint32_t pid;
    uint32_t tid;
    uint64_t addr;
    uint64_t len;
    uint32_t prot;
    uint32_t flags;
    uint8_t event_type;
    char comm[16];
};

// Global eBPF state
static struct bpf_object *bpf_obj = NULL;
static struct ring_buffer *rb = NULL;
static pthread_t ebpf_thread;
static volatile int ebpf_running = 0;

// Forward declarations (implemented in realtime_memdump_tool.c)
extern void queue_push(void *queue, pid_t pid, int event_type);
extern void *event_queue_ptr;

// Callback for ringbuffer events
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct exec_event *e = data;
    
    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "[!] Invalid event size: %zu\n", data_sz);
        return 0;
    }
    
    const char *event_name;
    switch (e->event_type) {
        case EVENT_MMAP_EXEC:
            event_name = "mmap(PROT_EXEC)";
            printf("[eBPF] PID %u (%s): %s addr=0x%lx len=%lu prot=0x%x flags=0x%x\n",
                   e->pid, e->comm, event_name, e->addr, e->len, e->prot, e->flags);
            break;
        case EVENT_MPROTECT_EXEC:
            event_name = "mprotect(PROT_EXEC)";
            printf("[eBPF] PID %u (%s): %s addr=0x%lx len=%lu prot=0x%x\n",
                   e->pid, e->comm, event_name, e->addr, e->len, e->prot);
            break;
        case EVENT_MEMFD_CREATE:
            event_name = "memfd_create()";
            printf("[eBPF] PID %u (%s): %s flags=0x%x\n",
                   e->pid, e->comm, event_name, e->flags);
            break;
        case EVENT_EXECVE:
            event_name = "execve()";
            printf("[eBPF] PID %u (%s): %s\n", e->pid, e->comm, event_name);
            break;
        default:
            event_name = "unknown";
            break;
    }
    
    // Queue this PID for scanning
    if (event_queue_ptr) {
        queue_push(event_queue_ptr, e->pid, e->event_type);
    }
    
    return 0;
}

// eBPF polling thread
static void *ebpf_poll_thread(void *arg) {
    printf("[+] eBPF polling thread started\n");
    
    while (ebpf_running) {
        int err = ring_buffer__poll(rb, 100);  // 100ms timeout
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("[+] eBPF polling thread stopped\n");
    return NULL;
}

// Load and attach eBPF programs
static int load_ebpf_monitor(const char *ebpf_obj_path) {
    int err;
    
    printf("[+] Loading eBPF object: %s\n", ebpf_obj_path);
    
    // Open and load BPF object
    bpf_obj = bpf_object__open(ebpf_obj_path);
    if (!bpf_obj) {
        fprintf(stderr, "[!] Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }
    
    err = bpf_object__load(bpf_obj);
    if (err) {
        fprintf(stderr, "[!] Failed to load BPF object: %d\n", err);
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    // Attach all programs
    err = bpf_object__attach_skeleton(bpf_obj);
    if (err) {
        fprintf(stderr, "[!] Failed to attach BPF programs: %d\n", err);
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    // Get ringbuffer map
    struct bpf_map *events_map = bpf_object__find_map_by_name(bpf_obj, "events");
    if (!events_map) {
        fprintf(stderr, "[!] Failed to find events map\n");
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    // Create ring buffer
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[!] Failed to create ring buffer: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    printf("[+] eBPF programs attached successfully\n");
    printf("[+] Monitoring syscalls: mmap, mprotect, memfd_create, execve\n");
    
    // Start polling thread
    ebpf_running = 1;
    if (pthread_create(&ebpf_thread, NULL, ebpf_poll_thread, NULL) != 0) {
        fprintf(stderr, "[!] Failed to create eBPF polling thread\n");
        ring_buffer__free(rb);
        bpf_object__close(bpf_obj);
        return -1;
    }
    
    return 0;
}

// Cleanup eBPF resources
static void cleanup_ebpf_monitor(void) {
    printf("[+] Cleaning up eBPF monitor\n");
    
    ebpf_running = 0;
    
    if (ebpf_thread) {
        pthread_join(ebpf_thread, NULL);
    }
    
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    
    if (bpf_obj) {
        bpf_object__close(bpf_obj);
        bpf_obj = NULL;
    }
}

#endif // EBPF_LOADER_H
