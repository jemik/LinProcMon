/*
 * Standalone eBPF Syscall Monitor
 * Can run alongside realtime_memdump_tool or independently
 * 
 * Compile: 
 *   clang -O2 -target bpf -c ebpf_monitor.c -o ebpf_monitor.o
 *   gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz
 * 
 * Run:
 *   sudo ./ebpf_standalone [--pid PID]
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

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

static volatile int running = 1;
static int filter_pid = 0;  // 0 = monitor all PIDs
static FILE *pipe_output = NULL;  // Output pipe for IPC

static void sig_handler(int sig) {
    running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) {
        return 0;  // Suppress debug messages
    }
    return vfprintf(stderr, format, args);
}

static const char *event_type_str(uint8_t type) {
    switch (type) {
        case EVENT_MMAP_EXEC: return "mmap(PROT_EXEC)";
        case EVENT_MPROTECT_EXEC: return "mprotect(PROT_EXEC)";
        case EVENT_MEMFD_CREATE: return "memfd_create()";
        case EVENT_EXECVE: return "execve()";
        default: return "unknown";
    }
}

static const char *prot_str(uint32_t prot) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "%c%c%c",
             (prot & 0x1) ? 'R' : '-',
             (prot & 0x2) ? 'W' : '-',
             (prot & 0x4) ? 'X' : '-');
    return buf;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct exec_event *e = data;
    
    if (data_sz < sizeof(*e)) {
        return 0;
    }
    
    // Filter by PID if specified
    if (filter_pid > 0 && e->pid != filter_pid) {
        return 0;
    }
    
    // Get timestamp
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm);
    
    // Print event
    printf("[%s] ", timestamp);
    
    switch (e->event_type) {
        case EVENT_MMAP_EXEC:
            printf("%-20s PID=%-6u TID=%-6u (%s) addr=0x%016lx len=%-8lu prot=%s flags=0x%x\n",
                   event_type_str(e->event_type), e->pid, e->tid, e->comm,
                   e->addr, e->len, prot_str(e->prot), e->flags);
            break;
            
        case EVENT_MPROTECT_EXEC:
            printf("%-20s PID=%-6u TID=%-6u (%s) addr=0x%016lx len=%-8lu prot=%s\n",
                   event_type_str(e->event_type), e->pid, e->tid, e->comm,
                   e->addr, e->len, prot_str(e->prot));
            break;
            
        case EVENT_MEMFD_CREATE:
            printf("%-20s PID=%-6u TID=%-6u (%s) flags=0x%x\n",
                   event_type_str(e->event_type), e->pid, e->tid, e->comm, e->flags);
            break;
            
        case EVENT_EXECVE:
            printf("%-20s PID=%-6u TID=%-6u (%s)\n",
                   event_type_str(e->event_type), e->pid, e->tid, e->comm);
            break;
    }
    
    fflush(stdout);
    
    // Write to pipe if available (for IPC with memory dumper)
    if (pipe_output) {
        fprintf(pipe_output, "%u,%u,%lx,%lu,%u,%u,%u,%s\n",
                e->pid, e->tid, e->addr, e->len, e->prot, e->flags, e->event_type, e->comm);
        fflush(pipe_output);
    }
    
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_map *events_map;
    int err;
    
    // Parse arguments
    const char *pipe_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            filter_pid = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--pipe") == 0 && i + 1 < argc) {
            pipe_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--pid PID] [--pipe PATH]\n", argv[0]);
            printf("\nMonitor dangerous syscalls using eBPF:\n");
            printf("  mmap(PROT_EXEC)      - Allocate executable memory\n");
            printf("  mprotect(PROT_EXEC)  - Make memory executable\n");
            printf("  memfd_create()       - Create anonymous file (fileless execution)\n");
            printf("  execve()             - Execute program\n");
            printf("\nOptions:\n");
            printf("  --pid PID     Only monitor specific PID\n");
            printf("  --pipe PATH   Write events to named pipe for IPC\n");
            return 0;
        }
    }
    
    // DON'T open pipe yet - will open after eBPF attaches
    // This prevents blocking/hanging during startup
    
    // Check root
    if (geteuid() != 0) {
        fprintf(stderr, "[!] This program requires root privileges\n");
        return 1;
    }
    
    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Set libbpf logging
    libbpf_set_print(libbpf_print_fn);
    
    // Load BPF object
    printf("[+] Loading eBPF program: ebpf_monitor.o\n");
    obj = bpf_object__open_file("ebpf_monitor.o", NULL);
    if (!obj) {
        fprintf(stderr, "[!] Failed to open BPF object: %s\n", strerror(errno));
        fprintf(stderr, "[!] Make sure ebpf_monitor.o exists in current directory\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[!] Failed to load BPF object: %d\n", err);
        fprintf(stderr, "[!] Your kernel may not support eBPF or BTF\n");
        goto cleanup;
    }
    
    // Manually attach each tracepoint program
    struct bpf_program *prog;
    struct bpf_link *link;
    int attached_count = 0;
    
    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            err = -errno;
            fprintf(stderr, "[!] Failed to attach program %s: %s\n", 
                    bpf_program__name(prog), strerror(-err));
            // Continue trying to attach other programs
        } else {
            attached_count++;
        }
    }
    
    if (attached_count == 0) {
        fprintf(stderr, "[!] Failed to attach any BPF programs\n");
        err = -1;
        goto cleanup;
    }
    
    printf("[+] Attached %d BPF programs successfully\n", attached_count);
    
    // Get ringbuffer map
    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "[!] Failed to find events map\n");
        err = -1;
        goto cleanup;
    }
    
    // Create ring buffer
    rb = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[!] Failed to create ring buffer: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }
    
    printf("[+] eBPF programs attached successfully\n");
    printf("[+] Monitoring syscalls: mmap, mprotect, memfd_create, execve (enter+exit)\n");
    if (filter_pid > 0) {
        printf("[+] Filtering PID: %d\n", filter_pid);
    }
    printf("[+] Press Ctrl-C to stop\n");
    printf("\n");
    
    // NOW open pipe after eBPF is fully ready
    // At this point, memory dumper should be starting and will open read end
    if (pipe_path) {
        printf("[+] Opening pipe for IPC: %s\n", pipe_path);
        pipe_output = fopen(pipe_path, "w");
        if (!pipe_output) {
            fprintf(stderr, "[!] Failed to open pipe %s: %s\n", pipe_path, strerror(errno));
            fprintf(stderr, "[!] Make sure realtime_memdump_tool is reading from pipe\n");
            err = -1;
            goto cleanup;
        }
        printf("[+] Pipe opened successfully\n");
    }
    
    // Poll for events
    while (running) {
        err = ring_buffer__poll(rb, 100);  // 100ms timeout
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    printf("\n[+] Shutting down...\n");
    err = 0;
    
cleanup:
    if (pipe_output) {
        fclose(pipe_output);
    }
    if (rb) {
        ring_buffer__free(rb);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    
    return err != 0;
}
