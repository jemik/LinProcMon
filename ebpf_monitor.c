/*
 * eBPF Syscall Monitor for LinProcMon
 * 
 * Hooks critical syscalls to detect malicious memory operations:
 * - mmap() with PROT_EXEC
 * - mprotect() changing to PROT_EXEC  
 * - memfd_create()
 * - execve() / execveat()
 * 
 * Compile: clang -O2 -target bpf -c ebpf_monitor.c -o ebpf_monitor.o
 */

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Minimal type definitions needed
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

// Event types
#define EVENT_MMAP_EXEC 1
#define EVENT_MPROTECT_EXEC 2
#define EVENT_MEMFD_CREATE 3
#define EVENT_EXECVE 4

// Event structure sent to userspace
struct exec_event {
    u32 pid;
    u32 tid;
    u64 addr;
    u64 len;
    u32 prot;
    u32 flags;
    u8 event_type;
    char comm[16];
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Tracepoint format for syscall entry (simplified)
struct trace_event_raw_sys_enter {
    u64 __unused;
    long id;
    unsigned long args[6];
};

// Helper to get current comm
static __always_inline void get_task_comm(char *buf, int size) {
    bpf_get_current_comm(buf, size);
}

// Hook: sys_mmap / do_mmap
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    u64 addr = ctx->args[0];
    u64 len = ctx->args[1];
    u32 prot = (u32)ctx->args[2];
    u32 flags = (u32)ctx->args[3];
    
    // Check if PROT_EXEC (0x4) is set
    if (!(prot & 0x4)) {
        return 0;  // Not executable, ignore
    }
    
    // Allocate event
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = pid_tgid & 0xFFFFFFFF;
    e->addr = addr;
    e->len = len;
    e->prot = prot;
    e->flags = flags;
    e->event_type = EVENT_MMAP_EXEC;
    get_task_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: sys_mprotect
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    u64 addr = ctx->args[0];
    u64 len = ctx->args[1];
    u32 prot = (u32)ctx->args[2];
    
    // Check if PROT_EXEC (0x4) is being added
    if (!(prot & 0x4)) {
        return 0;
    }
    
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = pid_tgid & 0xFFFFFFFF;
    e->addr = addr;
    e->len = len;
    e->prot = prot;
    e->flags = 0;
    e->event_type = EVENT_MPROTECT_EXEC;
    get_task_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: sys_memfd_create
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = pid_tgid & 0xFFFFFFFF;
    e->addr = 0;
    e->len = 0;
    e->prot = 0;
    e->flags = (u32)ctx->args[1];  // MFD_* flags
    e->event_type = EVENT_MEMFD_CREATE;
    get_task_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: sys_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = pid_tgid & 0xFFFFFFFF;
    e->addr = ctx->args[0];  // filename pointer
    e->len = 0;
    e->prot = 0;
    e->flags = 0;
    e->event_type = EVENT_EXECVE;
    get_task_comm(e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
