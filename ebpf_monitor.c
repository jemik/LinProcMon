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

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Event types
#define EVENT_MMAP_EXEC 1
#define EVENT_MPROTECT_EXEC 2
#define EVENT_MEMFD_CREATE 3
#define EVENT_EXECVE 4

// Event structure sent to userspace
struct exec_event {
    __u32 pid;
    __u32 tid;
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 flags;
    __u8 event_type;
    char comm[16];
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Helper to get current task comm
static __always_inline void get_current_comm(char *comm) {
    struct task_struct *task = (void *)bpf_get_current_task();
    bpf_probe_read_kernel(comm, 16, &task->comm);
}

// Hook: sys_mmap / do_mmap
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u64 addr = ctx->args[0];
    __u64 len = ctx->args[1];
    __u32 prot = (__u32)ctx->args[2];
    __u32 flags = (__u32)ctx->args[3];
    
    // Check if PROT_EXEC (0x4) is set
    if (!(prot & 0x4)) {
        return 0;  // Not executable, ignore
    }
    
    // Allocate event
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = addr;
    e->len = len;
    e->prot = prot;
    e->flags = flags;
    e->event_type = EVENT_MMAP_EXEC;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: sys_mprotect
SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u64 addr = ctx->args[0];
    __u64 len = ctx->args[1];
    __u32 prot = (__u32)ctx->args[2];
    
    // Check if PROT_EXEC (0x4) is being added
    if (!(prot & 0x4)) {
        return 0;
    }
    
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = addr;
    e->len = len;
    e->prot = prot;
    e->flags = 0;
    e->event_type = EVENT_MPROTECT_EXEC;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
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
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = 0;
    e->len = 0;
    e->prot = 0;
    e->flags = (__u32)ctx->args[1];  // MFD_* flags
    e->event_type = EVENT_MEMFD_CREATE;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
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
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->addr = ctx->args[0];  // filename pointer
    e->len = 0;
    e->prot = 0;
    e->flags = 0;
    e->event_type = EVENT_EXECVE;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
