// realtime_memdump_tool.c
// Linux C tool for real-time process monitoring + memory injection detection + dumping + YARA scan + env check

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#include <ctype.h>
#include <sched.h>  // For sched_yield()

#include <stddef.h> // For NULL

#ifdef ENABLE_YARA
#include <yara.h>
#endif

#define MAX_LINE 4096
#define MAX_WORKER_THREADS 8
#define EVENT_QUEUE_SIZE 1024

// Note: No delay for process initialization - prioritize event processing speed
// Short-lived processes may race (exit before we read them) - this is acceptable

volatile sig_atomic_t running = 1;  // Main loop control flag
int nl_sock;
const char* yara_rules_path = NULL;
int continuous_scan = 0;  // Flag for continuous monitoring of all processes
int quiet_mode = 0;  // Suppress non-critical messages
int mem_dump = 0;  // Enable memory dumping to disk
int full_dump = 0;  // Enable full process memory dump (all regions)
int sandbox_mode = 0;  // Sandbox mode: monitor specific process tree
pid_t sandbox_root_pid = 0;  // Root PID for sandbox monitoring
char* sandbox_binary = NULL;  // Binary to execute in sandbox mode
char** sandbox_args = NULL;  // Arguments for sandbox binary
int sandbox_args_count = 0;  // Number of arguments
int sandbox_timeout = 0;  // Sandbox timeout in seconds (0 = wait for process exit)
time_t sandbox_start_time = 0;  // When sandbox started
int sandbox_rescan_interval = 2;  // Rescan sandbox processes every N seconds (for unpacking detection)
time_t last_sandbox_rescan = 0;  // Last time we rescanned sandbox processes
int max_dumps = 0;  // Maximum number of processes to dump (0 = unlimited)
int dumps_performed = 0;  // Counter for dumps performed
char sandbox_termination_status[32] = "running";  // Termination status: running, completed, timeout, crashed
int sandbox_exit_code = -1;  // Exit code or signal number
char* ebpf_pipe_path = NULL;  // Path to named pipe for eBPF events
pthread_t ebpf_pipe_thread;
int sandbox_tool_crashed = 0;  // Set to 1 if tool crashes due to sample
char sandbox_crash_reason[128] = "";  // Reason for tool crash

// Sandbox reporting infrastructure
char sandbox_report_dir[512] = "";  // Base directory for sandbox output
char sandbox_dropped_dir[512] = "";  // Directory for dropped files
char sandbox_memdump_dir[512] = "";  // Directory for memory dumps
char sample_sha1[41] = "";  // SHA-1 of sample being analyzed
FILE *sandbox_json_report = NULL;  // JSON report file
pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
int json_first_item = 1;  // Track if we need comma before next JSON item
int report_writer_busy = 0;  // Flag to prevent re-entrant report writing
int alerts_written = 0;  // Counter for alerts written to file
#define MAX_ALERTS_TO_FILE 1000  // Maximum alerts to write to temp file

// Alert deduplication to prevent processing same region multiple times
#define ALERT_CACHE_SIZE 2048
typedef struct {
    pid_t pid;
    unsigned long start;
    unsigned long end;
    char reason[64];
} alert_key_t;

static alert_key_t alert_cache[ALERT_CACHE_SIZE];
static int alert_cache_count = 0;
pthread_mutex_t alert_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Process tracking for sandbox
#define MAX_SANDBOX_PROCESSES 256
typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[256];
    char path[512];
    char cmdline[1024];
    char creation_method[32];
    time_t start_time;
    int active;
} sandbox_process_t;

sandbox_process_t sandbox_processes[MAX_SANDBOX_PROCESSES];
int sandbox_process_count = 0;
pthread_mutex_t sandbox_proc_mutex = PTHREAD_MUTEX_INITIALIZER;

// Memory dump tracking - separate from EDR telemetry
#define MAX_MEMDUMP_RECORDS 64
typedef struct {
    pid_t pid;
    char filename[256];
    size_t size;
    char sha1[41];
    time_t timestamp;
    int written_to_disk;  // Track if dump actually succeeded
} memdump_record_t;

memdump_record_t memdump_records[MAX_MEMDUMP_RECORDS];
int memdump_record_count = 0;
pthread_mutex_t memdump_mutex = PTHREAD_MUTEX_INITIALIZER;

// Deduplication for memory dumps using SHA1
typedef struct {
    char sha1[41];
    pid_t pid;
} memdump_hash_t;

#define MAX_MEMDUMP_HASHES 64
memdump_hash_t memdump_hashes[MAX_MEMDUMP_HASHES];
int memdump_hash_count = 0;

// Check if we already dumped this exact content (by SHA1)
static int is_duplicate_memdump(const char *sha1) {
    for (int i = 0; i < memdump_hash_count; i++) {
        if (strcmp(memdump_hashes[i].sha1, sha1) == 0) {
            return 1;
        }
    }
    return 0;
}

// Register a memory dump by SHA1 to prevent duplicates
static void register_memdump(const char *sha1, pid_t pid) {
    if (memdump_hash_count < MAX_MEMDUMP_HASHES) {
        strncpy(memdump_hashes[memdump_hash_count].sha1, sha1, sizeof(memdump_hashes[0].sha1) - 1);
        memdump_hashes[memdump_hash_count].pid = pid;
        memdump_hash_count++;
    }
}

// JSON string escape helper - prevents buffer overflow from special characters
// Returns escaped string in a static buffer (not thread-safe but used with mutex protection)
static const char* json_escape(const char *str) {
    static __thread char escaped[2048];  // Reduced from 8KB to 2KB per thread
    if (!str) return "";
    
    int j = 0;
    int max_len = sizeof(escaped) - 10;
    for (int i = 0; str[i] && j < max_len; i++) {
        unsigned char c = str[i];
        
        // Truncate if getting close to buffer limit
        if (j >= max_len - 6) {
            escaped[j++] = '.';
            escaped[j++] = '.';
            escaped[j++] = '.';
            break;
        }
        
        // Escape special JSON characters
        if (c == '"' || c == '\\') {
            escaped[j++] = '\\';
            escaped[j++] = c;
        } else if (c == '\n') {
            escaped[j++] = '\\';
            escaped[j++] = 'n';
        } else if (c == '\r') {
            escaped[j++] = '\\';
            escaped[j++] = 'r';
        } else if (c == '\t') {
            escaped[j++] = '\\';
            escaped[j++] = 't';
        } else if (c < 32 || c == 127) {
            // Control characters - skip them
            continue;
        } else {
            escaped[j++] = c;
        }
    }
    escaped[j] = '\0';
    return escaped;
}

// Fast PID deduplication using hash set (lock-free reads)
#define WRITTEN_PID_HASH_SIZE 512  // Power of 2 for fast modulo
static volatile int written_pid_hash[WRITTEN_PID_HASH_SIZE] = {0};  // 0 = empty, >0 = PID stored

// Cache for sandbox process checks (reduces /proc filesystem load)
#define SANDBOX_CACHE_SIZE 1024
static struct {
    pid_t pid;
    int is_sandbox;
    time_t timestamp;
} sandbox_cache[SANDBOX_CACHE_SIZE];
static int sandbox_cache_index = 0;
pthread_mutex_t sandbox_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

// Check if a PID is part of the sandbox process tree
int is_sandbox_process(pid_t pid) {
    if (!sandbox_mode) return 0;
    if (pid == sandbox_root_pid) return 1;
    if (pid <= 1 || pid > 4194304) return 0;  // Invalid PID range
    
    // Check cache first
    time_t now = time(NULL);
    pthread_mutex_lock(&sandbox_cache_mutex);
    for (int i = 0; i < SANDBOX_CACHE_SIZE; i++) {
        if (sandbox_cache[i].pid == pid && (now - sandbox_cache[i].timestamp) < 5) {
            int result = sandbox_cache[i].is_sandbox;
            pthread_mutex_unlock(&sandbox_cache_mutex);
            return result;
        }
    }
    pthread_mutex_unlock(&sandbox_cache_mutex);
    
    // Check if already tracked
    pthread_mutex_lock(&sandbox_proc_mutex);
    for (int i = 0; i < sandbox_process_count; i++) {
        if (sandbox_processes[i].active && sandbox_processes[i].pid == pid) {
            pthread_mutex_unlock(&sandbox_proc_mutex);
            goto cache_and_return_true;
        }
    }
    pthread_mutex_unlock(&sandbox_proc_mutex);
    
    // Check parent chain - simplified approach to reduce crashes
    pid_t current = pid;
    for (int depth = 0; depth < 10; depth++) {  // Reduced from 20 to 10
        if (current <= 1 || current > 4194304) break;  // Invalid PID
        
        char stat_path[64];
        int n = snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", current);
        if (n < 0 || n >= sizeof(stat_path)) break;  // Buffer overflow protection
        
        FILE *f = fopen(stat_path, "r");
        if (!f) break;  // Process doesn't exist
        
        char stat_line[256];  // Smaller buffer
        pid_t ppid = -1;
        
        if (fgets(stat_line, sizeof(stat_line), f)) {
            // Format: pid (comm) state ppid ...
            char *p = strrchr(stat_line, ')');
            if (p) {
                int scan_result = sscanf(p + 1, " %*c %d", &ppid);
                if (scan_result != 1) ppid = -1;
            }
        }
        fclose(f);
        
        if (ppid < 0) break;  // Parse error
        if (ppid == sandbox_root_pid) goto cache_and_return_true;
        if (ppid <= 1) break;  // Reached init
        if (ppid == current) break;  // Prevent infinite loop
        
        current = ppid;
    }
    
cache_and_return_false:
    pthread_mutex_lock(&sandbox_cache_mutex);
    sandbox_cache[sandbox_cache_index].pid = pid;
    sandbox_cache[sandbox_cache_index].is_sandbox = 0;
    sandbox_cache[sandbox_cache_index].timestamp = time(NULL);
    sandbox_cache_index = (sandbox_cache_index + 1) % SANDBOX_CACHE_SIZE;
    pthread_mutex_unlock(&sandbox_cache_mutex);
    return 0;
    
cache_and_return_true:
    pthread_mutex_lock(&sandbox_cache_mutex);
    sandbox_cache[sandbox_cache_index].pid = pid;
    sandbox_cache[sandbox_cache_index].is_sandbox = 1;
    sandbox_cache[sandbox_cache_index].timestamp = time(NULL);
    sandbox_cache_index = (sandbox_cache_index + 1) % SANDBOX_CACHE_SIZE;
    pthread_mutex_unlock(&sandbox_cache_mutex);
    return 1;
}

// Check if alert already exists (deduplication)
int is_duplicate_alert(pid_t pid, unsigned long start, unsigned long end, const char *reason) {
    if (!reason) return 1;  // Safety check
    if (pid <= 0) return 1;  // Invalid PID
    
    // Try lock - if busy, allow alert through (better than crash)
    if (pthread_mutex_trylock(&alert_cache_mutex) != 0) {
        return 0;  // Couldn't get lock, allow alert to proceed
    }
    
    for (int i = 0; i < alert_cache_count; i++) {
        if (alert_cache[i].pid == pid &&
            alert_cache[i].start == start &&
            alert_cache[i].end == end &&
            strcmp(alert_cache[i].reason, reason) == 0) {
            pthread_mutex_unlock(&alert_cache_mutex);
            return 1;  // Duplicate found
        }
    }
    
    // Not a duplicate - add to cache
    if (alert_cache_count < ALERT_CACHE_SIZE) {
        alert_cache[alert_cache_count].pid = pid;
        alert_cache[alert_cache_count].start = start;
        alert_cache[alert_cache_count].end = end;
        size_t reason_len = strlen(reason);
        size_t copy_len = reason_len < sizeof(alert_cache[0].reason) - 1 ? reason_len : sizeof(alert_cache[0].reason) - 1;
        memcpy(alert_cache[alert_cache_count].reason, reason, copy_len);
        alert_cache[alert_cache_count].reason[copy_len] = '\0';
        alert_cache_count++;
    }
    pthread_mutex_unlock(&alert_cache_mutex);
    return 0;  // Not a duplicate
}

// Clear alert cache for specific PID to allow re-detection after unpacking
void clear_alert_cache_for_pid(pid_t pid) {
    pthread_mutex_lock(&alert_cache_mutex);
    
    int write_idx = 0;
    for (int read_idx = 0; read_idx < alert_cache_count; read_idx++) {
        if (alert_cache[read_idx].pid != pid) {
            if (write_idx != read_idx) {
                alert_cache[write_idx] = alert_cache[read_idx];
            }
            write_idx++;
        }
    }
    alert_cache_count = write_idx;
    
    pthread_mutex_unlock(&alert_cache_mutex);
}

// Clear entire alert cache (for sandbox mode periodic rescans)
void clear_alert_cache() {
    pthread_mutex_lock(&alert_cache_mutex);
    alert_cache_count = 0;
    pthread_mutex_unlock(&alert_cache_mutex);
}

// File operations and network activity tracking for JSON report
#define MAX_SANDBOX_FILE_OPS 512
typedef struct {
    pid_t pid;
    char operation[32];
    char filepath[512];
    int risk_score;
    char category[64];
    time_t timestamp;
} sandbox_file_op_t;

#define MAX_SANDBOX_NETWORK 256
typedef struct {
    pid_t pid;
    char protocol[16];
    char local_addr[128];
    char remote_addr[128];
    time_t timestamp;
} sandbox_network_t;

#define MAX_SANDBOX_MEMDUMPS 64
typedef struct {
    pid_t pid;
    char filename[256];
    size_t size;
    char sha1[41];
    time_t timestamp;
} sandbox_memdump_t;

sandbox_file_op_t sandbox_file_ops[MAX_SANDBOX_FILE_OPS];
int sandbox_file_op_count = 0;
sandbox_network_t sandbox_network[MAX_SANDBOX_NETWORK];
int sandbox_network_count = 0;
sandbox_memdump_t sandbox_memdumps[MAX_SANDBOX_MEMDUMPS];
int sandbox_memdump_count = 0;

// Async file operation queue for sandbox reporting (non-blocking)
#define FILE_OP_QUEUE_SIZE 128
typedef struct {
    pid_t pid;
    char operation[32];
    char filepath[512];
} file_op_t;

typedef struct {
    file_op_t ops[FILE_OP_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    int shutdown;
} file_op_queue_t;

file_op_queue_t file_op_queue;
pthread_t file_worker_thread;

// Statistics (now protected by mutex)
static unsigned long total_events = 0;
static unsigned long suspicious_found = 0;
static unsigned long race_conditions = 0;
static unsigned long queue_drops = 0;
static unsigned long sandbox_events = 0;  // Events from sandbox process tree
static unsigned long files_created = 0;  // Files created by sandbox
static unsigned long sockets_created = 0;  // Network connections by sandbox

// Thread-safe event queue
typedef struct {
    pid_t pid;
    pid_t ppid;
} event_data_t;

typedef struct {
    event_data_t events[EVENT_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    int shutdown;
} event_queue_t;

event_queue_t event_queue;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// Asynchronous memory dump queue
#define DUMP_QUEUE_SIZE 32
typedef struct {
    pid_t pids[DUMP_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    int shutdown;
} dump_queue_t;

dump_queue_t dump_queue;
pthread_t dump_worker_thread;

// Track PIDs that have already been dumped (prevent duplicate dumps)
#define MAX_DUMPED_PIDS 512
pid_t dumped_pids[MAX_DUMPED_PIDS];
int dumped_pids_count = 0;
pthread_mutex_t dumped_pids_mutex = PTHREAD_MUTEX_INITIALIZER;

// Track PIDs that have been processed (prevent duplicate EXEC processing)
#define MAX_PROCESSED_PIDS 1024
pid_t processed_pids[MAX_PROCESSED_PIDS];
int processed_pids_count = 0;
pthread_mutex_t processed_pids_mutex = PTHREAD_MUTEX_INITIALIZER;

// Track PIDs that called memfd_create (dump on next mmap(PROT_EXEC))
#define MAX_MEMFD_PIDS 128
pid_t memfd_pids[MAX_MEMFD_PIDS];
int memfd_pids_count = 0;
pthread_mutex_t memfd_pids_mutex = PTHREAD_MUTEX_INITIALIZER;

// Track PIDs that did execve after memfd (dump on next mmap)
#define MAX_MEMFD_EXEC_PIDS 128
pid_t memfd_exec_pids[MAX_MEMFD_EXEC_PIDS];
int memfd_exec_pids_count = 0;
pthread_mutex_t memfd_exec_pids_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// SANDBOX REPORTING FUNCTIONS
// ============================================================================

// Check if PID has already been dumped
int is_already_dumped(pid_t pid) {
    pthread_mutex_lock(&dumped_pids_mutex);
    for (int i = 0; i < dumped_pids_count; i++) {
        if (dumped_pids[i] == pid) {
            pthread_mutex_unlock(&dumped_pids_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&dumped_pids_mutex);
    return 0;
}

// Mark PID as dumped
void mark_as_dumped(pid_t pid) {
    pthread_mutex_lock(&dumped_pids_mutex);
    if (dumped_pids_count < MAX_DUMPED_PIDS) {
        dumped_pids[dumped_pids_count++] = pid;
    }
    pthread_mutex_unlock(&dumped_pids_mutex);
}

// Clear dumped flag for PID (e.g., after execve to allow re-dump)
void clear_dumped_flag(pid_t pid) {
    pthread_mutex_lock(&dumped_pids_mutex);
    for (int i = 0; i < dumped_pids_count; i++) {
        if (dumped_pids[i] == pid) {
            // Shift array left to remove this entry
            for (int j = i; j < dumped_pids_count - 1; j++) {
                dumped_pids[j] = dumped_pids[j + 1];
            }
            dumped_pids_count--;
            break;
        }
    }
    pthread_mutex_unlock(&dumped_pids_mutex);
}

// Mark PID as having done execve after memfd_create
void mark_memfd_exec_pid(pid_t pid) {
    pthread_mutex_lock(&memfd_exec_pids_mutex);
    if (memfd_exec_pids_count < MAX_MEMFD_EXEC_PIDS) {
        memfd_exec_pids[memfd_exec_pids_count++] = pid;
    }
    pthread_mutex_unlock(&memfd_exec_pids_mutex);
}

// Check and clear memfd+exec flag for PID
int check_and_clear_memfd_exec_pid(pid_t pid) {
    pthread_mutex_lock(&memfd_exec_pids_mutex);
    for (int i = 0; i < memfd_exec_pids_count; i++) {
        if (memfd_exec_pids[i] == pid) {
            // Remove from array
            for (int j = i; j < memfd_exec_pids_count - 1; j++) {
                memfd_exec_pids[j] = memfd_exec_pids[j + 1];
            }
            memfd_exec_pids_count--;
            pthread_mutex_unlock(&memfd_exec_pids_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&memfd_exec_pids_mutex);
    return 0;
}

// Mark PID as having called memfd_create
void mark_memfd_pid(pid_t pid) {
    pthread_mutex_lock(&memfd_pids_mutex);
    if (memfd_pids_count < MAX_MEMFD_PIDS) {
        memfd_pids[memfd_pids_count++] = pid;
    }
    pthread_mutex_unlock(&memfd_pids_mutex);
}

// Check and clear memfd flag for PID (returns 1 if was flagged, 0 otherwise)
int check_and_clear_memfd_pid(pid_t pid) {
    pthread_mutex_lock(&memfd_pids_mutex);
    for (int i = 0; i < memfd_pids_count; i++) {
        if (memfd_pids[i] == pid) {
            // Remove from array by shifting
            for (int j = i; j < memfd_pids_count - 1; j++) {
                memfd_pids[j] = memfd_pids[j + 1];
            }
            memfd_pids_count--;
            pthread_mutex_unlock(&memfd_pids_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&memfd_pids_mutex);
    return 0;
}

// Check if PID has already been processed
int is_already_processed(pid_t pid) {
    pthread_mutex_lock(&processed_pids_mutex);
    for (int i = 0; i < processed_pids_count; i++) {
        if (processed_pids[i] == pid) {
            pthread_mutex_unlock(&processed_pids_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&processed_pids_mutex);
    return 0;
}

// Mark PID as processed
void mark_as_processed(pid_t pid) {
    pthread_mutex_lock(&processed_pids_mutex);
    if (processed_pids_count < MAX_PROCESSED_PIDS) {
        processed_pids[processed_pids_count++] = pid;
    }
    pthread_mutex_unlock(&processed_pids_mutex);
}

// Calculate SHA-1 hash of a file
int calculate_sha1(const char *filename, char *output_hex) {
    FILE *file = fopen(filename, "rb");
    if (!file) return -1;
    
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA1_Update(&sha1, buffer, bytes);
    }
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &sha1);
    fclose(file);
    
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[40] = '\0';
    
    return 0;
}

// Calculate SHA-256 hash of a file
int calculate_sha256(const char *filename, char *output_hex) {
    FILE *file = fopen(filename, "rb");
    if (!file) return -1;
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes);
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    fclose(file);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[64] = '\0';
    
    return 0;
}

// Get file type using basic magic number detection
const char* get_file_type(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return "unknown";
    
    unsigned char magic[16];
    size_t bytes = fread(magic, 1, sizeof(magic), f);
    fclose(f);
    
    if (bytes < 4) return "empty";
    
    // ELF
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return "ELF";
    // PE/COFF
    if (magic[0] == 'M' && magic[1] == 'Z')
        return "PE";
    // Shell script
    if (magic[0] == '#' && magic[1] == '!')
        return "script";
    // Python
    if (bytes > 10 && strstr((char*)magic, "python"))
        return "python";
    // Text
    int is_text = 1;
    for (size_t i = 0; i < bytes && i < 256; i++) {
        if (magic[i] < 32 && magic[i] != '\n' && magic[i] != '\r' && magic[i] != '\t') {
            is_text = 0;
            break;
        }
    }
    if (is_text) return "text";
    
    return "binary";
}

// File operation queue functions (non-blocking)
void file_op_queue_init(file_op_queue_t *q) {
    memset(q, 0, sizeof(file_op_queue_t));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    q->shutdown = 0;
}

int file_op_queue_push(file_op_queue_t *q, pid_t pid, const char *operation, const char *filepath) {
    pthread_mutex_lock(&q->mutex);
    
    if (q->count >= FILE_OP_QUEUE_SIZE) {
        pthread_mutex_unlock(&q->mutex);
        return -1;  // Queue full, drop
    }
    
    q->ops[q->tail].pid = pid;
    strncpy(q->ops[q->tail].operation, operation, sizeof(q->ops[0].operation) - 1);
    strncpy(q->ops[q->tail].filepath, filepath, sizeof(q->ops[0].filepath) - 1);
    q->tail = (q->tail + 1) % FILE_OP_QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int file_op_queue_pop(file_op_queue_t *q, file_op_t *op) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    
    if (q->shutdown && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    *op = q->ops[q->head];
    q->head = (q->head + 1) % FILE_OP_QUEUE_SIZE;
    q->count--;
    
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Background worker for file operations (hashing, copying) - doesn't block monitoring
void* file_operation_worker(void *arg) {
    (void)arg;
    
    while (1) {
        file_op_t op;
        if (file_op_queue_pop(&file_op_queue, &op) < 0) {
            break;  // Shutdown
        }
        
        // Process file operation in background
        if (strcmp(op.operation, "created") == 0 || strcmp(op.operation, "written") == 0) {
            // Check if file still exists and is accessible
            struct stat st;
            if (stat(op.filepath, &st) < 0) {
                // File deleted or inaccessible - still log it
                printf("[SANDBOX] File %s but no longer accessible: %s (PID=%d)\n",
                       op.operation, op.filepath, op.pid);
                continue;
            }
            
            // Generate safe filename preserving directory structure indicators
            char safe_filename[1024];
            const char *filepath_ptr = op.filepath;
            
            // Strip leading slashes
            while (*filepath_ptr == '/') filepath_ptr++;
            
            // Replace remaining slashes with underscores
            int i = 0;
            for (const char *p = filepath_ptr; *p && i < 1000; p++) {
                if (*p == '/') {
                    safe_filename[i++] = '_';
                } else {
                    safe_filename[i++] = *p;
                }
            }
            safe_filename[i] = '\0';
            
            char dest_path[1024];
            snprintf(dest_path, sizeof(dest_path), "%s/%s", sandbox_dropped_dir, safe_filename);
            
            // Copy file
            FILE *src = fopen(op.filepath, "rb");
            if (src) {
                FILE *dst = fopen(dest_path, "wb");
                if (dst) {
                    char buffer[8192];
                    size_t bytes;
                    size_t total_bytes = 0;
                    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                        fwrite(buffer, 1, bytes, dst);
                        total_bytes += bytes;
                    }
                    fclose(dst);
                    
                    // Calculate hashes (this is the slow part - now async!)
                    char sha1[41], sha256[65];
                    if (calculate_sha1(dest_path, sha1) == 0 && calculate_sha256(dest_path, sha256) == 0) {
                        // Detect file type
                        const char *ftype = get_file_type(dest_path);
                        printf("[SANDBOX] Captured %s: %s (%zu bytes, type: %s, SHA-1: %s)\n",
                               op.operation, op.filepath, total_bytes, ftype, sha1);
                    }
                } else {
                    fprintf(stderr, "[WARN] Could not create %s: %s\n", dest_path, strerror(errno));
                }
                fclose(src);
            } else {
                // File exists but can't be read - log it
                printf("[SANDBOX] File %s (no read access): %s (PID=%d, size=%ld)\n",
                       op.operation, op.filepath, op.pid, (long)st.st_size);
            }
        } else if (strcmp(op.operation, "accessed") == 0) {
            // Just log access to suspicious locations (no copy)
            printf("[SANDBOX] File accessed: %s (PID=%d)\n", op.filepath, op.pid);
        }
    }
    
    return NULL;
}

// Initialize sandbox reporting
int init_sandbox_reporting(const char *sample_path) {
    // Calculate SHA-1 of sample
    if (calculate_sha1(sample_path, sample_sha1) < 0) {
        fprintf(stderr, "[!] Warning: Could not calculate SHA-1 of sample\n");
        snprintf(sample_sha1, sizeof(sample_sha1), "unknown_%ld", time(NULL));
    }
    
    // Create base directory
    snprintf(sandbox_report_dir, sizeof(sandbox_report_dir), "sandbox_%s", sample_sha1);
    if (mkdir(sandbox_report_dir, 0755) < 0 && errno != EEXIST) {
        perror("mkdir sandbox dir");
        return -1;
    }
    
    // Create subdirectories
    snprintf(sandbox_dropped_dir, sizeof(sandbox_dropped_dir), "%s/dropped_files", sandbox_report_dir);
    mkdir(sandbox_dropped_dir, 0755);
    
    snprintf(sandbox_memdump_dir, sizeof(sandbox_memdump_dir), "%s/memory_dumps", sandbox_report_dir);
    mkdir(sandbox_memdump_dir, 0755);
    
    // Create JSON report file
    char report_path[600];
    snprintf(report_path, sizeof(report_path), "%s/report.json", sandbox_report_dir);
    sandbox_json_report = fopen(report_path, "w");
    if (!sandbox_json_report) {
        perror("fopen report.json");
        return -1;
    }
    
    // Start JSON structure
    fprintf(sandbox_json_report, "{\n");
    fprintf(sandbox_json_report, "  \"analysis\": {\n");
    fprintf(sandbox_json_report, "    \"start_time\": %ld,\n", time(NULL));
    fprintf(sandbox_json_report, "    \"sample_path\": \"%s\",\n", sample_path);
    fprintf(sandbox_json_report, "    \"sample_sha1\": \"%s\",\n", sample_sha1);
    
    // Calculate SHA-256
    char sha256[65];
    if (calculate_sha256(sample_path, sha256) == 0) {
        fprintf(sandbox_json_report, "    \"sample_sha256\": \"%s\",\n", sha256);
    }
    
    // File type
    fprintf(sandbox_json_report, "    \"sample_type\": \"%s\",\n", get_file_type(sample_path));
    
    // Get file size
    struct stat st;
    if (stat(sample_path, &st) == 0) {
        fprintf(sandbox_json_report, "    \"sample_size\": %ld,\n", st.st_size);
    }
    
    fprintf(sandbox_json_report, "    \"timeout\": %d\n", sandbox_timeout);
    fprintf(sandbox_json_report, "  },\n");
    
    // Save analysis section to temp file for later reconstruction
    char analysis_tmp[600];
    snprintf(analysis_tmp, sizeof(analysis_tmp), "%s/.analysis.tmp", sandbox_report_dir);
    FILE *atmp = fopen(analysis_tmp, "w");
    if (atmp) {
        fprintf(atmp, "\"sample_path\": \"%s\",\n", sample_path);
        fprintf(atmp, "\"sample_sha1\": \"%s\",\n", sample_sha1);
        if (calculate_sha256(sample_path, sha256) == 0) {
            fprintf(atmp, "\"sample_sha256\": \"%s\",\n", sha256);
        }
        fprintf(atmp, "\"sample_type\": \"%s\",\n", get_file_type(sample_path));
        if (stat(sample_path, &st) == 0) {
            fprintf(atmp, "\"sample_size\": %ld,\n", st.st_size);
        }
        fprintf(atmp, "\"timeout\": %d\n", sandbox_timeout);
        fclose(atmp);
    }
    
    // IMMEDIATELY write a minimal complete JSON in case of crash
    // This creates a valid JSON that can be updated later
    fprintf(sandbox_json_report, "  \"processes\": [],\n");
    fprintf(sandbox_json_report, "  \"file_operations\": [],\n");
    fprintf(sandbox_json_report, "  \"network_activity\": [],\n");
    fprintf(sandbox_json_report, "  \"memory_dumps\": [],\n");
    fprintf(sandbox_json_report, "  \"summary\": {\n");
    fprintf(sandbox_json_report, "    \"end_time\": %ld,\n", time(NULL));
    fprintf(sandbox_json_report, "    \"duration\": 0,\n");
    fprintf(sandbox_json_report, "    \"total_processes\": 0,\n");
    fprintf(sandbox_json_report, "    \"files_created\": 0,\n");
    fprintf(sandbox_json_report, "    \"sockets_created\": 0,\n");
    fprintf(sandbox_json_report, "    \"suspicious_findings\": 0,\n");
    fprintf(sandbox_json_report, "    \"termination_status\": \"running\"\n");
    fprintf(sandbox_json_report, "  }\n");
    fprintf(sandbox_json_report, "}\n");
    fflush(sandbox_json_report);
    fclose(sandbox_json_report);
    sandbox_json_report = NULL;  // Will be reopened when needed
    
    printf("[+] Sandbox report directory: %s/\n", sandbox_report_dir);
    printf("[+] Sample SHA-1: %s\n", sample_sha1);
    
    return 0;
}

// Add process to sandbox report (fast - just in-memory tracking)
void report_sandbox_process(pid_t pid, pid_t ppid, const char *name, const char *path, const char *cmdline) {
    // Always write to temp file in sandbox mode
    if (!sandbox_mode) return;
    if (pid <= 0 || pid > 4194304) return;
    
    // Safety: ensure strings are not NULL
    if (!name) name = "unknown";
    if (!path) path = "unknown";
    if (!cmdline) cmdline = "unknown";
    
    // Filter out the monitoring tool itself
    if (pid == getpid() || strstr(name, "realtime_memdum") != NULL) {
        return;
    }
    
    // Determine process creation method
    const char *creation_method = "UNKNOWN";
    if (strstr(path, "memfd:") != NULL) {
        creation_method = "MEMFD_EXEC";
    } else if (pid == sandbox_root_pid) {
        creation_method = "SPAWN";
    } else {
        creation_method = "FORK_EXEC";
    }
    
    // Use trylock to avoid deadlocks
    if (pthread_mutex_trylock(&sandbox_proc_mutex) != 0) {
        fprintf(stderr, "[!] WARN: Could not acquire lock for PID %d, skipping report\n", pid);
        return;
    }
    
    // Check if this PID already exists (prevent duplicates from periodic rescans)
    int already_exists = 0;
    for (int i = 0; i < sandbox_process_count && i < MAX_SANDBOX_PROCESSES; i++) {
        if (sandbox_processes[i].pid == pid) {
            // Update the existing entry with better info
            already_exists = 1;
            strncpy(sandbox_processes[i].name, name, sizeof(sandbox_processes[i].name) - 1);
            sandbox_processes[i].name[sizeof(sandbox_processes[i].name) - 1] = '\0';
            strncpy(sandbox_processes[i].path, path, sizeof(sandbox_processes[i].path) - 1);
            sandbox_processes[i].path[sizeof(sandbox_processes[i].path) - 1] = '\0';
            strncpy(sandbox_processes[i].cmdline, cmdline, sizeof(sandbox_processes[i].cmdline) - 1);
            sandbox_processes[i].cmdline[sizeof(sandbox_processes[i].cmdline) - 1] = '\0';
            break;
        }
    }
    
    if (!already_exists) {
        // Add new process
        if (sandbox_process_count < MAX_SANDBOX_PROCESSES) {
            int idx = sandbox_process_count;
            sandbox_processes[idx].pid = pid;
            sandbox_processes[idx].ppid = ppid;
            strncpy(sandbox_processes[idx].name, name, sizeof(sandbox_processes[idx].name) - 1);
            sandbox_processes[idx].name[sizeof(sandbox_processes[idx].name) - 1] = '\0';
            strncpy(sandbox_processes[idx].path, path, sizeof(sandbox_processes[idx].path) - 1);
            sandbox_processes[idx].path[sizeof(sandbox_processes[idx].path) - 1] = '\0';
            strncpy(sandbox_processes[idx].cmdline, cmdline, sizeof(sandbox_processes[idx].cmdline) - 1);
            sandbox_processes[idx].cmdline[sizeof(sandbox_processes[idx].cmdline) - 1] = '\0';
            strncpy(sandbox_processes[idx].creation_method, creation_method, sizeof(sandbox_processes[idx].creation_method) - 1);
            sandbox_processes[idx].creation_method[sizeof(sandbox_processes[idx].creation_method) - 1] = '\0';
            sandbox_processes[idx].start_time = time(NULL);
            sandbox_processes[idx].active = 1;
            sandbox_process_count++;
        } else {
            fprintf(stderr, "[!] WARN: Process tracking array full (%d processes)\n", MAX_SANDBOX_PROCESSES);
            pthread_mutex_unlock(&sandbox_proc_mutex);
            return;
        }
    }
    
    // Fast duplicate check using hash (lock-free, no iteration)
    int hash_idx = pid % WRITTEN_PID_HASH_SIZE;
    int already_written = 0;
    
    // Try up to 8 hash slots (linear probing for collisions)
    for (int probe = 0; probe < 8; probe++) {
        int idx = (hash_idx + probe) % WRITTEN_PID_HASH_SIZE;
        int stored_pid = written_pid_hash[idx];
        if (stored_pid == pid) {
            already_written = 1;
            break;
        }
        if (stored_pid == 0) break;  // Empty slot, PID not found
    }
    
    // Write to file only if new PID
    if (!already_written) {
        char temp_file[600];
        int n = snprintf(temp_file, sizeof(temp_file), "%s/.processes.tmp", sandbox_report_dir);
        if (n > 0 && n < sizeof(temp_file)) {
            FILE *tf = fopen(temp_file, "a");
            if (tf) {
                // Escape strings separately to avoid buffer reuse
                const char *esc_name = json_escape(name);
                char name_copy[512];
                strncpy(name_copy, esc_name, sizeof(name_copy) - 1);
                name_copy[sizeof(name_copy) - 1] = '\0';
                
                const char *esc_path = json_escape(path);
                char path_copy[1024];
                strncpy(path_copy, esc_path, sizeof(path_copy) - 1);
                path_copy[sizeof(path_copy) - 1] = '\0';
                
                const char *esc_cmdline = json_escape(cmdline);
                
                fprintf(tf, "{\"pid\":%d,\"ppid\":%d,\"name\":\"%s\",\"path\":\"%s\",\"cmdline\":\"%s\",\"creation_method\":\"%s\",\"start_time\":%ld}\n",
                        pid, ppid, name_copy, path_copy, esc_cmdline, creation_method, (long)time(NULL));
                fflush(tf);
                fclose(tf);
                
                // Mark as written using atomic store
                for (int probe = 0; probe < 8; probe++) {
                    int idx = (hash_idx + probe) % WRITTEN_PID_HASH_SIZE;
                    int expected = 0;
                    if (__sync_bool_compare_and_swap(&written_pid_hash[idx], 0, pid)) {
                        break;  // Successfully stored
                    }
                    // Slot occupied, try next
                }
            }
        }
    }
    pthread_mutex_unlock(&sandbox_proc_mutex);
}

// Add file operation to report
// Add file operation to report (async - non-blocking)
void report_file_operation(pid_t pid, const char *operation, const char *filepath, int risk_score, const char *category) {
    // Always write to temp file in sandbox mode
    if (!sandbox_mode) return;
    
    // Store in JSON report array immediately (in-memory, fast)
    pthread_mutex_lock(&sandbox_proc_mutex);
    if (sandbox_file_op_count < MAX_SANDBOX_FILE_OPS) {
        sandbox_file_ops[sandbox_file_op_count].pid = pid;
        strncpy(sandbox_file_ops[sandbox_file_op_count].operation, operation, sizeof(sandbox_file_ops[0].operation) - 1);
        strncpy(sandbox_file_ops[sandbox_file_op_count].filepath, filepath, sizeof(sandbox_file_ops[0].filepath) - 1);
        sandbox_file_ops[sandbox_file_op_count].risk_score = risk_score;
        strncpy(sandbox_file_ops[sandbox_file_op_count].category, category, sizeof(sandbox_file_ops[0].category) - 1);
        sandbox_file_ops[sandbox_file_op_count].timestamp = time(NULL);
        sandbox_file_op_count++;
        
        // BULLETPROOF: Write immediately to temp file
        char temp_file[600];
        snprintf(temp_file, sizeof(temp_file), "%s/.fileops.tmp", sandbox_report_dir);
        FILE *tf = fopen(temp_file, "a");
        if (tf) {
            // Escape strings separately to avoid buffer reuse
            const char *esc_op = json_escape(operation);
            char op_copy[128];
            strncpy(op_copy, esc_op, sizeof(op_copy) - 1);
            op_copy[sizeof(op_copy) - 1] = '\0';
            
            const char *esc_path = json_escape(filepath);
            char path_copy[1024];
            strncpy(path_copy, esc_path, sizeof(path_copy) - 1);
            path_copy[sizeof(path_copy) - 1] = '\0';
            
            const char *esc_cat = json_escape(category);
            
            fprintf(tf, "{\"pid\":%d,\"operation\":\"%s\",\"filepath\":\"%s\",\"risk_score\":%d,\"category\":\"%s\",\"timestamp\":%ld}\n",
                    pid, op_copy, path_copy, risk_score, esc_cat, time(NULL));
            fflush(tf);
            fclose(tf);
        }
    }
    pthread_mutex_unlock(&sandbox_proc_mutex);
    
    // Queue for background processing (file copying, hashing) instead of blocking
    if (file_op_queue_push(&file_op_queue, pid, operation, filepath) < 0) {
        // Queue full, just log without blocking
        if (!quiet_mode) {
            fprintf(stderr, "[WARN] File operation queue full, skipping copy: %s\n", filepath);
        }
    }
}

// Add network activity to report  
void report_network_activity(pid_t pid, const char *protocol, const char *local_addr, const char *remote_addr) {
    // Always write to temp file in sandbox mode
    if (!sandbox_mode) return;
    
    pthread_mutex_lock(&sandbox_proc_mutex);
    
    // Check for duplicates (same connection already logged)
    for (int i = 0; i < sandbox_network_count; i++) {
        if (sandbox_network[i].pid == pid &&
            strcmp(sandbox_network[i].protocol, protocol) == 0 &&
            strcmp(sandbox_network[i].local_addr, local_addr) == 0 &&
            strcmp(sandbox_network[i].remote_addr, remote_addr) == 0) {
            // Already logged
            pthread_mutex_unlock(&sandbox_proc_mutex);
            return;
        }
    }
    
    // Add new network activity
    if (sandbox_network_count < MAX_SANDBOX_NETWORK) {
        sandbox_network[sandbox_network_count].pid = pid;
        strncpy(sandbox_network[sandbox_network_count].protocol, protocol, sizeof(sandbox_network[0].protocol) - 1);
        strncpy(sandbox_network[sandbox_network_count].local_addr, local_addr, sizeof(sandbox_network[0].local_addr) - 1);
        strncpy(sandbox_network[sandbox_network_count].remote_addr, remote_addr, sizeof(sandbox_network[0].remote_addr) - 1);
        sandbox_network[sandbox_network_count].timestamp = time(NULL);
        sandbox_network_count++;
        
        // BULLETPROOF: Write immediately to temp file
        char temp_file[600];
        snprintf(temp_file, sizeof(temp_file), "%s/.network.tmp", sandbox_report_dir);
        FILE *tf = fopen(temp_file, "a");
        if (tf) {
            // Escape strings separately to avoid buffer reuse issue
            const char *esc_proto = json_escape(protocol);
            char proto_copy[256];
            strncpy(proto_copy, esc_proto, sizeof(proto_copy) - 1);
            proto_copy[sizeof(proto_copy) - 1] = '\0';
            
            const char *esc_local = json_escape(local_addr);
            char local_copy[256];
            strncpy(local_copy, esc_local, sizeof(local_copy) - 1);
            local_copy[sizeof(local_copy) - 1] = '\0';
            
            const char *esc_remote = json_escape(remote_addr);
            
            fprintf(tf, "{\"pid\":%d,\"protocol\":\"%s\",\"local_address\":\"%s\",\"remote_address\":\"%s\",\"timestamp\":%ld}\n",
                    pid, proto_copy, local_copy, esc_remote, time(NULL));
            fflush(tf);
            fclose(tf);
        }
    }
    
    pthread_mutex_unlock(&sandbox_proc_mutex);
    
    printf("[SANDBOX] Network: PID=%d %s %s -> %s\n", pid, protocol, local_addr, remote_addr);
}

// Finalize sandbox report
void finalize_sandbox_report() {
    // Prevent re-entrant calls
    if (__sync_lock_test_and_set(&report_writer_busy, 1)) {
        fprintf(stderr, "[DEBUG] Report writer already busy, skipping...\n");
        return;
    }
    
    // Use trylock to avoid deadlocks
    if (pthread_mutex_trylock(&report_mutex) != 0) {
        fprintf(stderr, "[!] WARN: Could not acquire report_mutex, skipping update\n");
        __sync_lock_release(&report_writer_busy);
        return;
    }
    
    // Check if sandbox directory is valid
    if (strlen(sandbox_report_dir) == 0) {
        fprintf(stderr, "[!] ERROR: sandbox_report_dir is empty!\n");
        pthread_mutex_unlock(&report_mutex);
        __sync_lock_release(&report_writer_busy);
        return;
    }
    
    // If file was closed/NULL, reopen for writing (truncate mode)
    if (!sandbox_json_report) {
        char report_path[600];
        snprintf(report_path, sizeof(report_path), "%s/report.json", sandbox_report_dir);
        sandbox_json_report = fopen(report_path, "w");
        if (!sandbox_json_report) {
            fprintf(stderr, "[!] ERROR: Cannot open report.json for finalization: %s\n", strerror(errno));
            pthread_mutex_unlock(&report_mutex);
            __sync_lock_release(&report_writer_busy);
            return;
        }
    } else {
        // File is open - rewind and truncate to rewrite from scratch
        rewind(sandbox_json_report);
        if (ftruncate(fileno(sandbox_json_report), 0) != 0) {
            fprintf(stderr, "[!] WARN: Could not truncate report file\n");
        }
    }
    
    // Write complete JSON from scratch with error checking
    if (!sandbox_json_report) {
        fprintf(stderr, "[!] ERROR: sandbox_json_report is NULL after open attempt\n");
        goto write_error;
    }
    if (fprintf(sandbox_json_report, "{\n") < 0) goto write_error;
    if (fprintf(sandbox_json_report, "  \"analysis\": {\n") < 0) goto write_error;
    if (fprintf(sandbox_json_report, "    \"start_time\": %ld,\n", sandbox_start_time) < 0) goto write_error;
    
    // Read full analysis from initial report or reconstruct
    char initial_report[600];
    snprintf(initial_report, sizeof(initial_report), "%s/.analysis.tmp", sandbox_report_dir);
    FILE *af = fopen(initial_report, "r");
    if (af) {
        // Read and write all analysis fields from temp file
        char line[1024];
        while (fgets(line, sizeof(line), af)) {
            fprintf(sandbox_json_report, "    %s", line);
        }
        fclose(af);
    } else {
        // Fallback: write minimal analysis
        fprintf(sandbox_json_report, "    \"sample_sha1\": \"%s\"\n", sample_sha1);
    }
    fprintf(sandbox_json_report, "  },\n");
    
    // Write process tree - read from temp file if exists
    fprintf(sandbox_json_report, "  \"processes\": [\n");
    char temp_file[600];
    snprintf(temp_file, sizeof(temp_file), "%s/.processes.tmp", sandbox_report_dir);
    FILE *tf = fopen(temp_file, "r");
    if (tf) {
        // Check file size first
        fseek(tf, 0, SEEK_END);
        long file_size = ftell(tf);
        fseek(tf, 0, SEEK_SET);
        
        if (file_size < 0 || file_size > 10*1024*1024) {  // Max 10MB
            fprintf(stderr, "[!] WARN: Processes file size invalid or too large (%ld bytes), skipping\n", file_size);
            fclose(tf);
        } else {
            // Use heap instead of stack for large buffer to prevent stack overflow
            char *line = malloc(MAX_LINE);
            if (!line) {
                fprintf(stderr, "[!] ERROR: Cannot allocate memory for line buffer\n");
                fclose(tf);
            } else {
                int first = 1;
                while (fgets(line, MAX_LINE, tf)) {
                    // Ensure null termination
                    line[MAX_LINE - 1] = '\0';
                    // Strip newline if present - safe bounds check
                    size_t len = strnlen(line, MAX_LINE);
                    if (len > 0 && len < MAX_LINE && line[len-1] == '\n') {
                        line[len-1] = '\0';
                    }
                    if (!first) fprintf(sandbox_json_report, ",\n");
                    fprintf(sandbox_json_report, "    %s", line);
                    first = 0;
                }
                free(line);
                fclose(tf);
                if (!first) fprintf(sandbox_json_report, "\n");  // Add final newline if data was written
            }
        }
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write file operations - read from temp file
    fprintf(sandbox_json_report, "  \"file_operations\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.fileops.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char *line = malloc(MAX_LINE);
        if (line) {
            int first = 1;
            while (fgets(line, MAX_LINE, tf)) {
                line[MAX_LINE - 1] = '\0';
                size_t len = strnlen(line, MAX_LINE);
                if (len > 0 && len < MAX_LINE && line[len-1] == '\n') {
                    line[len-1] = '\0';
                }
                if (!first) fprintf(sandbox_json_report, ",\n");
                fprintf(sandbox_json_report, "    %s", line);
                first = 0;
            }
            free(line);
            if (!first) fprintf(sandbox_json_report, "\n");
        }
        fclose(tf);
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write network activity - read from temp file
    fprintf(sandbox_json_report, "  \"network_activity\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.network.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char *line = malloc(MAX_LINE);
        if (line) {
            int first = 1;
            while (fgets(line, MAX_LINE, tf)) {
                line[MAX_LINE - 1] = '\0';
                size_t len = strnlen(line, MAX_LINE);
                if (len > 0 && len < MAX_LINE && line[len-1] == '\n') {
                    line[len-1] = '\0';
                }
                if (!first) fprintf(sandbox_json_report, ",\n");
                fprintf(sandbox_json_report, "    %s", line);
                first = 0;
            }
            free(line);
            if (!first) fprintf(sandbox_json_report, "\n");
        }
        fclose(tf);
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write memory dumps - from deduplicated records (not temp file)
    fprintf(sandbox_json_report, "  \"memory_dumps\": [\n");
    pthread_mutex_lock(&memdump_mutex);
    for (int i = 0; i < memdump_record_count; i++) {
        if (i > 0) fprintf(sandbox_json_report, ",\n");
        fprintf(sandbox_json_report, "    {\"pid\":%d,\"filename\":\"%s\",\"size\":%zu,\"sha1\":\"%s\",\"timestamp\":%ld}",
                memdump_records[i].pid,
                memdump_records[i].filename,
                memdump_records[i].size,
                memdump_records[i].sha1,
                (long)memdump_records[i].timestamp);
    }
    if (memdump_record_count > 0) fprintf(sandbox_json_report, "\n");
    pthread_mutex_unlock(&memdump_mutex);
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write alerts/suspicious findings
    fprintf(sandbox_json_report, "  \"alerts\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.alerts.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char *line = malloc(MAX_LINE);
        if (line) {
            int first = 1;
            int line_count = 0;
            int max_alert_lines = 1000;  // Limit to 1k alerts to prevent crashes
            while (line_count < max_alert_lines && fgets(line, MAX_LINE, tf)) {
                // Ensure null termination
                line[MAX_LINE - 1] = '\0';
                // Strip newline if present - safe bounds check
                size_t len = strnlen(line, MAX_LINE);
                if (len > 0 && len < MAX_LINE && line[len-1] == '\n') {
                    line[len-1] = '\0';
                }
                if (!first) fprintf(sandbox_json_report, ",\n");
                fprintf(sandbox_json_report, "    %s", line);
                first = 0;
                line_count++;
            }
            free(line);
            if (!first) fprintf(sandbox_json_report, "\n");
            if (line_count >= max_alert_lines) {
                fprintf(stderr, "[!] WARN: Alert limit reached (%d), truncating...\n", max_alert_lines);
            }
        }
        if (ferror(tf)) {
            fprintf(stderr, "[!] ERROR: I/O error reading alerts file\n");
            clearerr(tf);
        }
        fclose(tf);
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write summary
    fprintf(sandbox_json_report, "  \"summary\": {\n");
    fprintf(sandbox_json_report, "    \"end_time\": %ld,\n", time(NULL));
    fprintf(sandbox_json_report, "    \"duration\": %ld,\n", time(NULL) - sandbox_start_time);
    fprintf(sandbox_json_report, "    \"total_processes\": %d,\n", sandbox_process_count);
    fprintf(sandbox_json_report, "    \"files_created\": %lu,\n", files_created);
    fprintf(sandbox_json_report, "    \"sockets_created\": %lu,\n", sockets_created);
    fprintf(sandbox_json_report, "    \"suspicious_findings\": %lu,\n", suspicious_found);
    fprintf(sandbox_json_report, "    \"termination_status\": \"%s\"", sandbox_termination_status);
    if (sandbox_exit_code >= 0) {
        fprintf(sandbox_json_report, ",\n    \"exit_code\": %d", sandbox_exit_code);
    }
    if (sandbox_tool_crashed) {
        fprintf(sandbox_json_report, ",\n    \"tool_crashed\": true,\n    \"crash_reason\": \"%s\"\n", sandbox_crash_reason);
    } else {
        fprintf(sandbox_json_report, "\n");
    }
    fprintf(sandbox_json_report, "  }\n");
    
    fprintf(sandbox_json_report, "}\n");
    fflush(sandbox_json_report);
    // DO NOT close or set to NULL - keep file open for periodic updates
    
    printf("[+] Sandbox report finalized: %s/report.json\n", sandbox_report_dir);
    
    pthread_mutex_unlock(&report_mutex);
    __sync_lock_release(&report_writer_busy);
    return;

write_error:
    fprintf(stderr, "[!] ERROR: Failed to write to report.json: %s\n", strerror(errno));
    if (sandbox_json_report) {
        fclose(sandbox_json_report);
        sandbox_json_report = NULL;
    }
    pthread_mutex_unlock(&report_mutex);
    __sync_lock_release(&report_writer_busy);
}

// Signal-safe finalization: no mutexes, best-effort write
void finalize_sandbox_report_signal_safe() {
    // Try to reopen file if closed
    if (!sandbox_json_report) {
        if (strlen(sandbox_report_dir) == 0) {
            write(STDERR_FILENO, "[!] ERROR: sandbox_report_dir empty in signal handler\n", 56);
            return;
        }
        
        char report_path[600];
        snprintf(report_path, sizeof(report_path), "%s/report.json", sandbox_report_dir);
        sandbox_json_report = fopen(report_path, "w");  // CHANGED: Use "w" to truncate/rewrite
        if (!sandbox_json_report) {
            char err[256];
            int len = snprintf(err, sizeof(err), "[!] ERROR: Cannot reopen report.json in signal handler\n");
            write(STDERR_FILENO, err, len);
            return;
        }
    } else {
        // File is open - rewind and truncate to rewrite from scratch
        rewind(sandbox_json_report);
        int fd = fileno(sandbox_json_report);
        if (ftruncate(fd, 0) != 0) {
            write(STDERR_FILENO, "[!] WARN: Could not truncate report file in signal handler\n", 60);
        }
    }
    
    // Get file descriptor for low-level operations
    int fd = fileno(sandbox_json_report);
    
    // Write complete JSON from scratch
    fprintf(sandbox_json_report, "{\n");
    
    // Write analysis section
    fprintf(sandbox_json_report, "  \"analysis\": {\n");
    fprintf(sandbox_json_report, "    \"start_time\": %ld,\n", sandbox_start_time);
    
    // Read full analysis from temp file
    char temp_file[600];
    snprintf(temp_file, sizeof(temp_file), "%s/.analysis.tmp", sandbox_report_dir);
    FILE *af = fopen(temp_file, "r");
    if (af) {
        char line[1024];
        while (fgets(line, sizeof(line), af)) {
            fprintf(sandbox_json_report, "    %s", line);
        }
        fclose(af);
    } else {
        fprintf(sandbox_json_report, "    \"sample_sha1\": \"%s\"\n", sample_sha1);
    }
    fprintf(sandbox_json_report, "  },\n");
    
    // Write sections by reading from temp files (bulletproof - data already on disk)
    fprintf(sandbox_json_report, "  \"processes\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.processes.tmp", sandbox_report_dir);
    FILE *tf = fopen(temp_file, "r");
    if (tf) {
        char line[MAX_LINE];
        int first = 1;
        while (fgets(line, sizeof(line), tf)) {
            line[sizeof(line) - 1] = '\0';
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
            if (!first) fprintf(sandbox_json_report, ",\n");
            fprintf(sandbox_json_report, "    %s", line);
            first = 0;
        }
        fclose(tf);
        if (!first) fprintf(sandbox_json_report, "\n");
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    fprintf(sandbox_json_report, "  \"file_operations\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.fileops.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char line[MAX_LINE];
        int first = 1;
        while (fgets(line, sizeof(line), tf)) {
            line[sizeof(line) - 1] = '\0';
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
            if (!first) fprintf(sandbox_json_report, ",\n");
            fprintf(sandbox_json_report, "    %s", line);
            first = 0;
        }
        fclose(tf);
        if (!first) fprintf(sandbox_json_report, "\n");
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    fprintf(sandbox_json_report, "  \"network_activity\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.network.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char line[MAX_LINE];
        int first = 1;
        while (fgets(line, sizeof(line), tf)) {
            line[sizeof(line) - 1] = '\0';
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
            if (!first) fprintf(sandbox_json_report, ",\n");
            fprintf(sandbox_json_report, "    %s", line);
            first = 0;
        }
        fclose(tf);
        if (!first) fprintf(sandbox_json_report, "\n");
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write memory dumps from centralized array (same as normal path)
    fprintf(sandbox_json_report, "  \"memory_dumps\": [\n");
    // Note: In signal handler we skip mutex to avoid deadlock - accept potential inconsistency
    for (int i = 0; i < memdump_record_count && i < MAX_MEMDUMP_RECORDS; i++) {
        if (i > 0) fprintf(sandbox_json_report, ",\n");
        fprintf(sandbox_json_report, "    {\"pid\":%d,\"filename\":\"%s\",\"size\":%zu,\"sha1\":\"%s\",\"timestamp\":%ld}",
                memdump_records[i].pid,
                memdump_records[i].filename,
                memdump_records[i].size,
                memdump_records[i].sha1,
                (long)memdump_records[i].timestamp);
    }
    if (memdump_record_count > 0) fprintf(sandbox_json_report, "\n");
    fprintf(sandbox_json_report, "  ],\n");
    
    fprintf(sandbox_json_report, "  \"alerts\": [\n");
    snprintf(temp_file, sizeof(temp_file), "%s/.alerts.tmp", sandbox_report_dir);
    tf = fopen(temp_file, "r");
    if (tf) {
        char line[MAX_LINE];
        int first = 1;
        int line_count = 0;
        int max_alert_lines = 1000;  // Limit alerts in signal handler too
        while (line_count < max_alert_lines && fgets(line, sizeof(line), tf)) {
            line[sizeof(line) - 1] = '\0';
            size_t len = strnlen(line, sizeof(line));
            if (len > 0 && len < sizeof(line) && line[len-1] == '\n') line[len-1] = '\0';
            if (!first) fprintf(sandbox_json_report, ",\n");
            fprintf(sandbox_json_report, "    %s", line);
            first = 0;
            line_count++;
        }
        if (ferror(tf)) {
            write(STDERR_FILENO, "[!] ERROR: I/O error reading alerts in signal handler\n", 56);
            clearerr(tf);
        }
        fclose(tf);
        if (!first) fprintf(sandbox_json_report, "\n");
        if (line_count >= max_alert_lines) {
            write(STDERR_FILENO, "[!] WARN: Alert limit reached in signal handler\n", 49);
        }
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    fprintf(sandbox_json_report, "  \"summary\": {\n");
    fprintf(sandbox_json_report, "    \"end_time\": %ld,\n", time(NULL));
    fprintf(sandbox_json_report, "    \"duration\": %ld,\n", time(NULL) - sandbox_start_time);
    fprintf(sandbox_json_report, "    \"total_processes\": %d,\n", sandbox_process_count);
    fprintf(sandbox_json_report, "    \"files_created\": %lu,\n", files_created);
    fprintf(sandbox_json_report, "    \"sockets_created\": %lu,\n", sockets_created);
    fprintf(sandbox_json_report, "    \"suspicious_findings\": %lu,\n", suspicious_found);
    fprintf(sandbox_json_report, "    \"termination_status\": \"%s\"", sandbox_termination_status);
    
    // Debug output to stderr
    char debug_msg[512];
    int debug_len = snprintf(debug_msg, sizeof(debug_msg),
                            "[DEBUG] Signal-safe writing summary: status=%s, crashed=%d, exit_code=%d\n",
                            sandbox_termination_status, sandbox_tool_crashed, sandbox_exit_code);
    write(STDERR_FILENO, debug_msg, debug_len);
    
    if (sandbox_exit_code >= 0) {
        fprintf(sandbox_json_report, ",\n    \"exit_code\": %d", sandbox_exit_code);
    }
    if (sandbox_tool_crashed) {
        fprintf(sandbox_json_report, ",\n    \"tool_crashed\": true,\n    \"crash_reason\": \"%s\"\n", sandbox_crash_reason);
    } else {
        fprintf(sandbox_json_report, "\n");
    }
    fprintf(sandbox_json_report, "  }\n");
    
    fprintf(sandbox_json_report, "}\n");
    
    // CRITICAL: Force all buffered data to disk immediately
    fflush(sandbox_json_report);
    fsync(fd);  // Ensure kernel writes to disk
    
    fclose(sandbox_json_report);
    sandbox_json_report = NULL;
}

// Emergency exit handler - runs even if signals don't work
void emergency_exit_handler() {
    static int exit_called = 0;
    if (exit_called) return;
    exit_called = 1;
    
    // Only run in sandbox mode
    if (!sandbox_mode) return;
    
    // If termination status is still running, the tool likely crashed
    if (strcmp(sandbox_termination_status, "running") == 0) {
        sandbox_tool_crashed = 1;
        strncpy(sandbox_crash_reason, "Monitoring tool terminated unexpectedly (atexit handler)", 
                sizeof(sandbox_crash_reason) - 1);
        strncpy(sandbox_termination_status, "tool_crashed", sizeof(sandbox_termination_status) - 1);
    }
    
    // Only finalize if directory is set
    if (strlen(sandbox_report_dir) > 0) {
        fprintf(stderr, "[EMERGENCY] atexit() handler running, finalizing report...\n");
        finalize_sandbox_report();
    }
}

// Flush current report data (for periodic saves or crash recovery)
void flush_sandbox_report() {
    if (!sandbox_json_report || !sandbox_mode) return;
    
    // Just flush the file buffer to disk without closing
    pthread_mutex_lock(&report_mutex);
    fflush(sandbox_json_report);
    pthread_mutex_unlock(&report_mutex);
}

// ============================================================================
// END SANDBOX REPORTING
// ============================================================================

// Initialize dump queue
void dump_queue_init(dump_queue_t *q) {
    memset(q, 0, sizeof(dump_queue_t));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    q->shutdown = 0;
}

// Queue a PID for background memory dumping
int dump_queue_push(dump_queue_t *q, pid_t pid) {
    pthread_mutex_lock(&q->mutex);
    
    if (q->count >= DUMP_QUEUE_SIZE) {
        // Queue full - drop request
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    q->pids[q->tail] = pid;
    q->tail = (q->tail + 1) % DUMP_QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Dequeue a PID for dumping (blocking)
int dump_queue_pop(dump_queue_t *q, pid_t *pid) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    
    if (q->shutdown && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    *pid = q->pids[q->head];
    q->head = (q->head + 1) % DUMP_QUEUE_SIZE;
    q->count--;
    
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

void cleanup(int sig) {
    static int cleanup_called = 0;
    
    // Prevent double cleanup
    if (cleanup_called) {
        return;
    }
    cleanup_called = 1;
    
    running = 0;  // Signal main loop to exit
    
    if (sig != 0) {
        // CRITICAL: In signal handler - use write() for signal-safe output
        char msg[256];
        int len = snprintf(msg, sizeof(msg), "\n[!] Caught signal %d, finalizing report...\n", sig);
        write(STDERR_FILENO, msg, len);
        
        // Record that the tool crashed if it's not a normal termination signal
        if (sandbox_mode && sig != SIGINT && sig != SIGTERM) {
            sandbox_tool_crashed = 1;
            snprintf(sandbox_crash_reason, sizeof(sandbox_crash_reason), 
                     "Monitoring tool crashed with signal %d (%s)", sig,
                     sig == SIGSEGV ? "SIGSEGV" : 
                     sig == SIGABRT ? "SIGABRT" : 
                     sig == SIGBUS ? "SIGBUS" : "UNKNOWN");
            strncpy(sandbox_termination_status, "tool_crashed", sizeof(sandbox_termination_status) - 1);
            
            // Debug output
            char debug[256];
            int dlen = snprintf(debug, sizeof(debug), 
                               "[DEBUG] Set tool_crashed=1, status=%s, reason=%s\n",
                               sandbox_termination_status, sandbox_crash_reason);
            write(STDERR_FILENO, debug, dlen);
        }
        
        // CRITICAL: Always finalize report in sandbox mode (even if file pointer is NULL)
        if (sandbox_mode) {
            write(STDERR_FILENO, "[DEBUG] Calling finalize_sandbox_report_signal_safe()...\n", 59);
            finalize_sandbox_report_signal_safe();
            write(STDERR_FILENO, "[DEBUG] Report finalized\n", 25);
        } else {
            write(STDERR_FILENO, "[DEBUG] Not in sandbox mode, skipping report\n", 46);
        }
        
        write(STDERR_FILENO, "[!] Report saved, exiting...\n", 30);
        _exit(0);  // Use _exit() for immediate termination from signal handler
    }
    
    // Normal shutdown path (not from signal)
    printf("\n[!] Shutting down...\n");
    
    // Signal shutdown to all worker threads first
    pthread_mutex_lock(&event_queue.mutex);
    event_queue.shutdown = 1;
    pthread_cond_broadcast(&event_queue.not_empty);
    pthread_mutex_unlock(&event_queue.mutex);
    
    // Signal dump thread to shutdown
    if (full_dump) {
        pthread_mutex_lock(&dump_queue.mutex);
        dump_queue.shutdown = 1;
        pthread_cond_signal(&dump_queue.not_empty);
        pthread_mutex_unlock(&dump_queue.mutex);
    }
    
    // Signal file operation thread to shutdown
    if (sandbox_mode) {
        pthread_mutex_lock(&file_op_queue.mutex);
        file_op_queue.shutdown = 1;
        pthread_cond_signal(&file_op_queue.not_empty);
        pthread_mutex_unlock(&file_op_queue.mutex);
        
        // Give file worker time to finish pending operations
        usleep(200000);  // 200ms - increased to ensure all operations complete
    }
    
    // Finalize sandbox report after workers are done
    // Always call finalization in sandbox mode - it will reopen file if needed
    if (sandbox_mode) {
        printf("[*] Finalizing sandbox report...\n");
        finalize_sandbox_report();
    }
    
    printf("[*] Statistics:\n");
    printf("    Total events processed: %lu\n", total_events);
    printf("    Suspicious findings: %lu\n", suspicious_found);
    printf("    Race conditions (normal): %lu\n", race_conditions);
    printf("    Queue drops (overload): %lu\n", queue_drops);
    if (sandbox_mode) {
        printf("    Sandbox events: %lu\n", sandbox_events);
        printf("    Files created: %lu\n", files_created);
        printf("    Sockets created: %lu\n", sockets_created);
    }
    
    if (nl_sock >= 0) {
        close(nl_sock);
    }
}

#ifdef ENABLE_YARA
// YARA callback function for match reporting
static int yara_callback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
    (void)context;  // Mark as intentionally unused
    (void)user_data;  // Mark as intentionally unused
    
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *) message_data;
        printf("[YARA] Match: %s\n", rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

int scan_with_yara(const char *filename) {
    YR_RULES *rules = NULL;
    YR_COMPILER *compiler = NULL;
    YR_SCANNER *scanner = NULL;

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return -1;
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to create YARA compiler\n");
        yr_finalize();
        return -1;
    }

    FILE *rule_file = fopen(yara_rules_path, "r");
    if (!rule_file) {
        perror("[-] Could not open YARA rule file");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    int errors = yr_compiler_add_file(compiler, rule_file, NULL, yara_rules_path);
    fclose(rule_file);

    if (errors > 0) {
        fprintf(stderr, "[-] YARA compilation errors\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return -1;
    }

    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS) {
        yr_rules_destroy(rules);
        yr_finalize();
        return -1;
    }

    printf("[YARA] Scanning %s\n", filename);

    int result = 0;
    yr_scanner_set_callback(scanner, yara_callback, NULL);

    if (yr_scanner_scan_file(scanner, filename) != ERROR_SUCCESS)
        result = -1;

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();

    return result;
}
#else
int scan_with_yara(const char *filename) {
    printf("[INFO] YARA support not compiled in. Skipping scan of %s\n", filename);
    return 0;
}
#endif

void dump_memory_region(pid_t pid, unsigned long start, unsigned long end, int skip_large) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    size_t size = end - start;
    
    // Check for overflow and excessively large regions
    if (end < start || size > 1024*1024*1024) {
        fprintf(stderr, "[-] Invalid or too large memory region: %zu bytes\n", size);
        return;
    }
    
    // In high-load environments, skip dumping large regions to prevent buffer overflow
    // Log the region for manual investigation instead
    if (skip_large && size > 10*1024*1024) {  // > 10MB
        printf("[INFO] Skipping dump of large region (manual investigation recommended): PID=%d range=0x%lx-0x%lx size=%zuMB\n",
               pid, start, end, size/(1024*1024));
        return;
    }

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror("[-] open mem");
        return;
    }

    char out_filename[128];
    snprintf(out_filename, sizeof(out_filename), "dump_%d_0x%lx-0x%lx.bin", pid, start, end);
    int out_fd = open(out_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("[-] open out");
        close(mem_fd);
        return;
    }

    if (lseek(mem_fd, start, SEEK_SET) == -1) {
        perror("[-] lseek");
        close(mem_fd);
        close(out_fd);
        return;
    }
    
    char *buffer = malloc(size);
    if (!buffer) {
        perror("[-] malloc");
        close(mem_fd);
        close(out_fd);
        return;
    }

    ssize_t bytes = read(mem_fd, buffer, size);
    if (bytes > 0) {
        ssize_t written = write(out_fd, buffer, bytes);
        if (written == bytes) {
            printf("[+] Dumped %ld bytes to %s\n", bytes, out_filename);
            if (yara_rules_path)
                scan_with_yara(out_filename);
        } else {
            fprintf(stderr, "[-] Partial write: %ld/%ld bytes\n", written, bytes);
        }
    } else if (bytes < 0) {
        perror("[-] read mem");
    }

    free(buffer);
    close(mem_fd);
    close(out_fd);
}

// Dump memfd file contents - this is where the decrypted shellcode lives
void dump_memfd_files(pid_t pid) {
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    
    DIR *dir = opendir(fd_dir);
    if (!dir) {
        fprintf(stderr, "[-] Cannot open /proc/%d/fd\n", pid);
        return;
    }
    
    // Get process name
    char comm[256] = "unknown";
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *comm_file = fopen(comm_path, "r");
    if (comm_file) {
        if (fgets(comm, sizeof(comm), comm_file)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n')
                comm[len-1] = '\0';
        }
        fclose(comm_file);
    }
    
    struct dirent *entry;
    int memfd_found = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char fd_path[128], link_target[512];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%s", pid, entry->d_name);
        
        ssize_t len = readlink(fd_path, link_target, sizeof(link_target) - 1);
        if (len > 0) {
            link_target[len] = '\0';
            
            // Check if this is a memfd
            if (strstr(link_target, "/memfd:") != NULL || strstr(link_target, "memfd:") == link_target) {
                memfd_found = 1;
                printf("[+] Found memfd in PID %d: fd/%s -> %s\n", pid, entry->d_name, link_target);
                
                // Open and dump the memfd contents
                int fd = open(fd_path, O_RDONLY);
                if (fd < 0) {
                    fprintf(stderr, "[-] Cannot open memfd: %s\n", strerror(errno));
                    continue;
                }
                
                // Get file size
                struct stat st;
                if (fstat(fd, &st) < 0) {
                    fprintf(stderr, "[-] Cannot stat memfd: %s\n", strerror(errno));
                    close(fd);
                    continue;
                }
                
                printf("[+] Memfd size: %ld bytes\n", st.st_size);
                
                // Create dump file
                char dump_file[512];
                if (sandbox_mode && strlen(sandbox_memdump_dir) > 0) {
                    snprintf(dump_file, sizeof(dump_file), "%s/memfd_dump_%d_%s.bin", 
                             sandbox_memdump_dir, pid, comm);
                } else {
                    snprintf(dump_file, sizeof(dump_file), "memfd_dump_%d_%s.bin", pid, comm);
                }
                
                int out_fd = open(dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (out_fd < 0) {
                    fprintf(stderr, "[-] Cannot create dump file: %s\n", strerror(errno));
                    close(fd);
                    continue;
                }
                
                // Copy memfd contents
                char buffer[8192];
                ssize_t total = 0;
                ssize_t n;
                while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
                    write(out_fd, buffer, n);
                    total += n;
                }
                
                close(fd);
                close(out_fd);
                
                printf("[+] Dumped memfd to %s (%ld bytes)\n", dump_file, total);
                
                // Calculate hash and report
                char sha1[41];
                if (calculate_sha1(dump_file, sha1) == 0) {
                    printf("[+] Memfd dump SHA-1: %s\n", sha1);
                    
                    // Use separate memory dump tracking (not EDR telemetry lock)
                    if (sandbox_mode) {
                        pthread_mutex_lock(&memdump_mutex);
                        
                        // Check if this exact dump already exists (SHA1 deduplication)
                        if (!is_duplicate_memdump(sha1)) {
                            if (memdump_record_count < MAX_MEMDUMP_RECORDS) {
                                const char *filename = strrchr(dump_file, '/');
                                filename = filename ? filename + 1 : dump_file;
                                
                                memdump_records[memdump_record_count].pid = pid;
                                strncpy(memdump_records[memdump_record_count].filename, filename, 
                                        sizeof(memdump_records[0].filename) - 1);
                                memdump_records[memdump_record_count].size = total;
                                strncpy(memdump_records[memdump_record_count].sha1, sha1, 
                                        sizeof(memdump_records[0].sha1) - 1);
                                memdump_records[memdump_record_count].timestamp = time(NULL);
                                memdump_records[memdump_record_count].written_to_disk = 1;
                                memdump_record_count++;
                                
                                // Register to prevent future duplicates
                                register_memdump(sha1, pid);
                                
                                printf("[+] Registered memory dump %d: %s (SHA1: %s)\n", 
                                       memdump_record_count, filename, sha1);
                            }
                        } else {
                            printf("[!] Skipping duplicate dump (SHA1: %s already captured)\n", sha1);
                        }
                        
                        pthread_mutex_unlock(&memdump_mutex);
                    }
                }
            }
        }
    }
    
    closedir(dir);
    
    if (!memfd_found) {
        printf("[!] No memfd found in PID %d\n", pid);
    }
}

// Dump executable memory regions from /proc/PID/maps
// This catches XOR'd ELFs, UPX unpacked code, and runtime payloads in memory
void dump_executable_mappings(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(stderr, "[-] Cannot open /proc/%d/maps for dumping\n", pid);
        return;
    }
    
    // Get process name
    char comm[256] = "unknown";
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *comm_file = fopen(comm_path, "r");
    if (comm_file) {
        if (fgets(comm, sizeof(comm), comm_file)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n')
                comm[len-1] = '\0';
        }
        fclose(comm_file);
    }
    
    char line[1024];
    int dumps_created = 0;
    
    printf("[+] Scanning executable memory regions in PID %d...\n", pid);
    printf("[INFO] Process: %s\n", comm);
    
    // Debug: if comm starts with "memfd:", this is a fexecve'd process
    int comm_is_memfd = (strncmp(comm, "memfd:", 6) == 0);
    if (comm_is_memfd) {
        printf("[DEBUG] Comm indicates fexecve from memfd - looking for payload regions\n");
    }
    
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char path[512] = "";
        
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) < 3)
            continue;
        
        // Only dump executable regions with suspicious characteristics:
        // 1. Anonymous executable (RWX shellcode, reflective loading)
        // 2. memfd executable (fileless execution)
        // 3. Deleted executable (anti-forensics)
        // 4. /tmp or /dev/shm executable (suspicious locations)
        
        int is_executable = strchr(perms, 'x') != NULL;
        if (!is_executable) continue;
        
        int should_dump = 0;
        const char *reason = NULL;
        
        // Check if this process has memfd flag (indicates fexecve'd process)
        int is_memfd_process = 0;
        pthread_mutex_lock(&memfd_pids_mutex);
        for (int i = 0; i < memfd_pids_count; i++) {
            if (memfd_pids[i] == pid) {
                is_memfd_process = 1;
                break;
            }
        }
        pthread_mutex_unlock(&memfd_pids_mutex);
        
        // Check for suspicious patterns
        int is_anonymous = (strlen(path) == 0 || path[0] != '/');
        
        // HIGH PRIORITY: memfd mappings (fexecve'd processes)
        // Path might be: "memfd:name", "/memfd:name (deleted)", or even empty for some regions
        if (strstr(path, "memfd:") != NULL) {
            should_dump = 1;
            reason = "memfd_mapping";
        } else if (strstr(path, "(deleted)") != NULL && strstr(path, "memfd") != NULL) {
            // Catch /memfd:xxx (deleted) pattern
            should_dump = 1;
            reason = "memfd_deleted";
        } else if (comm_is_memfd && is_anonymous) {
            // CRITICAL: If comm shows "memfd:", anonymous regions are the payload!
            // After fexecve(), the ELF gets mapped and the memfd fd is closed.
            // /proc/PID/maps may show these as anonymous or with empty path.
            should_dump = 1;
            reason = "fexecve_payload";
        } else if (is_memfd_process && strlen(path) > 0 && strstr(path, "/tmp") == NULL && strstr(path, "/usr") == NULL && strstr(path, "/lib") == NULL) {
            // For memfd-flagged processes: dump any non-system, non-loader executable region
            // This catches cases where /proc/PID/maps shows unusual paths for fexecve'd code
            should_dump = 1;
            reason = "memfd_process_exec";
        } else if (strstr(path, "(deleted)") != NULL) {
            should_dump = 1;
            reason = "deleted_mapping";
        } else if (strstr(path, "/tmp/") != NULL && is_memfd_process) {
            // For memfd processes, even /tmp mappings might be the original loader stub
            // But we want the actual payload, so be selective
            should_dump = 0;  // Skip the original encrypted loader
        } else if (strstr(path, "/dev/shm") != NULL) {
            should_dump = 1;
            reason = "shm_executable";
        } else if (is_anonymous && 
                   strstr(path, "[stack]") == NULL &&
                   strstr(path, "[vdso]") == NULL &&
                   strstr(path, "[vvar]") == NULL &&
                   strstr(path, "[vsyscall]") == NULL) {
            // Anonymous executable (but not kernel pages)
            // For memfd processes, these are HIGH PRIORITY (XOR'd ELF payload!)
            should_dump = 1;
            reason = is_memfd_process ? "fexecve_payload" : "anonymous_exec";
        }
        // REMOVED: This was too aggressive and dumped all system libraries
        /*
        else if (is_memfd_process && strchr(perms, 'r') && strchr(perms, 'x')) {
            // For memfd-flagged processes: dump ANY readable+executable region
            // This is aggressive but necessary to catch all payload variations
            should_dump = 1;
            reason = "memfd_exec_region";
        }
        */
        
        if (should_dump) {
            size_t region_size = end - start;
            
            // Only dump reasonable sizes (avoid huge mappings, but allow up to 50MB for UPX)
            if (region_size < 100 || region_size > 50*1024*1024) {
                continue;
            }
            
            printf("[+] Found suspicious executable region: 0x%lx-0x%lx (%zu bytes) [%s] %s\n",
                   start, end, region_size, reason, path);
            
            // Open /proc/PID/mem for reading
            char mem_path[64];
            snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
            int mem_fd = open(mem_path, O_RDONLY);
            if (mem_fd < 0) {
                fprintf(stderr, "[-] Cannot open /proc/%d/mem: %s\n", pid, strerror(errno));
                continue;
            }
            
            // Seek to region start
            if (lseek(mem_fd, start, SEEK_SET) == -1) {
                fprintf(stderr, "[-] Cannot seek to 0x%lx: %s\n", start, strerror(errno));
                close(mem_fd);
                continue;
            }
            
            // Create dump file
            char dump_file[512];
            if (sandbox_mode && strlen(sandbox_memdump_dir) > 0) {
                snprintf(dump_file, sizeof(dump_file), "%s/memdump_%d_%s_0x%lx.bin",
                         sandbox_memdump_dir, pid, reason, start);
            } else {
                snprintf(dump_file, sizeof(dump_file), "memdump_%d_%s_0x%lx.bin",
                         pid, reason, start);
            }
            
            int out_fd = open(dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out_fd < 0) {
                fprintf(stderr, "[-] Cannot create %s: %s\n", dump_file, strerror(errno));
                close(mem_fd);
                continue;
            }
            
            // Read and write memory region
            char *buffer = malloc(region_size);
            if (!buffer) {
                fprintf(stderr, "[-] Cannot allocate %zu bytes\n", region_size);
                close(mem_fd);
                close(out_fd);
                unlink(dump_file);
                continue;
            }
            
            ssize_t bytes_read = read(mem_fd, buffer, region_size);
            close(mem_fd);
            
            if (bytes_read > 0) {
                ssize_t bytes_written = write(out_fd, buffer, bytes_read);
                close(out_fd);
                
                if (bytes_written == bytes_read) {
                    printf("[+] Dumped %ld bytes to %s\n", bytes_read, dump_file);
                    dumps_created++;
                    
                    // Calculate SHA1 and register
                    char sha1[41];
                    if (calculate_sha1(dump_file, sha1) == 0) {
                        printf("[+] Memory dump SHA-1: %s\n", sha1);
                        
                        // Check for ELF magic
                        if (bytes_read >= 4 && 
                            (unsigned char)buffer[0] == 0x7f && buffer[1] == 'E' &&
                            buffer[2] == 'L' && buffer[3] == 'F') {
                            printf("[!] DETECTED: ELF binary in memory (XOR'd/decrypted/UPX unpacked!)\n");
                        }
                        
                        // Register with SHA1 deduplication
                        if (sandbox_mode) {
                            pthread_mutex_lock(&memdump_mutex);
                            
                            if (!is_duplicate_memdump(sha1)) {
                                if (memdump_record_count < MAX_MEMDUMP_RECORDS) {
                                    const char *filename = strrchr(dump_file, '/');
                                    filename = filename ? filename + 1 : dump_file;
                                    
                                    memdump_records[memdump_record_count].pid = pid;
                                    strncpy(memdump_records[memdump_record_count].filename, filename,
                                            sizeof(memdump_records[0].filename) - 1);
                                    memdump_records[memdump_record_count].size = bytes_read;
                                    strncpy(memdump_records[memdump_record_count].sha1, sha1,
                                            sizeof(memdump_records[0].sha1) - 1);
                                    memdump_records[memdump_record_count].timestamp = time(NULL);
                                    memdump_records[memdump_record_count].written_to_disk = 1;
                                    memdump_record_count++;
                                    
                                    register_memdump(sha1, pid);
                                    
                                    printf("[+] Registered memory dump %d: %s (SHA1: %s)\n",
                                           memdump_record_count, filename, sha1);
                                }
                            } else {
                                printf("[!] Skipping duplicate dump (SHA1: %s already captured)\n", sha1);
                                unlink(dump_file);
                            }
                            
                            pthread_mutex_unlock(&memdump_mutex);
                        }
                    }
                } else {
                    fprintf(stderr, "[-] Write failed for %s\n", dump_file);
                    unlink(dump_file);
                }
            } else {
                fprintf(stderr, "[-] Cannot read memory region 0x%lx-0x%lx: %s\n",
                        start, end, strerror(errno));
                close(out_fd);
                unlink(dump_file);
            }
            
            free(buffer);
        }
    }
    
    fclose(maps);
    
    if (dumps_created > 0) {
        printf("[+] Created %d memory dumps from PID %d\n", dumps_created, pid);
    }
}

// Dump all memory regions of a process for dynamic unpacking analysis
// Creates a single contiguous dump file for easy reverse engineering
void dump_full_process_memory(pid_t pid) {
    // Validate PID
    if (pid <= 0 || pid > 4194304) {
        fprintf(stderr, "[-] Invalid PID for memory dump: %d\n", pid);
        return;
    }
    
    // Check if process exists before attempting dump
    char proc_check[64];
    snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
    if (access(proc_check, F_OK) != 0) {
        fprintf(stderr, "[-] Process %d does not exist, skipping dump\n", pid);
        return;
    }
    
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        fprintf(stderr, "[-] Cannot open maps for PID %d (process may have exited)\n", pid);
        return;
    }

    // Get process name for dump metadata
    char comm[256] = "unknown";
    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *comm_file = fopen(comm_path, "r");
    if (comm_file) {
        if (fgets(comm, sizeof(comm), comm_file)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n')
                comm[len-1] = '\0';
        }
        fclose(comm_file);
    }
    
    // Skip dumping if process is "sh" - we want the loader, not the shell
    if (strcmp(comm, "sh") == 0 || strstr(comm, "bash") != NULL) {
        printf("[!] Skipping dump of PID %d - process is shell (%s), not loader\n", pid, comm);
        fclose(maps);
        return;
    }

    // Create single dump file and map file
    char dump_file[512], map_file[512];
    
    // If sandbox mode, save to sandbox directory
    if (sandbox_mode && strlen(sandbox_memdump_dir) > 0) {
        snprintf(dump_file, sizeof(dump_file), "%s/memdump_%d_%s.bin", sandbox_memdump_dir, pid, comm);
        snprintf(map_file, sizeof(map_file), "%s/memdump_%d_%s.map", sandbox_memdump_dir, pid, comm);
    } else {
        snprintf(dump_file, sizeof(dump_file), "memdump_%d_%s.bin", pid, comm);
        snprintf(map_file, sizeof(map_file), "memdump_%d_%s.map", pid, comm);
    }
    
    printf("[+] Dumping full memory for PID %d (%s) to %s\n", pid, comm, dump_file);

    int dump_fd = open(dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dump_fd < 0) {
        perror("[-] create dump file");
        fclose(maps);
        return;
    }

    // Create map file for reference (shows offset -> address mapping)
    FILE *mapfile = fopen(map_file, "w");
    if (mapfile) {
        fprintf(mapfile, "Memory dump for PID %d (%s)\n", pid, comm);
        fprintf(mapfile, "Dump file: %s\n", dump_file);
        fprintf(mapfile, "========================================\n\n");
        fprintf(mapfile, "Format: [Offset in dump] -> [Virtual Address Range] [Perms] [Size] [Path]\n\n");
    }

    int mem_fd = -1;
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        fprintf(stderr, "[-] open /proc/PID/mem failed for PID %d: %s\n", pid, strerror(errno));
        fclose(maps);
        close(dump_fd);
        if (mapfile) fclose(mapfile);
        return;
    }
    
    printf("[DEBUG] Successfully opened /proc/%d/mem (fd=%d)\n", pid, mem_fd);

    char line[MAX_LINE];  // Use MAX_LINE (4096) instead of 512 for long paths
    int region_count = 0;
    int readable_regions = 0;
    int max_regions = 500;  // Limit number of regions to dump to prevent excessive processing
    size_t total_dumped = 0;
    size_t current_offset = 0;
    
    // Use smaller buffer (1MB) to reduce memory pressure and stack overflow risk
    size_t buffer_size = 1024 * 1024;  // 1MB buffer
    char *buffer = malloc(buffer_size);
    
    if (!buffer) {
        fprintf(stderr, "[-] malloc buffer failed for PID %d\n", pid);
        close(mem_fd);
        close(dump_fd);
        fclose(maps);
        if (mapfile) fclose(mapfile);
        return;
    }

    while (fgets(line, sizeof(line), maps) && region_count < max_regions) {
        // Periodically check if process still exists
        if (region_count % 50 == 0 && region_count > 0) {
            if (access(proc_check, F_OK) != 0) {
                fprintf(stderr, "[-] Process %d exited during dump\n", pid);
                break;
            }
        }
        
        unsigned long start, end;
        char perms[5], path[MAX_LINE] = "";
        
        int items = sscanf(line, "%lx-%lx %4s %*x %*s %*d %4095[^\n]", &start, &end, perms, path);
        if (items < 3) continue;

        // Skip regions without read permission
        if (perms[0] != 'r') continue;
        
        readable_regions++;

        size_t size = end - start;
        if (size == 0 || size > 1024*1024*1024) continue;  // Skip invalid/huge regions
        
        if (region_count == 0) {
            printf("[DEBUG] First readable region: %lx-%lx %s size=%zu path=%s\n", start, end, perms, size, path);
        }

        // Write to map file with current offset in dump
        if (mapfile) {
            fprintf(mapfile, "[0x%016zx] -> 0x%016lx-0x%016lx %s %10zu bytes %s",
                    current_offset, start, end, perms, size, path);
        }

        // Seek to region start in process memory
        if (lseek(mem_fd, start, SEEK_SET) == -1) {
            if (mapfile) fprintf(mapfile, " [SEEK FAILED]\n");
            region_count++;
            continue;
        }

        // Read and write region in chunks (use smaller chunks to prevent issues)
        size_t bytes_dumped = 0;
        size_t remaining = size;
        int read_failed = 0;
        
        while (remaining > 0 && !read_failed) {
            size_t chunk_size = (remaining > buffer_size) ? buffer_size : remaining;
            
            // Use errno to detect specific read errors
            errno = 0;
            ssize_t bytes = read(mem_fd, buffer, chunk_size);
            
            if (bytes <= 0) {
                // EIO = I/O error (common when process is modifying memory)
                // EFAULT = Bad address (process unmapped region)
                if (errno == EIO || errno == EFAULT) {
                    // Log for first region to help debug
                    if (region_count == 0) {
                        printf("[DEBUG] First region read failed: %s (errno=%d)\n", strerror(errno), errno);
                    }
                    read_failed = 1;
                } else if (errno != 0) {
                    // Other error - log it
                    printf("[DEBUG] Read error at region %d: %s (errno=%d)\n", region_count, strerror(errno), errno);
                    if (mapfile) fprintf(mapfile, " [READ ERROR: %s]", strerror(errno));
                    read_failed = 1;
                } else {
                    // bytes == 0 with no error means EOF
                    if (region_count == 0) {
                        printf("[DEBUG] First region returned 0 bytes (EOF)\n");
                    }
                    read_failed = 1;
                }
                break;
            }
            
            ssize_t written = write(dump_fd, buffer, bytes);
            if (written != bytes) {
                read_failed = 1;
                break;
            }
            
            bytes_dumped += bytes;
            remaining -= bytes;
        }

        if (bytes_dumped > 0) {
            total_dumped += bytes_dumped;
            current_offset += bytes_dumped;
            
            if (mapfile) {
                fprintf(mapfile, " [DUMPED %zu bytes]\n", bytes_dumped);
            }
        } else {
            if (mapfile) fprintf(mapfile, " [READ FAILED]\n");
        }

        region_count++;
    }

    free(buffer);
    close(mem_fd);
    close(dump_fd);
    fclose(maps);
    
    printf("[DEBUG] Dump complete: %d total regions, %d readable, %zu bytes dumped\n", 
           region_count, readable_regions, total_dumped);
    
    if (mapfile) {
        fprintf(mapfile, "\n========================================\n");
        fprintf(mapfile, "Total regions: %d\n", region_count);
        fprintf(mapfile, "Total dumped: %.2f MB\n", total_dumped / (1024.0 * 1024.0));
        fprintf(mapfile, "\nUsage:\n");
        fprintf(mapfile, "  - Load %s into your reverse engineering tool\n", dump_file);
        fprintf(mapfile, "  - Use this map file to locate specific memory regions\n");
        fprintf(mapfile, "  - Virtual address 0xADDR is at file offset shown in brackets\n");
        fclose(mapfile);
    }

    printf("[+] Full memory dump complete: %d regions, %.2f MB dumped\n", region_count, total_dumped / (1024.0 * 1024.0));
    printf("[+] Dump file: %s\n", dump_file);
    printf("[+] Memory map: %s\n", map_file);
    
    // DON'T mark as dumped here - we may dump again at execve
    // Deduplication handled by checking comm name (avoid dumping "sh")
    
    // Calculate hashes of memory dump
    char sha1[41], sha256[65];
    if (calculate_sha1(dump_file, sha1) == 0) {
        printf("[+] Memory dump SHA-1: %s\n", sha1);
        
        // Report to JSON if in sandbox mode - use centralized deduplication
        if (sandbox_mode) {
            pthread_mutex_lock(&memdump_mutex);
            
            // Use the same deduplication system as dump_memfd_files/dump_executable_mappings
            if (!is_duplicate_memdump(sha1)) {
                if (memdump_record_count < MAX_MEMDUMP_RECORDS) {
                    const char *filename = strrchr(dump_file, '/');
                    filename = filename ? filename + 1 : dump_file;
                    
                    memdump_records[memdump_record_count].pid = pid;
                    strncpy(memdump_records[memdump_record_count].filename, filename, 
                            sizeof(memdump_records[0].filename) - 1);
                    memdump_records[memdump_record_count].size = total_dumped;
                    strncpy(memdump_records[memdump_record_count].sha1, sha1, 
                            sizeof(memdump_records[0].sha1) - 1);
                    memdump_records[memdump_record_count].timestamp = time(NULL);
                    memdump_records[memdump_record_count].written_to_disk = 1;
                    memdump_record_count++;
                    
                    // Register to prevent future duplicates
                    register_memdump(sha1, pid);
                    
                    printf("[+] Registered memory dump %d: %s (SHA1: %s)\n", 
                           memdump_record_count, filename, sha1);
                }
            } else {
                printf("[!] Skipping duplicate dump (SHA1: %s already captured)\n", sha1);
                // Delete the duplicate file to save disk space
                unlink(dump_file);
                unlink(map_file);
            }
            
            pthread_mutex_unlock(&memdump_mutex);
        }
    }
    if (calculate_sha256(dump_file, sha256) == 0) {
        printf("[+] Memory dump SHA-256: %s\n", sha256);
    }
    
    // Optionally scan the full dump with YARA
    if (yara_rules_path) {
        printf("[+] Scanning full dump with YARA...\n");
        scan_with_yara(dump_file);
    }
}

void print_process_info(pid_t pid) {
    char cmdline_path[64], comm_path[64];
    char cmdline[2048] = "";
    char comm[256] = "";
    
    // Read process name from /proc/PID/comm
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *comm_file = fopen(comm_path, "r");
    if (comm_file) {
        if (fgets(comm, sizeof(comm), comm_file)) {
            // Remove trailing newline
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n')
                comm[len-1] = '\0';
        }
        fclose(comm_file);
    }
    
    // Read command line from /proc/PID/cmdline
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    FILE *cmdline_file = fopen(cmdline_path, "r");
    if (cmdline_file) {
        size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
        fclose(cmdline_file);
        
        if (len > 0) {
            cmdline[len] = '\0';
            // Replace null bytes with spaces for display
            for (size_t i = 0; i < len - 1; i++) {
                if (cmdline[i] == '\0')
                    cmdline[i] = ' ';
            }
        }
    }
    
    // Only print if we got valid info
    if (!quiet_mode && (strlen(comm) > 0 || strlen(cmdline) > 0)) {
        printf("[INFO] Process: %s", strlen(comm) > 0 ? comm : "<unknown>");
        if (strlen(cmdline) > 0)
            printf(" | Cmdline: %s", cmdline);
        printf("\n");
    }
}

void check_exe_link(pid_t pid) {
    char exe_path[64], exe_target[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
    if (len == -1) {
        // Process likely exited before we could read it - this is normal
        pthread_mutex_lock(&stats_mutex);
        race_conditions++;
        pthread_mutex_unlock(&stats_mutex);
        if (!quiet_mode) {
            // Only print if it's NOT a permission denied or no such file error
            if (errno != ENOENT && errno != EACCES) {
                printf("[!] WARNING: /proc/%d/exe unreadable: %s\n", pid, strerror(errno));
            }
        }
        return;
    }
    exe_target[len] = '\0';
    
    // CRITICAL: memfd execution detection
    if (strstr(exe_target, "memfd:") || strstr(exe_target, "anon_inode")) {
        // Process is executing from memfd - VERY suspicious
        pthread_mutex_lock(&stats_mutex);
        suspicious_found++;
        pthread_mutex_unlock(&stats_mutex);
        printf("[!] CRITICAL: Process executing from memfd | PID=%d | exe=%s\n", pid, exe_target);
        
        // Mark this PID for tracking
        mark_memfd_exec_pid(pid);
        
        // IMMEDIATE DUMP: This is the fexecve'd process with decrypted payload!
        if (full_dump) {
            if (sandbox_mode && !is_sandbox_process(pid)) {
                printf("[DEBUG] PID=%d is memfd but not in sandbox tree, skipping\n", pid);
            } else {
                // BULLETPROOF MULTI-STRATEGY:
                // 1. Try dumping from /proc/PID/fd (works if fd still open - rare after fexecve)
                printf("[+] Dumping memfd files from PID=%d...\n", pid);
                dump_memfd_files(pid);
                
                // 2. CRITICAL: Dump from /proc/PID/maps (ALWAYS works after fexecve!)
                //    This is where the decrypted ELF payload lives in memory
                printf("[+] Scanning executable memory regions in PID %d...\n", pid);
                dump_executable_mappings(pid);
            }
        } else {
            printf("[DEBUG] full_dump not enabled, skipping dump\n");
        }
    } else if (strstr(exe_target, "(deleted)")) {
        // Running from deleted file - could be legitimate (updated binary) or suspicious
        if (!quiet_mode) {
            printf("[WARN] Process running from deleted file PID %d: %s\n", pid, exe_target);
        }
        
        // STRATEGY 5: Dump deleted binaries - this catches executables that delete themselves
        // This is a common anti-forensics technique used by malware
        if (full_dump && sandbox_mode && is_sandbox_process(pid)) {
            printf("[+] Detecting deleted binary in PID %u - scanning for executable regions...\n", pid);
            
            // Scan /proc/PID/maps for executable regions to dump
            // We can't read the original file, but we can dump it from memory
            char maps_path[64];
            snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
            FILE *maps = fopen(maps_path, "r");
            if (maps) {
                char line[1024];
                while (fgets(line, sizeof(line), maps)) {
                    unsigned long start, end;
                    char perms[5];
                    char path[512] = "";
                    
                    if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) >= 3) {
                        // Look for the main executable mapping (usually first r-xp region)
                        if (strchr(perms, 'x') != NULL && strstr(path, "(deleted)") != NULL) {
                            size_t region_size = end - start;
                            // Only dump reasonably sized regions (avoid huge mappings)
                            if (region_size > 100 && region_size < 50*1024*1024) {
                                printf("[+] Dumping deleted binary region: 0x%lx-0x%lx (%zu bytes)\n", 
                                       start, end, region_size);
                                dump_memory_region(pid, start, end, 0);
                            }
                        }
                    }
                }
                fclose(maps);
            }
        }
    }
}

void check_env_vars(pid_t pid) {
    char env_path[64];
    snprintf(env_path, sizeof(env_path), "/proc/%d/environ", pid);

    FILE *env_file = fopen(env_path, "r");
    if (!env_file) return;

    char env_buf[8192];
    size_t len = fread(env_buf, 1, sizeof(env_buf) - 1, env_file);
    fclose(env_file);

    if (len <= 0) return;
    env_buf[len] = '\0';

    char *p = env_buf;
    while (p < env_buf + len) {
        if (strstr(p, "LD_PRELOAD=") == p || strstr(p, "LD_LIBRARY_PATH=") == p) {
            printf("[!] Suspicious ENV in PID %d: %s\n", pid, p);
            
            // STRATEGY 6: Dump LD_PRELOAD libraries - this catches library injection
            if (full_dump && sandbox_mode && is_sandbox_process(pid)) {
                // Extract the library path from LD_PRELOAD=<path>
                const char *preload_value = p + strlen("LD_PRELOAD=");
                if (strlen(preload_value) > 0 && preload_value[0] == '/') {
                    printf("[+] Detecting LD_PRELOAD library: %s\n", preload_value);
                    
                    // Scan /proc/PID/maps to find the loaded library and dump it
                    char maps_path[64];
                    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
                    FILE *maps = fopen(maps_path, "r");
                    if (maps) {
                        char line[1024];
                        while (fgets(line, sizeof(line), maps)) {
                            unsigned long start, end;
                            char perms[5];
                            char path[512] = "";
                            
                            if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) >= 3) {
                                // Look for the preloaded library's executable regions
                                if (strchr(perms, 'x') != NULL && strstr(path, preload_value) != NULL) {
                                    size_t region_size = end - start;
                                    if (region_size > 100 && region_size < 50*1024*1024) {
                                        printf("[+] Dumping LD_PRELOAD library region: 0x%lx-0x%lx (%zu bytes)\n", 
                                               start, end, region_size);
                                        dump_memory_region(pid, start, end, 0);
                                    }
                                }
                            }
                        }
                        fclose(maps);
                    }
                }
            }
        }
        p += strlen(p) + 1;
    }
}

// Check if process should be ignored (Docker/container infrastructure)
int should_ignore_process(pid_t pid) {
    char comm_path[64], comm[256] = "";
    
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
    FILE *comm_file = fopen(comm_path, "r");
    if (!comm_file) return 0;
    
    if (fgets(comm, sizeof(comm), comm_file)) {
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n')
            comm[len-1] = '\0';
    }
    fclose(comm_file);
    
    // Ignore Docker/container infrastructure processes
    if (strstr(comm, "runc") || 
        strstr(comm, "containerd-shim") ||
        strstr(comm, "docker-proxy") ||
        strstr(comm, "dockerd") ||
        strcmp(comm, "containerd") == 0) {
        return 1;
    }
    
    return 0;
}

// Helper function to check if path is a legitimate system binary/library
static int is_legitimate_path(const char *path) {
    if (strlen(path) == 0) return 0;  // Anonymous
    
    // Whitelist common legitimate paths
    const char *legitimate_prefixes[] = {
        "/usr/lib", "/lib", "/lib64",           // System libraries
        "/usr/bin", "/bin", "/sbin",            // System binaries
        "/opt/",                                 // Optional software
        "/usr/local/",                           // User-installed software
        "/snap/",                                // Snap packages
        "/var/lib/snapd",                        // Snap runtime
        "[vdso]", "[vvar]", "[vsyscall]",       // Kernel pages
        "[stack]", "[heap]"                      // Process memory
    };
    
    for (size_t i = 0; i < sizeof(legitimate_prefixes)/sizeof(legitimate_prefixes[0]); i++) {
        if (strstr(path, legitimate_prefixes[i]) == path) {  // Starts with prefix
            return 1;
        }
    }
    return 0;
}

// Check if path matches high-risk malware locations
static int is_suspicious_file_location(const char *path, int *risk_score, char *category) {
    *risk_score = 0;
    category[0] = '\0';
    
    // Whitelist eBPF IPC pipe (our own monitoring infrastructure)
    if (strstr(path, "/tmp/ebpf_") && strstr(path, "_pipe")) {
        return 0;  // Not suspicious - it's our pipe
    }
    
    // Extract filename to check for hidden files
    const char *filename = strrchr(path, '/');
    filename = filename ? filename + 1 : path;
    int is_hidden = (filename[0] == '.');
    
    // Critical persistence locations (VERY HIGH risk)
    if (strstr(path, "/etc/cron") || 
        strstr(path, "/var/spool/cron") ||
        strstr(path, "/etc/init.d/") ||
        strstr(path, "/etc/rc.local") ||
        strstr(path, "/etc/systemd/system/") ||
        strstr(path, "/etc/ld.so.preload")) {
        *risk_score = 95;
        strcpy(category, "persistence");
        return 1;
    }
    
    // Temporary/staging locations (HIGH risk)
    if (strstr(path, "/tmp/") || 
        strstr(path, "/var/tmp/") ||
        strstr(path, "/dev/shm/")) {
        *risk_score = is_hidden ? 85 : 70;
        strcpy(category, "temp_staging");
        return 1;
    }
    
    // Library hijacking (VERY HIGH risk)
    if ((strstr(path, "/lib/") || strstr(path, "/lib64/") || 
         strstr(path, "/usr/lib/") || strstr(path, "/usr/local/lib/")) &&
        (strstr(path, ".so") != NULL)) {
        // Check if it's in a writable subdirectory or hidden
        if (is_hidden || strstr(path, "/tmp") || strstr(path, "local")) {
            *risk_score = 90;
            strcpy(category, "library_hijack");
            return 1;
        }
    }
    
    // User-level persistence (MEDIUM-HIGH risk)
    if (strstr(path, "/.config/") ||
        strstr(path, "/.cache/") ||
        strstr(path, "/.local/share/") ||
        strstr(path, "/.bashrc") ||
        strstr(path, "/.bash_profile") ||
        strstr(path, "/.profile") ||
        strstr(path, "/.ssh/")) {
        *risk_score = is_hidden ? 75 : 60;
        strcpy(category, "user_persistence");
        return 1;
    }
    
    // Boot persistence (CRITICAL)
    if (strstr(path, "/boot/")) {
        *risk_score = 100;
        strcpy(category, "boot_persistence");
        return 1;
    }
    
    // Runtime/memory locations (HIGH risk)
    if (strstr(path, "/run/") ||
        (strstr(path, "/proc/") && (strstr(path, "/fd/") || strstr(path, "/mem")))) {
        *risk_score = 80;
        strcpy(category, "runtime_fileless");
        return 1;
    }
    
    // Root staging area (HIGH risk)
    if (strstr(path, "/root/") && !strstr(path, "/root/.cache/")) {
        *risk_score = is_hidden ? 85 : 65;
        strcpy(category, "root_staging");
        return 1;
    }
    
    // Home directories (MEDIUM risk if suspicious)
    if (strstr(path, "/home/")) {
        // Higher risk for hidden files or scripts
        if (is_hidden || strstr(path, ".sh") || strstr(path, ".py") || strstr(path, ".pl")) {
            *risk_score = 55;
            strcpy(category, "user_staging");
            return 1;
        }
    }
    
    // Hidden files anywhere (MEDIUM risk)
    if (is_hidden && strlen(filename) > 1) {  // Ignore single '.' entries
        *risk_score = 50;
        strcpy(category, "hidden_file");
        return 1;
    }
    
    return 0;
}

// Monitor file creation, modification, and access by sandbox process
static void check_file_operations(pid_t pid) {
    if (!sandbox_mode || !is_sandbox_process(pid)) return;
    
    // Verify process still exists before proceeding
    char proc_check[64];
    snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
    if (access(proc_check, F_OK) != 0) {
        return;  // Process exited, skip
    }
    
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    
    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir) return;
    
    struct dirent *entry;
    int fd_count = 0;
    int max_fds = 1024;  // Limit to prevent excessive iteration
    while ((entry = readdir(fd_dir)) != NULL && fd_count < max_fds) {
        if (entry->d_name[0] == '.') continue;
        fd_count++;
        
        // Re-check process existence periodically
        if (fd_count % 100 == 0) {
            if (access(proc_check, F_OK) != 0) {
                closedir(fd_dir);
                return;  // Process died during iteration
            }
        }
        
        char link_path[128];
        char target[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, entry->d_name);
        
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len <= 0 || len >= (ssize_t)sizeof(target)) {
            continue;  // readlink failed or buffer overflow
        }
        target[len] = '\0';
        
        // Skip non-file descriptors
        if (strstr(target, "socket:") || strstr(target, "pipe:") || 
            strstr(target, "anon_inode:") || target[0] != '/') {
            continue;
        }
        
        // Check if this is a suspicious location
        int risk_score;
        char category[64];
        if (is_suspicious_file_location(target, &risk_score, category)) {
            // Check file access mode to determine operation type
            char fdinfo_path[128];
            snprintf(fdinfo_path, sizeof(fdinfo_path), "/proc/%d/fdinfo/%s", pid, entry->d_name);
            
            FILE *fdinfo = fopen(fdinfo_path, "r");
            const char *op_type = "accessed";
            if (fdinfo) {
                char line[256];
                while (fgets(line, sizeof(line), fdinfo)) {
                    if (strstr(line, "flags:")) {
                        // O_WRONLY=01, O_RDWR=02, O_CREAT=0100
                        unsigned int flags;
                        if (sscanf(line, "flags: %o", &flags) == 1) {
                            if (flags & 0100) {  // O_CREAT
                                op_type = "created";
                            } else if (flags & 03) {  // O_WRONLY | O_RDWR
                                op_type = "written";
                            }
                        }
                        break;
                    }
                }
                fclose(fdinfo);
            }
            
            printf("[SANDBOX] File %s: %s (PID=%d, Risk=%d, Category=%s)\n", 
                   op_type, target, pid, risk_score, category);
                   
            report_file_operation(pid, op_type, target, risk_score, category);
            
            pthread_mutex_lock(&stats_mutex);
            files_created++;
            if (risk_score >= 80) {
                suspicious_found++;  // High-risk file operation
            }
            pthread_mutex_unlock(&stats_mutex);
        }
    }
    closedir(fd_dir);
}

// Monitor network connections by sandbox process
static void check_network_connections(pid_t pid) {
    if (!sandbox_mode || !is_sandbox_process(pid)) return;
    
    // Verify process still exists before proceeding
    char proc_check[64];
    snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
    if (access(proc_check, F_OK) != 0) {
        return;  // Process exited, skip
    }
    
    // Parse /proc/net/tcp and /proc/net/udp for actual network connections
    const char *net_files[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    
    for (int i = 0; i < 4; i++) {
        FILE *f = fopen(net_files[i], "r");
        if (!f) continue;
        
        char line[MAX_LINE];  // Use MAX_LINE for potential IPv6 addresses and long paths
        // Skip header
        if (fgets(line, sizeof(line), f) == NULL) {
            fclose(f);
            continue;
        }
        
        // Parse each connection
        while (fgets(line, sizeof(line), f)) {
            unsigned long local_addr, rem_addr;
            unsigned int local_port, rem_port, inode, uid;
            
            // Parse line format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
            int parsed = sscanf(line, "%*d: %lx:%x %lx:%x %*x %*x:%*x %*x:%*x %*x %u %*d %u",
                              &local_addr, &local_port, &rem_addr, &rem_port, &uid, &inode);
            
            if (parsed >= 6 && inode > 0) {
                // Check if this inode belongs to our PID
                char fd_path[64];
                snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
                
                DIR *fd_dir = opendir(fd_path);
                if (!fd_dir) {
                    // Process likely exited during scan
                    fclose(f);
                    return;
                }
                
                struct dirent *entry;
                int fd_count = 0;
                int max_fds = 512;  // Limit FD iteration in network check
                while ((entry = readdir(fd_dir)) != NULL && fd_count < max_fds) {
                    if (entry->d_name[0] == '.') continue;
                    fd_count++;
                    
                    // Check process existence every 50 iterations
                    if (fd_count % 50 == 0 && access(proc_check, F_OK) != 0) {
                        closedir(fd_dir);
                        fclose(f);
                        return;
                    }
                    
                    char link_path[128], target[256];
                    snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, entry->d_name);
                    
                    ssize_t len = readlink(link_path, target, sizeof(target) - 1);
                    if (len > 0) {
                        target[len] = '\0';
                        
                        // Check if this socket inode matches
                        char socket_str[64];
                        snprintf(socket_str, sizeof(socket_str), "socket:[%u]", inode);
                        
                        if (strstr(target, socket_str) != NULL) {
                            // Found a real network connection for this PID
                            const char *proto = (i < 2) ? "TCP" : "UDP";
                            char local_str[64], remote_str[64];
                            
                            // Format addresses (IPv4 only for now - IPv6 needs different parsing)
                            snprintf(local_str, sizeof(local_str), "%lu.%lu.%lu.%lu:%u",
                                    local_addr & 0xFF, (local_addr >> 8) & 0xFF,
                                    (local_addr >> 16) & 0xFF, (local_addr >> 24) & 0xFF,
                                    local_port);
                            snprintf(remote_str, sizeof(remote_str), "%lu.%lu.%lu.%lu:%u",
                                    rem_addr & 0xFF, (rem_addr >> 8) & 0xFF,
                                    (rem_addr >> 16) & 0xFF, (rem_addr >> 24) & 0xFF,
                                    rem_port);
                            
                            // Only log if remote address is not 0.0.0.0 (actual connection, not listening)
                            if (rem_addr != 0) {
                                printf("[SANDBOX] Network connection: PID=%d %s %s -> %s\n",
                                       pid, proto, local_str, remote_str);
                                report_network_activity(pid, proto, local_str, remote_str);
                                
                                pthread_mutex_lock(&stats_mutex);
                                sockets_created++;
                                pthread_mutex_unlock(&stats_mutex);
                            }
                            break;
                        }
                    }
                }
                closedir(fd_dir);
            }
        }
        fclose(f);
    }
}

void scan_maps_and_dump(pid_t pid) {
    if (pid <= 0 || pid > 4194304) {
        return;  // Invalid PID
    }
    
    char maps_path[64];
    int n = snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    if (n < 0 || n >= sizeof(maps_path)) {
        return;  // Buffer error
    }

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        // Process likely exited - this is a race condition, not an error
        pthread_mutex_lock(&stats_mutex);
        race_conditions++;
        pthread_mutex_unlock(&stats_mutex);
        return;
    }

    // Check if this is a sandbox process
    if (sandbox_mode && is_sandbox_process(pid)) {
        // Verify process still exists before collecting info
        char proc_check[64];
        snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
        if (access(proc_check, F_OK) != 0) {
            fclose(maps);
            return;  // Process exited during scan
        }
        
        // Double-check maps file is still open
        if (!maps || ferror(maps)) {
            if (maps) fclose(maps);
            return;
        }
        
        pthread_mutex_lock(&stats_mutex);
        sandbox_events++;
        pthread_mutex_unlock(&stats_mutex);
        printf("[SANDBOX] Monitoring PID %d\n", pid);
        
        // Get process info for reporting - with comprehensive error checking
        char comm[256] = "unknown", cmdline[1024] = "", exe_path[512] = "";
        char comm_path[64], cmdline_path[64], exe_link[64];
        
        // Verify process still exists before reading files
        if (access(proc_check, F_OK) != 0) {
            fclose(maps);
            return;
        }
        
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *comm_file = fopen(comm_path, "r");
        if (comm_file) {
            if (fgets(comm, sizeof(comm), comm_file)) {
                comm[sizeof(comm) - 1] = '\0';  // Ensure null termination
                size_t len = strnlen(comm, sizeof(comm));
                if (len > 0 && len < sizeof(comm) && comm[len-1] == '\n') {
                    comm[len-1] = '\0';
                }
            }
            fclose(comm_file);
        }
        
        // Check again before next read
        if (access(proc_check, F_OK) != 0) {
            fclose(maps);
            return;
        }
        
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *cmdline_file = fopen(cmdline_path, "r");
        if (cmdline_file) {
            size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
            if (len > 0 && len < sizeof(cmdline)) {
                cmdline[len] = '\0';  // Null terminate
                // Replace null bytes with spaces for display
                for (size_t i = 0; i < len - 1 && i < sizeof(cmdline) - 1; i++) {
                    if (cmdline[i] == '\0') cmdline[i] = ' ';
                }
                // Trim trailing spaces
                while (len > 0 && cmdline[len-1] == ' ') {
                    cmdline[--len] = '\0';
                }
            } else {
                // Fallback: use comm if cmdline is empty
                strncpy(cmdline, comm, sizeof(cmdline) - 1);
                cmdline[sizeof(cmdline) - 1] = '\0';
            }
            fclose(cmdline_file);
        } else {
            // Fallback: use comm if cmdline file can't be opened
            strncpy(cmdline, comm, sizeof(cmdline) - 1);
            cmdline[sizeof(cmdline) - 1] = '\0';
        }
        
        // Check again before readlink
        if (access(proc_check, F_OK) != 0) {
            fclose(maps);
            return;
        }
        
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len > 0 && len < (ssize_t)sizeof(exe_path)) {
            exe_path[len] = '\0';
        } else {
            exe_path[0] = '\0';
        }
        
        // Get PPID - read entire stat line and parse carefully
        pid_t ppid = 0;
        if (access(proc_check, F_OK) == 0) {
            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
            FILE *stat_file = fopen(stat_path, "r");
            if (stat_file) {
                char stat_line[2048];
                if (fgets(stat_line, sizeof(stat_line), stat_file)) {
                    // Format: pid (comm) state ppid ...
                    // Find last ')' to handle comm with spaces
                    char *p = strrchr(stat_line, ')');
                    if (p && (p - stat_line) < (ssize_t)sizeof(stat_line) - 10) {
                        sscanf(p + 1, " %*c %d", &ppid);
                    }
                }
                fclose(stat_file);
            }
        }
        
        // Final check before reporting
        if (access(proc_check, F_OK) != 0) {
            fclose(maps);
            return;
        }
        
        report_sandbox_process(pid, ppid, comm, exe_path, cmdline);
        
        // Wrap these in process existence checks to prevent crashes
        char proc_check2[64];
        snprintf(proc_check2, sizeof(proc_check2), "/proc/%d", pid);
        if (access(proc_check2, F_OK) == 0) {
            check_file_operations(pid);
        }
        
        if (access(proc_check2, F_OK) == 0) {
            check_network_connections(pid);
        }
    }

    // First read process info and check for obvious red flags
    // check_exe_link must run in all modes to detect memfd execution
    check_exe_link(pid);
    check_env_vars(pid);
    
    // CRITICAL: Check if this PID has memfd flag set (from MEMFD_CREATE event)
    // For memfd processes, we use a MULTI-STRATEGY approach:
    // 1. Try dump from /proc/PID/fd (works if fd still open)
    // 2. Dump from /proc/PID/maps (works after fexecve when fd is consumed)
    int has_memfd = 0;
    if (full_dump && sandbox_mode && is_sandbox_process(pid)) {
        pthread_mutex_lock(&memfd_pids_mutex);
        for (int i = 0; i < memfd_pids_count; i++) {
            if (memfd_pids[i] == pid) {
                has_memfd = 1;
                break;
            }
        }
        pthread_mutex_unlock(&memfd_pids_mutex);
        
        if (has_memfd) {
            printf("[+] PID %d has memfd flag - using multi-strategy dump...\n", pid);
            // Try fd-based dump first (might fail if fexecve already consumed it)
            dump_memfd_files(pid);
        }
    }
    
    // BULLETPROOF STRATEGY: Dump executable memory regions
    // This catches:
    // - XOR'd ELFs and UPX unpacked code
    // - memfd processes AFTER fexecve (fd consumed but memory remains!)
    // - Runtime payloads
    if (full_dump && sandbox_mode && is_sandbox_process(pid)) {
        if (has_memfd) {
            printf("[+] Dumping memfd process from memory maps (post-fexecve)...\n");
        }
        dump_executable_mappings(pid);
    }
    
    // Print process info only in verbose mode
    if (!quiet_mode) {
        print_process_info(pid);
    }

    char line[MAX_LINE];
    int suspicious_count = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char path[MAX_LINE] = "";

        // Parse maps line: address range, permissions, and optional path
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) < 3)
            continue;

        int is_executable = strchr(perms, 'x') != NULL;
        int is_writable = strchr(perms, 'w') != NULL;
        int is_readable = strchr(perms, 'r') != NULL;
        int is_rwx = is_readable && is_writable && is_executable;
        int is_anonymous = (strlen(path) == 0);
        
        // Detection criteria for malware techniques:
        int suspicious = 0;
        const char *reason = NULL;
        
        // Skip detection for legitimate system paths (libraries, binaries)
        // This significantly reduces false positives from JIT compilers, etc.
        int is_legit = is_legitimate_path(path);
        
        // 1. RWX regions (code injection, self-modifying code)
        // BUT: Many legitimate programs use RWX (JIT compilers: Java, Node.js, browsers)
        // Only flag RWX in non-system locations or anonymous memory
        if (is_rwx && !is_legit) {
            suspicious = 1;
            reason = "RWX permissions (writable+executable)";
        }
        // 2. Executable regions in suspicious paths
        else if (is_executable && (
            strstr(path, "memfd:") != NULL ||           // memfd_create execution
            strstr(path, "/dev/shm") != NULL ||         // shared memory execution  
            strstr(path, "/proc/self") != NULL ||       // self-reference execution
            strstr(path, "/tmp/") != NULL ||            // tmp execution
            strstr(path, "anon_inode") != NULL)) {      // anonymous inode
            suspicious = 1;
            reason = "Executable memory in suspicious location";
        }
        // 3. Anonymous executable mappings (reflective loading, process hollowing)
        // BUT exclude legitimate kernel pages: [stack], [vdso], [vvar], [vsyscall]
        // Also exclude vsyscall page by address range (0xffffffffff600000-0xffffffffff601000)
        else if (is_executable && is_anonymous && 
                 strstr(path, "[stack]") == NULL && 
                 strstr(path, "[vdso]") == NULL && 
                 strstr(path, "[vvar]") == NULL &&
                 strstr(path, "[vsyscall]") == NULL &&
                 !(start >= 0xffffffffff600000UL && end <= 0xffffffffff601000UL)) {  // vsyscall page range
            suspicious = 1;
            reason = "Anonymous executable mapping (possible injection)";
        }
        // 4. Executable heap (shellcode execution)
        else if (is_executable && strstr(path, "[heap]") != NULL) {
            suspicious = 1;
            reason = "Executable heap (shellcode/injection)";
        }
        // 5. Large anonymous writable mappings (staged payloads) - only warn in verbose mode
        // NOTE: Disabled even in verbose mode during high-load - causes I/O delays
        // Re-enable only for targeted forensic analysis
        /*
        else if (!quiet_mode && is_writable && is_anonymous && (end - start) > 10*1024*1024 && // > 10MB
                 strstr(path, "[stack]") == NULL && strstr(path, "[heap]") == NULL) {
            // These could become executable later via mprotect
            printf("[WARN] Large anonymous writable region in PID %d: %lx-%lx (%s) size=%luMB\n", 
                   pid, start, end, perms, (end-start)/(1024*1024));
        }
        */

        if (suspicious) {
            // Check for duplicate before processing
            if (is_duplicate_alert(pid, start, end, reason)) {
                continue;  // Skip duplicate alert
            }
            
            suspicious_count++;
            pthread_mutex_lock(&stats_mutex);
            suspicious_found++;
            pthread_mutex_unlock(&stats_mutex);
            
            // Always print alerts, even in quiet mode
            if (quiet_mode) {
                // Compact format for quiet mode
                printf("[!] %s | PID=%d | %lx-%lx (%s) %s\n", reason, pid, start, end, perms, path);
            } else {
                printf("[!] ALERT: %s in PID %d\n", reason, pid);
                printf("[!]   Region: %lx-%lx (%s) %s\n", start, end, perms, path);
            }
            
            // Report to sandbox JSON if in sandbox mode
            if (sandbox_mode && strlen(sandbox_report_dir) > 0 && alerts_written < MAX_ALERTS_TO_FILE) {
                char alert_tmp[600];
                snprintf(alert_tmp, sizeof(alert_tmp), "%s/.alerts.tmp", sandbox_report_dir);
                FILE *af = fopen(alert_tmp, "a");
                if (af) {
                    // Escape strings separately to avoid buffer reuse
                    const char *esc_reason = json_escape(reason);
                    char reason_copy[256];
                    strncpy(reason_copy, esc_reason, sizeof(reason_copy) - 1);
                    reason_copy[sizeof(reason_copy) - 1] = '\0';
                    
                    const char *esc_path = json_escape(path);
                    
                    fprintf(af, "{\"pid\":%d,\"type\":\"%s\",\"region\":\"%lx-%lx\",\"perms\":\"%s\",\"path\":\"%s\",\"timestamp\":%ld}\n",
                            pid, reason_copy, start, end, perms, esc_path, time(NULL));
                    fflush(af);
                    fclose(af);
                    __sync_fetch_and_add(&alerts_written, 1);
                    
                    if (alerts_written == MAX_ALERTS_TO_FILE) {
                        fprintf(stderr, "[!] WARN: Alert limit (%d) reached, no more alerts will be written to file\n", MAX_ALERTS_TO_FILE);
                    }
                }
            }
            
            // Only dump individual regions if --mem_dump is enabled (but not full_dump)
            // full_dump will handle everything in one file later
            if (mem_dump && !full_dump) {
                // In quiet mode, skip dumping large regions to prevent I/O blocking
                dump_memory_region(pid, start, end, quiet_mode);
            }
        }
    }
    fclose(maps);
    
    // If full_dump is enabled, queue for async memory dumping (non-blocking)
    // In sandbox mode: only dump processes in the sandbox tree
    if (full_dump && suspicious_count > 0) {
        // Skip if not a sandbox process when in sandbox mode
        if (sandbox_mode && !is_sandbox_process(pid)) {
            // Not part of sandbox tree, skip dumping
            return;
        }
        
        // Check dump limit
        if (max_dumps > 0 && dumps_performed >= max_dumps) {
            if (!quiet_mode) {
                printf("[INFO] Maximum dump limit (%d) reached, skipping PID %d\n", max_dumps, pid);
            }
            return;
        }
        
        // Check if already dumped to prevent duplicates
        if (is_already_dumped(pid)) {
            // Already dumped, skip
        } else if (dump_queue_push(&dump_queue, pid) < 0) {
            if (!quiet_mode) {
                printf("[WARN] Dump queue full, skipping full dump for PID %d\n", pid);
            }
        } else {
            dumps_performed++;
            if (!quiet_mode) {
                if (max_dumps > 0) {
                    printf("[INFO] Queued PID %d for full memory dump (%d/%d)\n", 
                           pid, dumps_performed, max_dumps);
                } else {
                    printf("[INFO] Queued PID %d for full memory dump (%d/unlimited)\n", 
                           pid, dumps_performed);
                }
            }
        }
    }
    
    if (suspicious_count > 0 && !quiet_mode) {
        printf("[!] Total suspicious regions found: %d\n", suspicious_count);
    }
}

// Initialize event queue
void queue_init(event_queue_t *q) {
    memset(q, 0, sizeof(event_queue_t));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
    q->shutdown = 0;
}

// Non-blocking enqueue (returns 0 on success, -1 if full)
int queue_push(event_queue_t *q, pid_t pid, pid_t ppid) {
    pthread_mutex_lock(&q->mutex);
    
    if (q->count >= EVENT_QUEUE_SIZE) {
        // Queue full - drop event and track it
        pthread_mutex_lock(&stats_mutex);
        queue_drops++;
        pthread_mutex_unlock(&stats_mutex);
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    q->events[q->tail].pid = pid;
    q->events[q->tail].ppid = ppid;
    q->tail = (q->tail + 1) % EVENT_QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Blocking dequeue (returns 0 on success, -1 on shutdown)
int queue_pop(event_queue_t *q, event_data_t *event) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }
    
    if (q->shutdown && q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    *event = q->events[q->head];
    q->head = (q->head + 1) % EVENT_QUEUE_SIZE;
    q->count--;
    
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

// Post-execve dump thread for fexecve'd processes
// Spawned when EXECVE event detected after memfd_create
// This catches the process AFTER it has replaced itself with the decrypted payload
void *memfd_dump_thread(void *arg) {
    typedef struct {
        pid_t pid;
        char comm[16];
    } memfd_dump_ctx_t;
    
    memfd_dump_ctx_t *ctx = (memfd_dump_ctx_t *)arg;
    pid_t pid = ctx->pid;
    
    printf("[POST-EXECVE] Starting dump for transformed PID %d\n", pid);
    
    // Small initial delay to let fexecve complete and mappings stabilize
    // fexecve() replaces the process but needs a few milliseconds to set up mappings
    usleep(20000);  // 20ms
    
    // Track if we got any useful dumps
    int initial_dump_count = 0;
    pthread_mutex_lock(&memdump_mutex);
    initial_dump_count = memdump_record_count;
    pthread_mutex_unlock(&memdump_mutex);
    
    // Retry multiple times - process exits in ~2 seconds, we have a window
    for (int attempt = 0; attempt < 10; attempt++) {
        // Verify process still exists
        char proc_check[64];
        snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
        if (access(proc_check, F_OK) != 0) {
            printf("[POST-EXECVE] PID %d exited after attempt %d\n", pid, attempt + 1);
            break;
        }
        
        // Verify it's still a sandbox process
        if (sandbox_mode && !is_sandbox_process(pid)) {
            printf("[POST-EXECVE] PID %d left sandbox tree\n", pid);
            break;
        }
        
        // Check /proc/PID/exe to see the transformation
        char exe_path[512];
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = '\0';
            if (attempt == 0) {
                printf("[POST-EXECVE] PID %d exe: %s\n", pid, exe_path);
            }
        }
        
        printf("[POST-EXECVE] Attempt %d: Dumping memory mappings for PID %d...\n", attempt + 1, pid);
        
        // PRIMARY STRATEGY: Dump ALL executable mappings
        // For fexecve'd processes, the decrypted ELF is now in memory
        dump_executable_mappings(pid);
        
        // Check if we got new dumps
        pthread_mutex_lock(&memdump_mutex);
        int current_dump_count = memdump_record_count;
        pthread_mutex_unlock(&memdump_mutex);
        
        if (current_dump_count > initial_dump_count) {
            printf("[POST-EXECVE] SUCCESS! Captured %d new dumps for PID %d\n", 
                   current_dump_count - initial_dump_count, pid);
            break;
        }
        
        // Retry with increasing delay (20ms -> 200ms over 10 attempts)
        usleep(20000 + (attempt * 20000));
    }
    
    // Also ensure we report this process
    printf("[MEMFD-THREAD] Triggering full scan for PID %d...\n", pid);
    scan_maps_and_dump(pid);
    
    printf("[MEMFD-THREAD] Completed for PID %d\n", pid);
    
    free(ctx);
    return NULL;
}

// eBPF event pipe reader thread
void *ebpf_pipe_reader(void *arg) {
    const char *pipe_path = (const char *)arg;
    
    printf("[+] eBPF pipe reader starting, opening: %s\n", pipe_path);
    
    FILE *pipe = fopen(pipe_path, "r");
    if (!pipe) {
        fprintf(stderr, "[!] Failed to open eBPF pipe %s: %s\n", pipe_path, strerror(errno));
        return NULL;
    }
    
    printf("[+] eBPF pipe opened successfully, waiting for events...\n");
    
    char line[512];
    while (fgets(line, sizeof(line), pipe)) {
        // Parse CSV: pid,tid,addr,len,prot,flags,event_type,comm
        uint32_t pid, tid, prot, flags, event_type;
        uint64_t addr, len;
        char comm[32];
        
        if (sscanf(line, "%u,%u,%lx,%lu,%u,%u,%u,%31s", 
                   &pid, &tid, &addr, &len, &prot, &flags, &event_type, comm) == 8) {
            
            // Event types: 1=MMAP_EXEC, 2=MPROTECT_EXEC, 3=MEMFD_CREATE, 4=EXECVE
            if (event_type == 1) {  // MMAP_EXEC
                // In sandbox mode, check if this PID is in sandbox tree
                if (sandbox_mode && !is_sandbox_process(pid)) {
                    continue;
                }
                
                // Check if this PID previously called memfd_create (but don't clear the flag yet)
                int had_memfd = 0;
                pthread_mutex_lock(&memfd_pids_mutex);
                for (int i = 0; i < memfd_pids_count; i++) {
                    if (memfd_pids[i] == pid) {
                        had_memfd = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&memfd_pids_mutex);
                
                // CRITICAL FIX: Check if process comm indicates post-fexecve memfd execution
                // After fexecve(), the process name will be "memfd:..." even if memfd fd is closed
                int is_memfd_process = (strncmp(comm, "memfd:", 6) == 0);
                
                if (!quiet_mode) {
                    if (had_memfd) {
                        printf("[eBPF] mmap(PROT_EXEC) AFTER memfd_create in PID %u (%s)\n", pid, comm);
                    } else {
                        printf("[eBPF] mmap(PROT_EXEC) PID %u (%s) addr=0x%lx len=%lu prot=0x%x\n", 
                               pid, comm, (unsigned long)addr, (unsigned long)len, prot);
                    }
                }
                
                // If this is a memfd process (post-fexecve), dump it immediately
                if (is_memfd_process && full_dump) {
                    printf("[+] Detected memfd process '%s' (PID %u) - dumping post-fexecve memory...\n", comm, pid);
                    // Don't use queue - dump synchronously while memory is still valid
                    scan_maps_and_dump(pid);
                } else {
                    // Queue immediate scan for all executable mappings
                    queue_push(&event_queue, pid, 0);
                }
                
                // STRATEGY 1: Dump memfd files (fileless execution)
                if (had_memfd && full_dump) {
                    printf("[+] Dumping memfd files for PID %u at mmap...\n", pid);
                    dump_memfd_files(pid);
                }
                
                // STRATEGY 2: Dump suspicious RWX regions (code injection)
                // Check if this is RWX (PROT_READ | PROT_WRITE | PROT_EXEC = 7)
                if (full_dump && (prot & 0x7) == 0x7) {
                    printf("[+] Detected RWX mmap in PID %u - dumping suspicious region...\n", pid);
                    // Dump this specific region
                    dump_memory_region(pid, addr, addr + len, 0);
                }
                
                // STRATEGY 3: Dump anonymous executable mappings (possible injection)
                // MAP_ANONYMOUS = 0x20
                if (full_dump && !had_memfd && (flags & 0x20) && len > 0 && len < 10*1024*1024) {
                    printf("[+] Detected anonymous executable mmap in PID %u - dumping region...\n", pid);
                    dump_memory_region(pid, addr, addr + len, 0);
                }
                
            } else if (event_type == 2) {  // MPROTECT_EXEC
                // In sandbox mode, check if this PID is in sandbox tree
                if (sandbox_mode && !is_sandbox_process(pid)) {
                    continue;
                }
                
                if (!quiet_mode) {
                    printf("[eBPF] mprotect(PROT_EXEC) detected in PID %u (%s) addr=0x%lx len=%lu prot=0x%x\n", 
                           pid, comm, (unsigned long)addr, (unsigned long)len, prot);
                }
                
                // Queue immediate scan (will trigger alerts)
                queue_push(&event_queue, pid, 0);
                
                // STRATEGY 4: Dump memory regions made executable via mprotect
                // This catches heap execution and other runtime code modifications
                if (full_dump && (prot & 0x7) == 0x7 && len > 0 && len < 10*1024*1024) {
                    printf("[+] Detected RWX mprotect in PID %u - dumping modified region...\n", pid);
                    dump_memory_region(pid, addr, addr + len, 0);
                } else if (full_dump && (prot & 0x4) && len > 100 && len < 10*1024*1024) {
                    // Even non-RWX but executable regions modified at runtime are suspicious
                    printf("[+] Detected executable mprotect in PID %u - dumping region...\n", pid);
                    dump_memory_region(pid, addr, addr + len, 0);
                }
                
            } else if (event_type == 3) {  // MEMFD_CREATE
                // In sandbox mode, check if this PID is in sandbox tree
                if (sandbox_mode && !is_sandbox_process(pid)) {
                    continue;
                }
                
                if (!quiet_mode) {
                    printf("[eBPF] memfd_create() detected in PID %u (%s)\n", pid, comm);
                }
                
                // Mark this PID for tracking
                mark_memfd_pid(pid);
                
                // DON'T dump here - too early! The process hasn't called fexecve() yet.
                // We'll dump when we see the EXECVE event (which comes from execveat/fexecve)
                
                if (!quiet_mode) {
                    printf("[+] Marked PID %u for memfd tracking (waiting for fexecve)\n", pid);
                }
                
                // Queue for worker thread
                queue_push(&event_queue, pid, 0);
                
            } else if (event_type == 4) {  // EXECVE
                // For execve events, the process has just replaced its binary
                if (sandbox_mode && !is_sandbox_process(pid)) {
                    continue;
                }
                
                // Check if memfd flag is set FIRST
                int had_memfd = 0;
                pthread_mutex_lock(&memfd_pids_mutex);
                for (int i = 0; i < memfd_pids_count; i++) {
                    if (memfd_pids[i] == pid) {
                        had_memfd = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&memfd_pids_mutex);
                
                // For memfd processes, DON'T skip duplicates
                // They do execve() twice: initial load + fexecve() to decrypted payload
                if (!had_memfd) {
                    // For normal processes, prevent duplicate processing
                    if (is_already_processed(pid)) {
                        continue;
                    }
                    mark_as_processed(pid);
                }
                
                if (had_memfd) {
                    // This is the golden moment! fexecve() just completed via execveat()
                    // Process has transformed: /proc/PID/exe now points to memfd
                    // /proc/PID/maps now shows the decrypted ELF payload
                    printf("[eBPF] execve() after memfd in PID %u (%s) - will dump\n", pid, comm);
                    
                    // CRITICAL: Give the kernel a moment to finish the execve transformation
                    // The syscall has ENTERED but may not be complete. Wait for memory to settle.
                    usleep(50000);  // 50ms - enough for kernel to finish exec
                    
                    // Mark as memfd_exec so worker thread prioritizes it
                    mark_memfd_exec_pid(pid);
                    
                    // Queue ONCE to worker thread - first worker to grab it will dump
                    queue_push(&event_queue, pid, 0);
                } else {
                    if (!quiet_mode) {
                        printf("[eBPF] execve() detected in PID %u (%s)\n", pid, comm);
                    }
                    // Queue for worker thread (will report process transformation)
                    queue_push(&event_queue, pid, 0);
                }
            }
        }
    }
    
    fclose(pipe);
    printf("[*] eBPF pipe reader exiting\n");
    return NULL;
}

// Worker thread function
void *worker_thread(void *arg) {
    (void)arg;  // Unused
    
    while (1) {
        event_data_t event;
        if (queue_pop(&event_queue, &event) < 0) {
            // Shutdown signal received
            break;
        }
        
        // Validate PID
        if (event.pid <= 0 || event.pid > 4194304) {
            continue;  // Invalid PID
        }
        
        // Skip Docker/container infrastructure processes
        if (should_ignore_process(event.pid)) {
            continue;
        }
        
        // In sandbox mode, only monitor sandbox process tree
        if (sandbox_mode && !is_sandbox_process(event.pid)) {
            continue;
        }
        
        if (!quiet_mode) {
            printf("\n[EXEC] PID=%d PPID=%d (thread=%lu)\n", 
                   event.pid, event.ppid, pthread_self());
        }
        
        // Wrap in error handler to prevent worker thread crashes
        scan_maps_and_dump(event.pid);
        
        if (!quiet_mode) {
            printf("========================================\n");
        }
    }
    
    return NULL;
}

void handle_proc_event(struct cn_msg *cn_hdr) {
    struct proc_event *ev = (struct proc_event *)cn_hdr->data;

    if (ev->what == PROC_EVENT_EXEC) {
        // If eBPF mode is enabled, skip netlink EXEC events
        // eBPF provides more accurate exec detection via tracepoints
        if (ebpf_pipe_path) {
            return;  // Let eBPF handle EXEC events
        }
        
        pid_t pid = ev->event_data.exec.process_pid;
        pid_t ppid = ev->event_data.exec.process_tgid;
        
        pthread_mutex_lock(&stats_mutex);
        total_events++;
        pthread_mutex_unlock(&stats_mutex);
        
        // Check if we've already processed this PID (prevent duplicate EXEC events)
        if (is_already_processed(pid)) {
            return;  // Skip duplicate EXEC event
        }
        mark_as_processed(pid);
        
        // Non-blocking push to queue - if queue is full, event is dropped (tracked in stats)
        if (queue_push(&event_queue, pid, ppid) < 0) {
            if (!quiet_mode) {
                fprintf(stderr, "[!] WARNING: Event queue full, dropped event for PID %d\n", pid);
            }
        }
    }
    else if (ev->what == PROC_EVENT_FORK) {
        // Fork creates a copy of parent process, including memory mappings
        // Check child process for inherited malicious mappings
        pid_t child_pid = ev->event_data.fork.child_pid;
        pid_t parent_pid = ev->event_data.fork.parent_pid;
        
        if (!quiet_mode || (sandbox_mode && is_sandbox_process(parent_pid))) {
            printf("[FORK] Parent=%d Child=%d\n", parent_pid, child_pid);
        }
        
        pthread_mutex_lock(&stats_mutex);
        total_events++;
        pthread_mutex_unlock(&stats_mutex);
        
        // Register child in sandbox tracking if parent is sandbox process
        if (sandbox_mode && is_sandbox_process(parent_pid)) {
            if (pthread_mutex_trylock(&sandbox_proc_mutex) == 0) {
                if (sandbox_process_count < MAX_SANDBOX_PROCESSES) {
                    int found = 0;
                    // Check if already registered
                    for (int i = 0; i < sandbox_process_count; i++) {
                        if (sandbox_processes[i].pid == child_pid) {
                            found = 1;
                            sandbox_processes[i].active = 1;  // Reactivate if needed
                            break;
                        }
                    }
                    if (!found) {
                        int idx = sandbox_process_count;
                        sandbox_processes[idx].pid = child_pid;
                        sandbox_processes[idx].ppid = parent_pid;
                        sandbox_processes[idx].active = 1;
                        sandbox_processes[idx].start_time = time(NULL);
                        snprintf(sandbox_processes[idx].name, sizeof(sandbox_processes[idx].name), "child_%d", child_pid);
                        sandbox_process_count++;
                    }
                }
                pthread_mutex_unlock(&sandbox_proc_mutex);
            }
        }
        
        // Queue child for scanning (may have inherited suspicious mappings from parent)
        if (queue_push(&event_queue, child_pid, parent_pid) < 0) {
            if (!quiet_mode) {
                fprintf(stderr, "[!] WARNING: Event queue full, dropped fork event for PID %d\n", child_pid);
            }
        }
    }
}

// Background thread for memory dumping (doesn't block monitoring)
void* dump_worker(void *arg) {
    (void)arg;
    
    while (1) {
        pid_t pid;
        if (dump_queue_pop(&dump_queue, &pid) < 0) {
            // Shutdown signal received
            break;
        }
        
        // In sandbox mode, only dump sandbox processes
        if (sandbox_mode && !is_sandbox_process(pid)) {
            if (!quiet_mode) {
                printf("[SKIP] PID %d not in sandbox process tree\n", pid);
            }
            continue;
        }
        
        // Check max_dumps limit (0 = unlimited)
        if (max_dumps > 0) {
            pthread_mutex_lock(&stats_mutex);
            int current_dumps = dumps_performed;
            pthread_mutex_unlock(&stats_mutex);
            
            if (current_dumps >= max_dumps) {
                if (!quiet_mode) {
                    printf("[SKIP] PID %d - max dump limit reached (%d/%d)\n", pid, current_dumps, max_dumps);
                }
                continue;
            }
        }
        
        // Check if process still exists before dumping
        char proc_check[64];
        snprintf(proc_check, sizeof(proc_check), "/proc/%d", pid);
        if (access(proc_check, F_OK) != 0) {
            printf("[WARN] PID %d exited before dump could start\n", pid);
            continue;
        }
        
        printf("[+] Starting background full memory dump for PID %d...\n", pid);
        dump_full_process_memory(pid);
    }
    
    return NULL;
}

// Periodic report updater - rewrites report.json from temp files every 2 seconds
void *periodic_report_writer(void *arg) {
    (void)arg;  // Unused
    
    fprintf(stderr, "[DEBUG] Periodic report writer thread started\n");
    
    // Do first update immediately (don't wait 2 seconds)
    if (strlen(sandbox_report_dir) > 0) {
        sleep(1);  // Brief delay to let initial events get written
        fprintf(stderr, "[DEBUG] Periodic writer: initial update...\n");
        if (!report_writer_busy) {
            finalize_sandbox_report();
        }
    }
    
    while (running && sandbox_mode) {
        sleep(2);  // Update every 2 seconds
        
        if (strlen(sandbox_report_dir) > 0 && !report_writer_busy) {
            fprintf(stderr, "[DEBUG] Periodic writer: updating report...\n");
            // Wrap in error recovery
            int saved_errno = errno;
            finalize_sandbox_report();
            errno = saved_errno;  // Restore errno
            fprintf(stderr, "[DEBUG] Periodic writer: update complete\n");
        }
    }
    
    fprintf(stderr, "[DEBUG] Periodic report writer thread exiting\n");
    return NULL;
}

int main(int argc, char **argv) {
    // Register emergency exit handler FIRST - runs even if signals fail
    atexit(emergency_exit_handler);
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGHUP, cleanup);
    signal(SIGSEGV, cleanup);  // Handle segmentation faults
    signal(SIGABRT, cleanup);  // Handle abort signals
    signal(SIGBUS, cleanup);   // Handle bus errors

    int num_threads = 4;  // Default number of worker threads

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--yara") == 0 && i + 1 < argc) {
            yara_rules_path = argv[++i];
#ifdef ENABLE_YARA
            printf("[+] YARA scanning enabled using rule file: %s\n", yara_rules_path);
#else
            printf("[!] WARNING: YARA support not compiled in. --yara flag ignored.\n");
            printf("[!] Recompile with -DENABLE_YARA and link against libyara to enable YARA scanning.\n");
#endif
        } else if (strcmp(argv[i], "--continuous") == 0) {
            continuous_scan = 1;
            printf("[+] Continuous monitoring enabled (will rescan running processes)\n");
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            quiet_mode = 1;
            printf("[+] Quiet mode enabled (only critical alerts)\n");
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[++i]);
            if (num_threads < 1) num_threads = 1;
            if (num_threads > MAX_WORKER_THREADS) num_threads = MAX_WORKER_THREADS;
            printf("[+] Using %d worker threads\n", num_threads);
        } else if (strcmp(argv[i], "--mem_dump") == 0) {
            mem_dump = 1;
        } else if (strcmp(argv[i], "--full_dump") == 0) {
            full_dump = 1;
            mem_dump = 1;  // full_dump implies mem_dump
            printf("[+] Memory dumping enabled (will save suspicious regions to disk)\n");
        } else if (strcmp(argv[i], "--sandbox-timeout") == 0 && i + 1 < argc) {
            sandbox_timeout = atoi(argv[++i]) * 60;  // Convert minutes to seconds
        } else if (strcmp(argv[i], "--sandbox-rescan") == 0 && i + 1 < argc) {
            sandbox_rescan_interval = atoi(argv[++i]);
            if (sandbox_rescan_interval < 1) {
                fprintf(stderr, "Error: --sandbox-rescan must be >= 1 second\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--max-dumps") == 0 && i + 1 < argc) {
            max_dumps = atoi(argv[++i]);
            if (max_dumps < 0) {
                fprintf(stderr, "Error: --max-dumps must be >= 0\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--ebpf-pipe") == 0 && i + 1 < argc) {
            ebpf_pipe_path = argv[++i];
            printf("[+] eBPF event pipe enabled: %s\n", ebpf_pipe_path);
        } else if (strcmp(argv[i], "--sandbox") == 0 && i + 1 < argc) {
            sandbox_mode = 1;
            sandbox_binary = argv[++i];
            
            // Collect remaining args for the sandbox binary
            sandbox_args_count = argc - i;
            sandbox_args = malloc((sandbox_args_count + 1) * sizeof(char*));
            sandbox_args[0] = sandbox_binary;
            for (int j = 1; j < sandbox_args_count; j++) {
                sandbox_args[j] = argv[i + j];
            }
            sandbox_args[sandbox_args_count] = NULL;
            
            printf("[+] Sandbox mode enabled\n");
            printf("[+] Will execute: %s", sandbox_binary);
            for (int j = 1; j < sandbox_args_count; j++) {
                printf(" %s", sandbox_args[j]);
            }
            printf("\n");
            break;  // No more args to parse
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Real-time process monitoring for malware detection\n\n");
            printf("[+] Options:\n");
            printf("  --yara <file>     Enable YARA scanning with specified rules file\n");
            printf("  --continuous      Enable continuous monitoring (rescan processes every 30s)\n");
            printf("  --quiet, -q       Quiet mode (suppress non-critical messages)\n");
            printf("  --threads <N>     Number of worker threads (1-%d, default: 4)\n", MAX_WORKER_THREADS);
            printf("  --mem_dump        Enable memory dumping to disk (default: off)\n");
            printf("  --full_dump       Dump entire process memory (implies --mem_dump)\n");
            printf("                    Creates memdump_PID/ directory with all regions\n");
            printf("  --max-dumps <N>   Maximum number of processes to dump (0=unlimited, default: 0)\n");
            printf("                    In sandbox mode, only counts sandbox processes\n");
            printf("  --ebpf-pipe <path>  Read eBPF syscall events from named pipe for event-driven scanning\n");
            printf("  --sandbox <bin>   Sandbox mode: execute and monitor specific binary\n");
            printf("                    All remaining arguments are passed to the binary\n");
            printf("  --sandbox-timeout <min>  Sandbox analysis timeout in minutes (default: wait for exit)\n");
            printf("  --sandbox-rescan <sec>   Rescan interval for unpacking detection (default: 2 seconds)\n");
            printf("                    Clears alert cache to detect XOR decryption, UPX unpacking, etc.\n");
            printf("  --help, -h        Show this help message\n\n");
            printf("Detection capabilities:\n");
            printf("  - Memory injection (memfd_create, /dev/shm execution)\n");
            printf("  - Process hollowing and reflective loading\n");
            printf("  - RWX memory regions (JIT spray, self-modifying code)\n");
            printf("  - Fileless execution techniques\n");
            printf("  - Heap/stack code execution\n");
            printf("  - Suspicious environment variables (LD_PRELOAD)\n");
            printf("  - Runtime unpacking detection (XOR, UPX, custom packers)\n");
            printf("  - File operations in /tmp, /dev/shm (sandbox mode)\n");
            printf("  - Network socket creation (sandbox mode)\n\n");
            printf("Sandbox mode examples:\n");
            printf("  Monitor binary:      %s --sandbox ./malware\n", argv[0]);
            printf("  With timeout:        %s --sandbox --sandbox-timeout 5 ./malware\n", argv[0]);
            printf("  With arguments:      %s --sandbox ./malware arg1 arg2\n", argv[0]);
            printf("  Python script:       %s --sandbox python3 script.py arg1\n", argv[0]);
            printf("  Bash script:         %s --sandbox bash script.sh\n", argv[0]);
            printf("  With memory dump:    %s --sandbox --mem_dump ./malware\n\n", argv[0]);
            printf("Multi-threaded architecture:\n");
            printf("  - Main thread rapidly drains netlink socket (no blocking)\n");
            printf("  - Worker threads process events asynchronously\n");
            printf("  - Prevents 'No buffer space available' in high-load environments\n");
            return 0;
        }
    }

    // Initialize event queue
    queue_init(&event_queue);

    // Initialize dump queue if full_dump enabled
    if (full_dump) {
        dump_queue_init(&dump_queue);
        if (pthread_create(&dump_worker_thread, NULL, dump_worker, NULL) != 0) {
            perror("pthread_create dump_worker");
            return 1;
        }
        printf("[+] Started background memory dump thread\n");
    }

    // Create worker threads
    pthread_t workers[MAX_WORKER_THREADS];
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    printf("[+] Started %d worker threads for async processing\n", num_threads);

    // Start eBPF pipe reader thread if enabled
    if (ebpf_pipe_path) {
        if (pthread_create(&ebpf_pipe_thread, NULL, ebpf_pipe_reader, (void*)ebpf_pipe_path) != 0) {
            perror("pthread_create ebpf_pipe_reader");
            return 1;
        }
        printf("[+] Started eBPF event pipe reader thread\n");
    }

    // Perform initial scan of all running processes to catch existing threats
    // Skip this in sandbox mode - we only care about the sandbox process tree
    if (!sandbox_mode) {
        printf("[+] Performing initial scan of running processes...\n");
        DIR *proc_dir = opendir("/proc");
        if (proc_dir) {
            struct dirent *entry;
            int scanned = 0;
            while ((entry = readdir(proc_dir)) != NULL) {
                if (entry->d_type == DT_DIR) {
                    pid_t pid = atoi(entry->d_name);
                    if (pid > 0) {
                        // Queue for worker threads to scan
                        if (!should_ignore_process(pid)) {
                            queue_push(&event_queue, pid, 0);
                            scanned++;
                        }
                    }
                }
            }
            closedir(proc_dir);
            printf("[+] Initial scan queued %d processes\n", scanned);
            // Give workers time to process the initial scan
            sleep(2);
        }
    }

    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket"); return 1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = CN_IDX_PROC,
        .nl_pid = getpid()
    };

    if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind"); return 1;
    }

    // Increase socket receive buffer significantly to prevent "No buffer space available" errors
    // This allows kernel to buffer more events during processing spikes
    // In container environments (Docker/K8s), process churn can be extreme
    int rcvbuf_size = 16 * 1024 * 1024; // 16MB buffer for container environments
    if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) == -1) {
        perror("setsockopt SO_RCVBUF");
        // Continue anyway, not fatal
    }
    
    // Also increase send buffer
    int sndbuf_size = 1024 * 1024; // 1MB
    setsockopt(nl_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size));

    // Set socket to non-blocking mode
    int flags = fcntl(nl_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(nl_sock, F_SETFL, flags | O_NONBLOCK);
    }

    struct {
        struct nlmsghdr nl_hdr;
        struct cn_msg cn_hdr;
        enum proc_cn_mcast_op op;
    } __attribute__((__packed__)) nl_packet;

    nl_packet.nl_hdr.nlmsg_len = sizeof(nl_packet);
    nl_packet.nl_hdr.nlmsg_type = NLMSG_DONE;
    nl_packet.nl_hdr.nlmsg_flags = 0;
    nl_packet.nl_hdr.nlmsg_seq = 0;
    nl_packet.nl_hdr.nlmsg_pid = getpid();

    nl_packet.cn_hdr.id.idx = CN_IDX_PROC;
    nl_packet.cn_hdr.id.val = CN_VAL_PROC;
    nl_packet.cn_hdr.len = sizeof(enum proc_cn_mcast_op);

    nl_packet.op = PROC_CN_MCAST_LISTEN;

    if (send(nl_sock, &nl_packet, sizeof(nl_packet), 0) == -1) {
        perror("send"); return 1;
    }

    printf("[+] Listening for process creation events (real-time)...\n");
    if (continuous_scan) {
        printf("[+] Continuous monitoring active - will rescan all processes every 30 seconds\n");
    }

    // If sandbox mode, execute the binary and monitor its process tree
    if (sandbox_mode) {
        // Initialize sandbox reporting
        char sample_full_path[1024];
        if (sandbox_binary[0] == '/') {
            strncpy(sample_full_path, sandbox_binary, sizeof(sample_full_path) - 1);
        } else {
            char cwd[512];
            getcwd(cwd, sizeof(cwd));
            if (strchr(sandbox_binary, '/')) {
                snprintf(sample_full_path, sizeof(sample_full_path), "%s/%s", cwd, sandbox_binary);
            } else {
                snprintf(sample_full_path, sizeof(sample_full_path), "%s/./%s", cwd, sandbox_binary);
            }
        }
        
        if (init_sandbox_reporting(sample_full_path) < 0) {
            fprintf(stderr, "[!] Warning: Sandbox reporting initialization failed, continuing without JSON report\n");
        } else {
            // Start periodic report writer thread
            pthread_t report_writer_thread;
            if (pthread_create(&report_writer_thread, NULL, periodic_report_writer, NULL) != 0) {
                perror("pthread_create report_writer");
            } else {
                printf("[+] Started periodic report writer (updates every 2 seconds)\n");
            }
        }
        
        printf("[+] Launching sandbox process...\n");
        
        pid_t child_pid = fork();
        if (child_pid == -1) {
            perror("fork");
            return 1;
        }
        
        if (child_pid == 0) {
            // Child process - execute the sandbox binary
            
            // Redirect stdin to a blocking pipe to prevent sample from exiting on EOF
            // This is critical for samples that read stdin (e.g., password prompts, crackmes)
            // Strategy: Fill pipe buffer completely to maximize time before EOF
            int pipe_fds[2];
            if (pipe(pipe_fds) == 0) {
                // Make write end non-blocking to fill buffer completely
                int flags = fcntl(pipe_fds[1], F_GETFL, 0);
                fcntl(pipe_fds[1], F_SETFL, flags | O_NONBLOCK);
                
                // Fill entire pipe buffer (typically 64KB on Linux)
                // Write many dummy password attempts to keep crackmes busy
                const char *dummy = "wrong_password_attempt_to_keep_sample_alive_longer\n";
                size_t dummy_len = strlen(dummy);
                
                // Write until pipe buffer is full (write() returns EAGAIN)
                for (int i = 0; i < 2000; i++) {  // 2000 * ~52 bytes = ~100KB attempt
                    ssize_t result = write(pipe_fds[1], dummy, dummy_len);
                    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;  // Buffer full, stop writing
                    }
                }
                close(pipe_fds[1]);  // Close write end after filling buffer
                
                // Redirect read end to stdin - sample will read from full buffer
                dup2(pipe_fds[0], STDIN_FILENO);
                close(pipe_fds[0]);
            }
            
            // If the binary doesn't contain '/', prepend './' for relative path
            char actual_path[512];
            if (strchr(sandbox_binary, '/') == NULL) {
                snprintf(actual_path, sizeof(actual_path), "./%s", sandbox_binary);
                sandbox_args[0] = actual_path;
            }
            
            // Auto-detect scripts based on file extension
            if (strstr(sandbox_binary, ".py") != NULL) {
                // Python script - prepend python3
                char **new_args = malloc((sandbox_args_count + 2) * sizeof(char*));
                new_args[0] = "python3";
                for (int i = 0; i < sandbox_args_count; i++) {
                    new_args[i + 1] = sandbox_args[i];
                }
                new_args[sandbox_args_count + 1] = NULL;
                execvp("python3", new_args);
                perror("execvp python3");
            } else if (strstr(sandbox_binary, ".sh") != NULL) {
                // Bash script - prepend bash
                char **new_args = malloc((sandbox_args_count + 2) * sizeof(char*));
                new_args[0] = "bash";
                for (int i = 0; i < sandbox_args_count; i++) {
                    new_args[i + 1] = sandbox_args[i];
                }
                new_args[sandbox_args_count + 1] = NULL;
                execvp("bash", new_args);
                perror("execvp bash");
            } else {
                // Direct execution
                // If path contains '/' use execv (absolute/relative path)
                // Otherwise use execvp (search PATH)
                if (strchr(sandbox_binary, '/') != NULL) {
                    execv(sandbox_binary, sandbox_args);
                    perror("execv");
                } else {
                    execvp(sandbox_binary, sandbox_args);
                    perror("execvp");
                }
            }
            
            // If exec fails
            exit(1);
        }
        
        // Parent process - store sandbox root PID
        sandbox_root_pid = child_pid;
        sandbox_start_time = time(NULL);
        
        // Register root PID in tracking array immediately
        pthread_mutex_lock(&sandbox_proc_mutex);
        sandbox_processes[0].pid = sandbox_root_pid;
        sandbox_processes[0].ppid = getpid();
        sandbox_processes[0].active = 1;
        sandbox_processes[0].start_time = sandbox_start_time;
        snprintf(sandbox_processes[0].name, sizeof(sandbox_processes[0].name), "sandbox_root");
        snprintf(sandbox_processes[0].path, sizeof(sandbox_processes[0].path), "%s", sandbox_binary);
        snprintf(sandbox_processes[0].creation_method, sizeof(sandbox_processes[0].creation_method), "SPAWN");
        sandbox_process_count = 1;
        
        // Write root process to temp file immediately
        char temp_file[600];
        int n = snprintf(temp_file, sizeof(temp_file), "%s/.processes.tmp", sandbox_report_dir);
        if (n > 0 && n < sizeof(temp_file)) {
            FILE *tf = fopen(temp_file, "a");
            if (tf) {
                // Escape separately to avoid buffer reuse
                const char *esc_path = json_escape(sandbox_binary);
                char path_copy[1024];
                strncpy(path_copy, esc_path, sizeof(path_copy) - 1);
                path_copy[sizeof(path_copy) - 1] = '\0';
                
                const char *esc_cmdline = json_escape(sandbox_binary);
                
                fprintf(tf, "{\"pid\":%d,\"ppid\":%d,\"name\":\"sandbox_root\",\"path\":\"%s\",\"cmdline\":\"%s\",\"creation_method\":\"SPAWN\",\"start_time\":%ld}\n",
                        sandbox_root_pid, getpid(), path_copy, esc_cmdline, sandbox_start_time);
                fflush(tf);
                fclose(tf);
            }
        }
        pthread_mutex_unlock(&sandbox_proc_mutex);
        
        printf("[+] Sandbox process started with PID %d\n", sandbox_root_pid);
        printf("[+] Sandbox binary: %s\n", sandbox_binary);
        if (sandbox_timeout > 0) {
            printf("[+] Analysis timeout: %d minutes\n", sandbox_timeout / 60);
        }
        printf("[+] Monitoring process tree...\n");
        
        // Give the process a moment to start and then scan it
        usleep(100000); // 100ms
        
        // Verify process is still running before gathering info
        if (kill(sandbox_root_pid, 0) == 0) {
            // Read what the child actually executed and add to process tree
            char exe_path[256];
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", sandbox_root_pid);
            char exe_link[256] = {0};
            ssize_t len = readlink(exe_path, exe_link, sizeof(exe_link) - 1);
            if (len > 0) {
                exe_link[len] = '\0';
                printf("[+] Child process executing: %s\n", exe_link);
            }
            
            // Get parent process info
            pid_t parent_ppid = 0;
            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", sandbox_root_pid);
            FILE *stat_file = fopen(stat_path, "r");
            if (stat_file) {
                fscanf(stat_file, "%*d %*s %*c %d", &parent_ppid);
                fclose(stat_file);
            }
            
            // Get process name
            char comm[256] = "unknown";
            char comm_path[64];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", sandbox_root_pid);
            FILE *comm_file = fopen(comm_path, "r");
            if (comm_file) {
                if (fgets(comm, sizeof(comm), comm_file)) {
                    size_t clen = strlen(comm);
                    if (clen > 0 && comm[clen-1] == '\n')
                        comm[clen-1] = '\0';
                }
                fclose(comm_file);
            }
            
            // Get command line
            char cmdline_buf[1024] = "";
            char cmdline_path[64];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", sandbox_root_pid);
            FILE *cmdline_file = fopen(cmdline_path, "r");
            if (cmdline_file) {
                size_t bytes = fread(cmdline_buf, 1, sizeof(cmdline_buf) - 1, cmdline_file);
                if (bytes > 0) {
                    // Replace nulls with spaces for readability
                    for (size_t i = 0; i < bytes - 1; i++) {
                        if (cmdline_buf[i] == '\0') cmdline_buf[i] = ' ';
                    }
                    cmdline_buf[bytes] = '\0';
                }
                fclose(cmdline_file);
            }
            
            // Add parent/root process to report
            report_sandbox_process(sandbox_root_pid, parent_ppid, comm, exe_link, cmdline_buf);
        } else {
            fprintf(stderr, "[!] WARN: Sandbox root process exited before info could be gathered\n");
            // Still report with minimal info
            report_sandbox_process(sandbox_root_pid, getpid(), "exited", sandbox_binary, sandbox_binary);
        }
        
        queue_push(&event_queue, sandbox_root_pid, 0);
    }

    time_t last_full_scan = time(NULL);
    last_sandbox_rescan = time(NULL);

    while (running) {
        char buf[32768];  // 32KB buffer to handle many events (reduced from 64KB)
        ssize_t len = recv(nl_sock, buf, sizeof(buf), 0);
        
        if (len == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, retry
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available - check if we should do a full scan
                
                // Check sandbox timeout or process exit
                if (sandbox_mode && sandbox_root_pid > 0) {
                    time_t now = time(NULL);
                    int process_exists = 1;  // Assume exists until proven otherwise
                    
                    // FIRST: Try to reap child process and get exit status (non-blocking)
                    // This must be done BEFORE checking /proc, because once process exits,
                    // the exit status is only available via waitpid() until it's reaped
                    int status;
                    pid_t wait_result = waitpid(sandbox_root_pid, &status, WNOHANG);
                    
                    if (wait_result == sandbox_root_pid) {
                        // Process has exited - capture exit status
                        process_exists = 0;
                        static int exit_logged = 0;
                        if (!exit_logged) {
                            printf("\n[+] Sandbox process (PID %d) has exited\n", sandbox_root_pid);
                            printf("[DEBUG] Raw status=0x%x, WIFEXITED=%d, WIFSIGNALED=%d\n", 
                                   status, WIFEXITED(status), WIFSIGNALED(status));
                            
                            if (WIFEXITED(status)) {
                                sandbox_exit_code = WEXITSTATUS(status);
                                if (sandbox_exit_code == 0) {
                                    strncpy(sandbox_termination_status, "completed", sizeof(sandbox_termination_status) - 1);
                                    printf("[+] Sample exited normally with code %d\n", sandbox_exit_code);
                                } else {
                                    strncpy(sandbox_termination_status, "error", sizeof(sandbox_termination_status) - 1);
                                    printf("[+] Sample exited with error code %d\n", sandbox_exit_code);
                                }
                            } else if (WIFSIGNALED(status)) {
                                sandbox_exit_code = WTERMSIG(status);
                                strncpy(sandbox_termination_status, "sample_crashed", sizeof(sandbox_termination_status) - 1);
                                const char* sig_name = 
                                    sandbox_exit_code == 11 ? "SIGSEGV (segmentation fault)" :
                                    sandbox_exit_code == 6 ? "SIGABRT (aborted)" :
                                    sandbox_exit_code == 9 ? "SIGKILL (killed)" :
                                    sandbox_exit_code == 15 ? "SIGTERM (terminated)" : "unknown signal";
                                printf("[+] Sample terminated by signal %d (%s)\n", sandbox_exit_code, sig_name);
                            } else {
                                printf("[+] Sample exited with unknown status (neither normal exit nor signal)\n");
                                strncpy(sandbox_termination_status, "unknown", sizeof(sandbox_termination_status) - 1);
                            }
                            
                            printf("[+] Collecting final data...\n");
                            exit_logged = 1;
                        }
                        
                        // Wait 2 seconds after exit to collect remaining events
                        static time_t exit_time = 0;
                        if (exit_time == 0) exit_time = now;
                        if (now - exit_time >= 2) {
                            printf("[+] Sandbox monitoring complete. Finalizing report...\n");
                            running = 0;
                        }
                    }
                    // Check if timeout expired
                    else if (sandbox_timeout > 0 && (now - sandbox_start_time) >= sandbox_timeout) {
                        printf("\n[+] Sandbox analysis timeout reached (%d minutes)\n", sandbox_timeout / 60);
                        printf("[+] Shutting down...\n");
                        strncpy(sandbox_termination_status, "timeout", sizeof(sandbox_termination_status) - 1);
                        running = 0;
                    }
                    // Check if process disappeared without waitpid catching it
                    else {
                        char proc_check[64];
                        snprintf(proc_check, sizeof(proc_check), "/proc/%d", sandbox_root_pid);
                        process_exists = (access(proc_check, F_OK) == 0);
                        
                        if (!process_exists) {
                            static time_t fallback_exit = 0;
                            if (fallback_exit == 0) {
                                printf("\n[+] Sandbox process disappeared (waitpid missed it)\n");
                                strncpy(sandbox_termination_status, "completed", sizeof(sandbox_termination_status) - 1);
                                fallback_exit = now;
                            }
                            if (now - fallback_exit >= 2) {
                                running = 0;
                            }
                        }
                    }
                    
                    // Periodic rescanning (only if process still exists)
                    if (running && process_exists) {
                        if (now - last_sandbox_rescan >= sandbox_rescan_interval) {
                            // Clear alert cache to allow re-detection of unpacked/decrypted code
                            // This is critical for catching XOR decryption, UPX unpacking, etc.
                            clear_alert_cache();
                            
                            // Rescan sandbox process
                            queue_push(&event_queue, sandbox_root_pid, 0);
                            
                            // Flush report data every 5 seconds for crash recovery
                            static time_t last_flush = 0;
                            if (last_flush == 0) last_flush = now;
                            if (now - last_flush >= 5) {
                                flush_sandbox_report();
                                last_flush = now;
                            }
                            
                            // Also scan for any child processes of sandbox
                            char task_path[256];
                            snprintf(task_path, sizeof(task_path), "/proc/%d/task/%d/children", 
                                     sandbox_root_pid, sandbox_root_pid);
                            FILE *children_file = fopen(task_path, "r");
                            if (children_file) {
                                char line[1024];
                                if (fgets(line, sizeof(line), children_file)) {
                                    // Parse space-separated PIDs
                                    char *token = strtok(line, " \n");
                                    int child_count = 0;
                                    while (token) {
                                        pid_t child_pid = atoi(token);
                                        if (child_pid > 0) {
                                            child_count++;
                                            printf("[+] Found child process: PID %d (parent: %d)\n", 
                                                   child_pid, sandbox_root_pid);
                                            queue_push(&event_queue, child_pid, sandbox_root_pid);
                                        }
                                        token = strtok(NULL, " \n");
                                    }
                                    if (child_count > 0 && !quiet_mode) {
                                        printf("[*] Scanning %d child process(es)\n", child_count);
                                    }
                                }
                                fclose(children_file);
                            } else if (!quiet_mode) {
                                // Fallback: scan /proc for children
                                DIR *proc_dir = opendir("/proc");
                                if (proc_dir) {
                                    struct dirent *entry;
                                    int child_count = 0;
                                    while ((entry = readdir(proc_dir)) != NULL) {
                                        if (!isdigit(entry->d_name[0])) continue;
                                        
                                        pid_t potential_child = atoi(entry->d_name);
                                        if (potential_child <= 0 || potential_child == sandbox_root_pid) continue;
                                        
                                        // Check if this process's ppid matches sandbox_root_pid
                                        char stat_path[256];
                                        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", potential_child);
                                        FILE *sf = fopen(stat_path, "r");
                                        if (sf) {
                                            char stat_line[2048];
                                            if (fgets(stat_line, sizeof(stat_line), sf)) {
                                                char *p = strrchr(stat_line, ')');
                                                if (p) {
                                                    int ppid = 0;
                                                    sscanf(p + 1, " %*c %d", &ppid);
                                                    if (ppid == sandbox_root_pid) {
                                                        child_count++;
                                                        printf("[+] Found child via /proc scan: PID %d\n", potential_child);
                                                        queue_push(&event_queue, potential_child, sandbox_root_pid);
                                                    }
                                                }
                                            }
                                            fclose(sf);
                                        }
                                    }
                                    closedir(proc_dir);
                                    if (child_count > 0) {
                                        printf("[*] Found %d child process(es) via fallback scan\n", child_count);
                                    }
                                }
                            }
                        
                            last_sandbox_rescan = now;
                            
                            if (!quiet_mode && ((now - sandbox_start_time) % 10 == 0)) {
                                printf("[*] Sandbox rescan (detecting unpacking/decryption changes)\n");
                            }
                        }
                    }
                }                if (continuous_scan) {
                    time_t now = time(NULL);
                    if (now - last_full_scan >= 30) {
                        if (!quiet_mode) {
                            printf("\n[*] Performing periodic scan (stats: %lu events, %lu alerts, %lu races)\n", 
                                   total_events, suspicious_found, race_conditions);
                        }
                        // Note: Periodic full scans are VERY noisy and may cause buffer overflow
                        // Consider disabling or making this optional
                        // Commenting out for now:
                        /*
                        DIR *proc_dir = opendir("/proc");
                        if (proc_dir) {
                            struct dirent *entry;
                            while ((entry = readdir(proc_dir)) != NULL) {
                                if (entry->d_type == DT_DIR) {
                                    pid_t pid = atoi(entry->d_name);
                                    if (pid > 0) {
                                        scan_maps_and_dump(pid);
                                    }
                                }
                            }
                            closedir(proc_dir);
                        }
                        */
                        last_full_scan = now;
                        if (!quiet_mode) {
                            printf("[*] Periodic scan skipped (too noisy - use targeted scans instead)\n\n");
                        }
                    }
                }
                // Sleep briefly to avoid busy-waiting
                usleep(1000);  // 1ms (reduced from 10ms for faster response)
                continue;
            }
            // Real error occurred
            perror("recv");
            break;
        }
        
        if (len == 0) {
            // Should not happen with netlink sockets, but handle it
            fprintf(stderr, "[!] Netlink socket closed\n");
            break;
        }

        // Process all messages in the buffer
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (NLMSG_OK(nlh, len)) {
            struct cn_msg *cn_hdr = NLMSG_DATA(nlh);
            handle_proc_event(cn_hdr);
            nlh = NLMSG_NEXT(nlh, len);
        }
        
        // Immediately try to drain more events from the socket buffer
        // without sleeping to prevent kernel buffer overflow
    }

    // Normal exit - call cleanup to finalize reports
    cleanup(0);
    return 0;
}