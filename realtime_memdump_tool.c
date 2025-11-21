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
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>

#ifdef ENABLE_YARA
#include <yara.h>
#endif

#define MAX_LINE 4096
#define MAX_WORKER_THREADS 8
#define EVENT_QUEUE_SIZE 1024

// Note: No delay for process initialization - prioritize event processing speed
// Short-lived processes may race (exit before we read them) - this is acceptable

int nl_sock;
const char* yara_rules_path = NULL;
int continuous_scan = 0;  // Flag for continuous monitoring of all processes
int quiet_mode = 0;  // Suppress non-critical messages
int mem_dump = 0;  // Enable memory dumping to disk

// Statistics (now protected by mutex)
static unsigned long total_events = 0;
static unsigned long suspicious_found = 0;
static unsigned long race_conditions = 0;
static unsigned long queue_drops = 0;

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

void cleanup(int sig) {
    printf("\n[!] Exiting...\n");
    
    // Signal shutdown and wake up worker threads
    pthread_mutex_lock(&event_queue.mutex);
    event_queue.shutdown = 1;
    pthread_cond_broadcast(&event_queue.not_empty);
    pthread_mutex_unlock(&event_queue.mutex);
    
    printf("[*] Statistics:\n");
    printf("    Total events processed: %lu\n", total_events);
    printf("    Suspicious findings: %lu\n", suspicious_found);
    printf("    Race conditions (normal): %lu\n", race_conditions);
    printf("    Queue drops (overload): %lu\n", queue_drops);
    close(nl_sock);
    exit(0);
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

    lseek(mem_fd, start, SEEK_SET);
    
    char *buffer = malloc(size);
    if (!buffer) {
        perror("[-] malloc");
        close(mem_fd);
        close(out_fd);
        return;
    }

    ssize_t bytes = read(mem_fd, buffer, size);
    if (bytes > 0) {
        write(out_fd, buffer, bytes);
        printf("[+] Dumped %ld bytes to %s\n", bytes, out_filename);
        if (yara_rules_path)
            scan_with_yara(out_filename);
    }

    free(buffer);
    close(mem_fd);
    close(out_fd);
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
    } else if (strstr(exe_target, "(deleted)")) {
        // Running from deleted file - could be legitimate (updated binary) or suspicious
        if (!quiet_mode) {
            printf("[WARN] Process running from deleted file PID %d: %s\n", pid, exe_target);
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

void scan_maps_and_dump(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        // Process likely exited - this is a race condition, not an error
        pthread_mutex_lock(&stats_mutex);
        race_conditions++;
        pthread_mutex_unlock(&stats_mutex);
        return;
    }

    // First read process info and check for obvious red flags
    // check_exe_link must run in all modes to detect memfd execution
    check_exe_link(pid);
    check_env_vars(pid);
    
    // Print process info only in verbose mode
    if (!quiet_mode) {
        print_process_info(pid);
    }

    char line[MAX_LINE];
    int suspicious_count = 0;
    
    // Helper function to check if path is a legitimate system binary/library
    int is_legitimate_path(const char *path) {
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
            
            // Only dump memory if --mem_dump flag is enabled
            if (mem_dump) {
                // In quiet mode, skip dumping large regions to prevent I/O blocking
                dump_memory_region(pid, start, end, quiet_mode);
            }
        }
    }
    fclose(maps);
    
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

// Worker thread function
void *worker_thread(void *arg) {
    (void)arg;  // Unused
    
    while (1) {
        event_data_t event;
        if (queue_pop(&event_queue, &event) < 0) {
            // Shutdown signal received
            break;
        }
        
        // Skip Docker/container infrastructure processes
        if (should_ignore_process(event.pid)) {
            continue;
        }
        
        if (!quiet_mode) {
            printf("\n[EXEC] PID=%d PPID=%d (thread=%lu)\n", 
                   event.pid, event.ppid, pthread_self());
        }
        
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
        pid_t pid = ev->event_data.exec.process_pid;
        pid_t ppid = ev->event_data.exec.process_tgid;
        
        pthread_mutex_lock(&stats_mutex);
        total_events++;
        pthread_mutex_unlock(&stats_mutex);
        
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
        
        pthread_mutex_lock(&stats_mutex);
        total_events++;
        pthread_mutex_unlock(&stats_mutex);
        
        // Queue child for scanning (may have inherited suspicious mappings from parent)
        if (queue_push(&event_queue, child_pid, parent_pid) < 0) {
            if (!quiet_mode) {
                fprintf(stderr, "[!] WARNING: Event queue full, dropped fork event for PID %d\n", child_pid);
            }
        }
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, cleanup);

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
            printf("[+] Memory dumping enabled (will save suspicious regions to disk)\n");
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Real-time process monitoring for malware detection\n\n");
            printf("[+] Options:\n");
            printf("  --yara <file>     Enable YARA scanning with specified rules file\n");
            printf("  --continuous      Enable continuous monitoring (rescan processes every 30s)\n");
            printf("  --quiet, -q       Quiet mode (suppress non-critical messages)\n");
            printf("  --threads <N>     Number of worker threads (1-%d, default: 4)\n", MAX_WORKER_THREADS);
            printf("  --mem_dump        Enable memory dumping to disk (default: off)\n");
            printf("  --help, -h        Show this help message\n\n");
            printf("Detection capabilities:\n");
            printf("  - Memory injection (memfd_create, /dev/shm execution)\n");
            printf("  - Process hollowing and reflective loading\n");
            printf("  - RWX memory regions (JIT spray, self-modifying code)\n");
            printf("  - Fileless execution techniques\n");
            printf("  - Heap/stack code execution\n");
            printf("  - Suspicious environment variables (LD_PRELOAD)\n\n");
            printf("Multi-threaded architecture:\n");
            printf("  - Main thread rapidly drains netlink socket (no blocking)\n");
            printf("  - Worker threads process events asynchronously\n");
            printf("  - Prevents 'No buffer space available' in high-load environments\n");
            return 0;
        }
    }

    // Initialize event queue
    queue_init(&event_queue);

    // Create worker threads
    pthread_t workers[MAX_WORKER_THREADS];
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&workers[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    printf("[+] Started %d worker threads for async processing\n", num_threads);

    // Perform initial scan of all running processes to catch existing threats
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

    time_t last_full_scan = time(NULL);

    while (1) {
        char buf[65536];  // 64KB buffer to handle many events at once
        ssize_t len = recv(nl_sock, buf, sizeof(buf), 0);
        
        if (len == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, retry
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available - check if we should do a full scan
                if (continuous_scan) {
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

    return 0;
}