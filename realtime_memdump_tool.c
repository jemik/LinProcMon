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

// Sandbox reporting infrastructure
char sandbox_report_dir[512] = "";  // Base directory for sandbox output
char sandbox_dropped_dir[512] = "";  // Directory for dropped files
char sandbox_memdump_dir[512] = "";  // Directory for memory dumps
char sample_sha1[41] = "";  // SHA-1 of sample being analyzed
FILE *sandbox_json_report = NULL;  // JSON report file
pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
int json_first_item = 1;  // Track if we need comma before next JSON item

// Process tracking for sandbox
#define MAX_SANDBOX_PROCESSES 256
typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[256];
    char path[512];
    char cmdline[1024];
    time_t start_time;
    int active;
} sandbox_process_t;

sandbox_process_t sandbox_processes[MAX_SANDBOX_PROCESSES];
int sandbox_process_count = 0;
pthread_mutex_t sandbox_proc_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// ============================================================================
// SANDBOX REPORTING FUNCTIONS
// ============================================================================

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

// JSON escape string
void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 2; i++) {
        switch (src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:
                if (src[i] < 32) {
                    j += snprintf(dst + j, dst_size - j, "\\u%04x", (unsigned char)src[i]);
                } else {
                    dst[j++] = src[i];
                }
        }
    }
    dst[j] = '\0';
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
    
    fflush(sandbox_json_report);
    
    printf("[+] Sandbox report directory: %s/\n", sandbox_report_dir);
    printf("[+] Sample SHA-1: %s\n", sample_sha1);
    
    return 0;
}

// Add process to sandbox report
void report_sandbox_process(pid_t pid, pid_t ppid, const char *name, const char *path, const char *cmdline) {
    if (!sandbox_json_report) return;
    
    pthread_mutex_lock(&report_mutex);
    
    // Track process
    pthread_mutex_lock(&sandbox_proc_mutex);
    if (sandbox_process_count < MAX_SANDBOX_PROCESSES) {
        sandbox_processes[sandbox_process_count].pid = pid;
        sandbox_processes[sandbox_process_count].ppid = ppid;
        strncpy(sandbox_processes[sandbox_process_count].name, name, sizeof(sandbox_processes[0].name) - 1);
        strncpy(sandbox_processes[sandbox_process_count].path, path, sizeof(sandbox_processes[0].path) - 1);
        strncpy(sandbox_processes[sandbox_process_count].cmdline, cmdline, sizeof(sandbox_processes[0].cmdline) - 1);
        sandbox_processes[sandbox_process_count].start_time = time(NULL);
        sandbox_processes[sandbox_process_count].active = 1;
        sandbox_process_count++;
    }
    pthread_mutex_unlock(&sandbox_proc_mutex);
    
    pthread_mutex_unlock(&report_mutex);
}

// Add file operation to report
void report_file_operation(pid_t pid, const char *operation, const char *filepath) {
    if (!sandbox_json_report) return;
    
    pthread_mutex_lock(&report_mutex);
    
    // Copy file to dropped_files directory if it's a create/write operation
    if (strcmp(operation, "created") == 0 || strcmp(operation, "written") == 0) {
        const char *filename = strrchr(filepath, '/');
        filename = filename ? filename + 1 : filepath;
        
        char dest_path[1024];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", sandbox_dropped_dir, filename);
        
        // Try to copy the file
        FILE *src = fopen(filepath, "rb");
        if (src) {
            FILE *dst = fopen(dest_path, "wb");
            if (dst) {
                char buffer[8192];
                size_t bytes;
                while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                    fwrite(buffer, 1, bytes, dst);
                }
                fclose(dst);
                
                // Calculate hashes
                char sha1[41], sha256[65];
                calculate_sha1(dest_path, sha1);
                calculate_sha256(dest_path, sha256);
                
                printf("[SANDBOX] Captured dropped file: %s (SHA-1: %s)\n", filename, sha1);
            }
            fclose(src);
        }
    }
    
    pthread_mutex_unlock(&report_mutex);
}

// Add network activity to report  
void report_network_activity(pid_t pid, const char *protocol, const char *local_addr, const char *remote_addr) {
    if (!sandbox_json_report) return;
    
    pthread_mutex_lock(&report_mutex);
    
    char escaped_local[256], escaped_remote[256];
    json_escape(local_addr, escaped_local, sizeof(escaped_local));
    json_escape(remote_addr, escaped_remote, sizeof(escaped_remote));
    
    printf("[SANDBOX] Network: PID=%d %s %s -> %s\n", pid, protocol, local_addr, remote_addr);
    
    pthread_mutex_unlock(&report_mutex);
}

// Finalize sandbox report
void finalize_sandbox_report() {
    if (!sandbox_json_report) return;
    
    pthread_mutex_lock(&report_mutex);
    
    // Write process tree
    fprintf(sandbox_json_report, "  \"processes\": [\n");
    for (int i = 0; i < sandbox_process_count; i++) {
        char escaped_name[512], escaped_path[1024], escaped_cmdline[2048];
        json_escape(sandbox_processes[i].name, escaped_name, sizeof(escaped_name));
        json_escape(sandbox_processes[i].path, escaped_path, sizeof(escaped_path));
        json_escape(sandbox_processes[i].cmdline, escaped_cmdline, sizeof(escaped_cmdline));
        
        fprintf(sandbox_json_report, "    {\n");
        fprintf(sandbox_json_report, "      \"pid\": %d,\n", sandbox_processes[i].pid);
        fprintf(sandbox_json_report, "      \"ppid\": %d,\n", sandbox_processes[i].ppid);
        fprintf(sandbox_json_report, "      \"name\": \"%s\",\n", escaped_name);
        fprintf(sandbox_json_report, "      \"path\": \"%s\",\n", escaped_path);
        fprintf(sandbox_json_report, "      \"cmdline\": \"%s\",\n", escaped_cmdline);
        fprintf(sandbox_json_report, "      \"start_time\": %ld\n", sandbox_processes[i].start_time);
        fprintf(sandbox_json_report, "    }%s\n", (i < sandbox_process_count - 1) ? "," : "");
    }
    fprintf(sandbox_json_report, "  ],\n");
    
    // Write summary
    fprintf(sandbox_json_report, "  \"summary\": {\n");
    fprintf(sandbox_json_report, "    \"end_time\": %ld,\n", time(NULL));
    fprintf(sandbox_json_report, "    \"duration\": %ld,\n", time(NULL) - sandbox_start_time);
    fprintf(sandbox_json_report, "    \"total_processes\": %d,\n", sandbox_process_count);
    fprintf(sandbox_json_report, "    \"files_created\": %lu,\n", files_created);
    fprintf(sandbox_json_report, "    \"sockets_created\": %lu,\n", sockets_created);
    fprintf(sandbox_json_report, "    \"suspicious_findings\": %lu\n", suspicious_found);
    fprintf(sandbox_json_report, "  }\n");
    
    fprintf(sandbox_json_report, "}\n");
    fclose(sandbox_json_report);
    sandbox_json_report = NULL;
    
    printf("[+] Sandbox report finalized: %s/report.json\n", sandbox_report_dir);
    
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
    running = 0;  // Signal main loop to exit
    printf("\n[!] Exiting...\n");
    
    // Finalize sandbox report if in sandbox mode
    if (sandbox_mode && sandbox_json_report) {
        finalize_sandbox_report();
    }
    
    // Signal shutdown and wake up worker threads
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

// Dump all memory regions of a process for dynamic unpacking analysis
// Creates a single contiguous dump file for easy reverse engineering
void dump_full_process_memory(pid_t pid) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("[-] open maps");
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
        perror("[-] open /proc/PID/mem");
        fclose(maps);
        close(dump_fd);
        if (mapfile) fclose(mapfile);
        return;
    }

    char line[512];
    int region_count = 0;
    size_t total_dumped = 0;
    size_t current_offset = 0;
    char *buffer = malloc(16 * 1024 * 1024);  // 16MB reusable buffer
    
    if (!buffer) {
        perror("[-] malloc buffer");
        close(mem_fd);
        close(dump_fd);
        fclose(maps);
        if (mapfile) fclose(mapfile);
        return;
    }

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5], path[256] = "";
        
        int items = sscanf(line, "%lx-%lx %4s %*x %*s %*d %255[^\n]", &start, &end, perms, path);
        if (items < 3) continue;

        // Skip regions without read permission
        if (perms[0] != 'r') continue;

        size_t size = end - start;
        if (size == 0 || size > 1024*1024*1024) continue;  // Skip invalid/huge regions

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

        // Read and write region in chunks
        size_t bytes_dumped = 0;
        size_t remaining = size;
        int read_failed = 0;
        
        while (remaining > 0 && !read_failed) {
            size_t chunk_size = (remaining > 16*1024*1024) ? 16*1024*1024 : remaining;
            ssize_t bytes = read(mem_fd, buffer, chunk_size);
            
            if (bytes <= 0) {
                read_failed = 1;
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
    
    // Calculate hashes of memory dump
    char sha1[41], sha256[65];
    if (calculate_sha1(dump_file, sha1) == 0) {
        printf("[+] Memory dump SHA-1: %s\n", sha1);
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

// Check if PID belongs to sandbox process tree
static int is_sandbox_process(pid_t pid) {
    if (!sandbox_mode) return 0;
    if (pid == sandbox_root_pid) return 1;
    
    // Check if this process is a descendant of sandbox root
    pid_t current = pid;
    for (int depth = 0; depth < 100; depth++) {  // Max depth to prevent infinite loop
        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", current);
        
        FILE *f = fopen(stat_path, "r");
        if (!f) return 0;  // Process doesn't exist
        
        pid_t ppid;
        // Parse: pid (comm) state ppid
        if (fscanf(f, "%*d %*s %*c %d", &ppid) != 1) {
            fclose(f);
            return 0;
        }
        fclose(f);
        
        if (ppid == sandbox_root_pid) return 1;  // Parent is sandbox root
        if (ppid <= 1) return 0;  // Reached init/kernel
        
        current = ppid;
    }
    return 0;
}

// Monitor file creation by sandbox process
static void check_file_operations(pid_t pid) {
    if (!sandbox_mode || !is_sandbox_process(pid)) return;
    
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    
    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char link_path[128];
        char target[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, entry->d_name);
        
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            
            // Check for suspicious file creation
            if (strstr(target, "/tmp/") || strstr(target, "/dev/shm/") || 
                strstr(target, "/var/tmp/")) {
                printf("[SANDBOX] File created: %s (PID=%d)\n", target, pid);
                report_file_operation(pid, "created", target);
                pthread_mutex_lock(&stats_mutex);
                files_created++;
                pthread_mutex_unlock(&stats_mutex);
            }
        }
    }
    closedir(fd_dir);
}

// Monitor network connections by sandbox process
static void check_network_connections(pid_t pid) {
    if (!sandbox_mode || !is_sandbox_process(pid)) return;
    
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    
    DIR *fd_dir = opendir(fd_path);
    if (!fd_dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char link_path[128];
        char target[PATH_MAX];
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, entry->d_name);
        
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            
            // Check for socket creation
            if (strstr(target, "socket:") != NULL) {
                printf("[SANDBOX] Socket created: %s (PID=%d)\n", target, pid);
                pthread_mutex_lock(&stats_mutex);
                sockets_created++;
                pthread_mutex_unlock(&stats_mutex);
            }
        }
    }
    closedir(fd_dir);
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

    // Check if this is a sandbox process
    if (sandbox_mode && is_sandbox_process(pid)) {
        pthread_mutex_lock(&stats_mutex);
        sandbox_events++;
        pthread_mutex_unlock(&stats_mutex);
        printf("[SANDBOX] Monitoring PID %d\n", pid);
        
        // Get process info for reporting
        char comm[256] = "", cmdline[1024] = "", exe_path[512] = "";
        char comm_path[64], cmdline_path[64], exe_link[64];
        
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        FILE *comm_file = fopen(comm_path, "r");
        if (comm_file) {
            fgets(comm, sizeof(comm), comm_file);
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            fclose(comm_file);
        }
        
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *cmdline_file = fopen(cmdline_path, "r");
        if (cmdline_file) {
            size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
            for (size_t i = 0; i < len - 1; i++) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
            fclose(cmdline_file);
        }
        
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len > 0) exe_path[len] = '\0';
        
        // Get PPID
        pid_t ppid = 0;
        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
        FILE *stat_file = fopen(stat_path, "r");
        if (stat_file) {
            fscanf(stat_file, "%*d %*s %*c %d", &ppid);
            fclose(stat_file);
        }
        
        report_sandbox_process(pid, ppid, comm, exe_path, cmdline);
        
        check_file_operations(pid);
        check_network_connections(pid);
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
    if (full_dump && suspicious_count > 0) {
        if (dump_queue_push(&dump_queue, pid) < 0) {
            if (!quiet_mode) {
                printf("[WARN] Dump queue full, skipping full dump for PID %d\n", pid);
            }
        } else if (!quiet_mode) {
            printf("[INFO] Queued PID %d for full memory dump (background)\n", pid);
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
        
        // In sandbox mode, only monitor sandbox process tree
        if (sandbox_mode && !is_sandbox_process(event.pid)) {
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
        
        if (!quiet_mode || (sandbox_mode && is_sandbox_process(parent_pid))) {
            printf("[FORK] Parent=%d Child=%d\n", parent_pid, child_pid);
        }
        
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

// Background thread for memory dumping (doesn't block monitoring)
void* dump_worker(void *arg) {
    (void)arg;
    
    while (1) {
        pid_t pid;
        if (dump_queue_pop(&dump_queue, &pid) < 0) {
            // Shutdown signal received
            break;
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
        } else if (strcmp(argv[i], "--full_dump") == 0) {
            full_dump = 1;
            mem_dump = 1;  // full_dump implies mem_dump
            printf("[+] Memory dumping enabled (will save suspicious regions to disk)\n");
        } else if (strcmp(argv[i], "--sandbox-timeout") == 0 && i + 1 < argc) {
            sandbox_timeout = atoi(argv[++i]) * 60;  // Convert minutes to seconds
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
            printf("  --sandbox <bin>   Sandbox mode: execute and monitor specific binary\n");
            printf("                    All remaining arguments are passed to the binary\n");
            printf("  --help, -h        Show this help message\n\n");
            printf("Detection capabilities:\n");
            printf("  - Memory injection (memfd_create, /dev/shm execution)\n");
            printf("  - Process hollowing and reflective loading\n");
            printf("  - RWX memory regions (JIT spray, self-modifying code)\n");
            printf("  - Fileless execution techniques\n");
            printf("  - Heap/stack code execution\n");
            printf("  - Suspicious environment variables (LD_PRELOAD)\n");
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
        }
        
        printf("[+] Launching sandbox process...\n");
        
        pid_t child_pid = fork();
        if (child_pid == -1) {
            perror("fork");
            return 1;
        }
        
        if (child_pid == 0) {
            // Child process - execute the sandbox binary
            
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
        printf("[+] Sandbox process started with PID %d\n", sandbox_root_pid);
        printf("[+] Sandbox binary: %s\n", sandbox_binary);
        if (sandbox_timeout > 0) {
            printf("[+] Analysis timeout: %d minutes\n", sandbox_timeout / 60);
        }
        printf("[+] Monitoring process tree...\n");
        
        // Give the process a moment to start and then scan it
        usleep(100000); // 100ms
        
        // Read what the child actually executed
        char exe_path[256];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", sandbox_root_pid);
        char exe_link[256] = {0};
        ssize_t len = readlink(exe_path, exe_link, sizeof(exe_link) - 1);
        if (len > 0) {
            exe_link[len] = '\0';
            printf("[+] Child process executing: %s\n", exe_link);
        }
        
        queue_push(&event_queue, sandbox_root_pid, 0);
    }

    time_t last_full_scan = time(NULL);
    time_t last_sandbox_scan = time(NULL);

    while (running) {
        char buf[65536];  // 64KB buffer to handle many events at once
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
                    char proc_check[64];
                    snprintf(proc_check, sizeof(proc_check), "/proc/%d", sandbox_root_pid);
                    int process_exists = (access(proc_check, F_OK) == 0);
                    
                    // Check if timeout expired
                    if (sandbox_timeout > 0 && (now - sandbox_start_time) >= sandbox_timeout) {
                        printf("\n[+] Sandbox analysis timeout reached (%d minutes)\n", sandbox_timeout / 60);
                        printf("[+] Shutting down...\n");
                        running = 0;
                    }
                    // If no timeout set, check if root process exited
                    else if (sandbox_timeout == 0 && !process_exists) {
                        printf("\n[+] Sandbox process (PID %d) has exited\n", sandbox_root_pid);
                        printf("[+] Sandbox monitoring complete. Shutting down...\n");
                        running = 0;
                    }
                    
                    // Periodic rescanning (only if process still exists)
                    if (running && process_exists) {
                        if (now - last_sandbox_scan >= 1) {
                            // Rescan sandbox process every second
                            queue_push(&event_queue, sandbox_root_pid, 0);
                            
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
                                    while (token) {
                                        pid_t child_pid = atoi(token);
                                        if (child_pid > 0) {
                                            queue_push(&event_queue, child_pid, sandbox_root_pid);
                                        }
                                        token = strtok(NULL, " \n");
                                    }
                                }
                                fclose(children_file);
                            }
                        
                            last_sandbox_scan = now;
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

    return 0;
}