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

#ifdef ENABLE_YARA
#include <yara.h>
#endif

#define MAX_LINE 4096

int nl_sock;
const char* yara_rules_path = NULL;
int continuous_scan = 0;  // Flag for continuous monitoring of all processes

void cleanup(int sig) {
    printf("\n[!] Exiting...\n");
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

void dump_memory_region(pid_t pid, unsigned long start, unsigned long end) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

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
    size_t size = end - start;
    
    // Check for overflow and excessively large regions (limit to 1GB)
    if (end < start || size > 1024*1024*1024) {
        fprintf(stderr, "[-] Invalid or too large memory region: %zu bytes\n", size);
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
    
    if (strlen(comm) > 0 || strlen(cmdline) > 0) {
        printf("[INFO] Process: %s\n", strlen(comm) > 0 ? comm : "<unknown>");
        if (strlen(cmdline) > 0)
            printf("[INFO] Cmdline: %s\n", cmdline);
    }
}

void check_exe_link(pid_t pid) {
    char exe_path[64], exe_target[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
    if (len == -1) {
        printf("[!] WARNING: /proc/%d/exe missing (possibly memfd or anonymous exec)\n", pid);
        return;
    }
    exe_target[len] = '\0';
    if (strstr(exe_target, "memfd:") || strstr(exe_target, "(deleted)") || strstr(exe_target, "anon_inode")) {
        printf("[!] Suspicious exe symlink for PID %d: %s\n", pid, exe_target);
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

void scan_maps_and_dump(pid_t pid) {
    print_process_info(pid);
    check_exe_link(pid);
    check_env_vars(pid);

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) return;

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
        
        // 1. RWX regions (code injection, self-modifying code)
        if (is_rwx) {
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
        else if (is_executable && is_anonymous && strstr(path, "[stack]") == NULL && 
                 strstr(path, "[vdso]") == NULL && strstr(path, "[vvar]") == NULL) {
            suspicious = 1;
            reason = "Anonymous executable mapping (possible injection)";
        }
        // 4. Executable heap (shellcode execution)
        else if (is_executable && strstr(path, "[heap]") != NULL) {
            suspicious = 1;
            reason = "Executable heap (shellcode/injection)";
        }
        // 5. Large anonymous writable mappings (staged payloads)
        else if (is_writable && is_anonymous && (end - start) > 1024*1024 && // > 1MB
                 strstr(path, "[stack]") == NULL && strstr(path, "[heap]") == NULL) {
            // These could become executable later via mprotect
            printf("[WARN] Large anonymous writable region in PID %d: %lx-%lx (%s) size=%luMB\n", 
                   pid, start, end, perms, (end-start)/(1024*1024));
        }

        if (suspicious) {
            suspicious_count++;
            printf("[!] ALERT: %s in PID %d\n", reason, pid);
            printf("[!]   Region: %lx-%lx (%s) %s\n", start, end, perms, path);
            dump_memory_region(pid, start, end);
        }
    }
    fclose(maps);
    
    if (suspicious_count > 0) {
        printf("[!] Total suspicious regions found: %d\n", suspicious_count);
    }
}

void handle_proc_event(struct cn_msg *cn_hdr) {
    struct proc_event *ev = (struct proc_event *)cn_hdr->data;

    if (ev->what == PROC_EVENT_EXEC) {
        pid_t pid = ev->event_data.exec.process_pid;
        pid_t ppid = ev->event_data.exec.process_tgid;
        printf("\n[EXEC] New process PID=%d PPID=%d\n", pid, ppid);
        printf("========================================\n");
        usleep(100000); // slight delay for maps to be available
        scan_maps_and_dump(pid);
        printf("========================================\n");
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, cleanup);

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
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Real-time process monitoring for malware detection\n\n");
            printf("Options:\n");
            printf("  --yara <file>     Enable YARA scanning with specified rules file\n");
            printf("  --continuous      Enable continuous monitoring (rescan processes every 30s)\n");
            printf("  --help, -h        Show this help message\n\n");
            printf("Detection capabilities:\n");
            printf("  - Memory injection (memfd_create, /dev/shm execution)\n");
            printf("  - Process hollowing and reflective loading\n");
            printf("  - RWX memory regions (JIT spray, self-modifying code)\n");
            printf("  - Fileless execution techniques\n");
            printf("  - Heap/stack code execution\n");
            printf("  - Suspicious environment variables (LD_PRELOAD)\n");
            return 0;
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

    // Increase socket receive buffer to prevent "No buffer space available" errors
    int rcvbuf_size = 1024 * 1024; // 1MB
    if (setsockopt(nl_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) == -1) {
        perror("setsockopt SO_RCVBUF");
        // Continue anyway, not fatal
    }

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
        char buf[8192];  // Increased from 1024 to handle more events
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
                        printf("\n[*] Performing periodic scan of all running processes...\n");
                        // Scan /proc for all PIDs
                        DIR *proc_dir = opendir("/proc");
                        if (proc_dir) {
                            struct dirent *entry;
                            while ((entry = readdir(proc_dir)) != NULL) {
                                // Check if directory name is a number (PID)
                                if (entry->d_type == DT_DIR) {
                                    pid_t pid = atoi(entry->d_name);
                                    if (pid > 0) {
                                        scan_maps_and_dump(pid);
                                    }
                                }
                            }
                            closedir(proc_dir);
                        }
                        last_full_scan = now;
                        printf("[*] Periodic scan complete\n\n");
                    }
                }
                // Sleep briefly to avoid busy-waiting
                usleep(10000);  // 10ms
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