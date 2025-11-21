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

#ifdef ENABLE_YARA
#include <yara.h>
#endif

#define MAX_LINE 4096

int nl_sock;
const char* yara_rules_path = NULL;

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
    check_exe_link(pid);
    check_env_vars(pid);

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) return;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char path[MAX_LINE] = "";

        // Parse maps line: address range, permissions, and optional path
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) < 3)
            continue;

        if (strchr(perms, 'x') != NULL && (
            strstr(path, "memfd:") != NULL ||
            strstr(path, "/dev/shm") != NULL ||
            strstr(path, "/proc/self") != NULL ||
            strstr(path, "/tmp/") != NULL ||
            strstr(path, "anon_inode") != NULL ||
            (strlen(path) == 0 && strstr(perms, "rwx") != NULL))) {

            printf("[!] Suspicious memory detected in PID %d: %lx-%lx (%s) %s\n", pid, start, end, perms, path);
            dump_memory_region(pid, start, end);
        }
    }
    fclose(maps);
}

void handle_proc_event(struct cn_msg *cn_hdr) {
    struct proc_event *ev = (struct proc_event *)cn_hdr->data;

    if (ev->what == PROC_EVENT_EXEC) {
        pid_t pid = ev->event_data.exec.process_pid;
        pid_t ppid = ev->event_data.exec.process_tgid;
        printf("[EXEC] New process PID=%d PPID=%d\n", pid, ppid);
        usleep(100000); // slight delay for maps to be available
        scan_maps_and_dump(pid);
    }
}

int main(int argc, char **argv) {
    signal(SIGINT, cleanup);

    if (argc >= 3 && strcmp(argv[1], "--yara") == 0) {
        yara_rules_path = argv[2];
#ifdef ENABLE_YARA
        printf("[+] YARA scanning enabled using rule file: %s\n", yara_rules_path);
#else
        printf("[!] WARNING: YARA support not compiled in. --yara flag ignored.\n");
        printf("[!] Recompile with -DENABLE_YARA and link against libyara to enable YARA scanning.\n");
#endif
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

    while (1) {
        char buf[1024];
        ssize_t len = recv(nl_sock, buf, sizeof(buf), 0);
        if (len == -1) {
            if (errno == EINTR) continue;
            perror("recv"); break;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (NLMSG_OK(nlh, len)) {
            struct cn_msg *cn_hdr = NLMSG_DATA(nlh);
            handle_proc_event(cn_hdr);
            nlh = NLMSG_NEXT(nlh, len);
        }
    }

    return 0;
}