#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <yara.h>
#include <openssl/sha.h>
#include <yara.h>
#include <openssl/sha.h>

#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

// Don't redefine MAX_PATH if YARA already defined it
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define HEX_DUMP_CONTEXT_DEFAULT 0x100  // Default: show 256 bytes of context
#define HEX_DUMP_CONTEXT_MAX 0x400      // Maximum: 1024 bytes

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_PURPLE  "\033[35m"

// Global state for JSON report generation
static FILE* g_json_report = NULL;
static int g_first_match = 1;
static size_t g_hex_dump_size = HEX_DUMP_CONTEXT_DEFAULT;

// Calculate SHA256 hash of data
void calculate_sha256(const uint8_t *data, size_t len, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

// Escape string for JSON output
void json_escape_string(const char *input, char *output, size_t output_size) {
    size_t j = 0;
    for (size_t i = 0; input[i] && j < output_size - 2; i++) {
        switch (input[i]) {
            case '"': case '\\': case '/': 
                output[j++] = '\\';
                output[j++] = input[i];
                break;
            case '\b': output[j++] = '\\'; output[j++] = 'b'; break;
            case '\f': output[j++] = '\\'; output[j++] = 'f'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n'; break;
            case '\r': output[j++] = '\\'; output[j++] = 'r'; break;
            case '\t': output[j++] = '\\'; output[j++] = 't'; break;
            default:
                if (input[i] < 32) {
                    j += snprintf(output + j, output_size - j, "\\u%04x", (unsigned char)input[i]);
                } else {
                    output[j++] = input[i];
                }
        }
    }
    output[j] = '\0';
}

// Calculate Shannon entropy of data
double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

// Print hex dump with context around a specific offset
void print_hex_dump(const uint8_t *data, size_t data_len, size_t match_offset, size_t match_len) {
    // Calculate context range
    size_t context = g_hex_dump_size / 2;
    size_t start = (match_offset >= context) ? (match_offset - context) : 0;
    size_t end = match_offset + match_len + context;
    if (end > data_len) end = data_len;
    
    // Round start down to 16-byte boundary for clean display
    start = (start / 16) * 16;
    
    printf("        Hex dump @ 0x%lx:\n", start);
    
    for (size_t offset = start; offset < end; offset += 16) {
        printf("        0x%016lx  ", offset);
        
        // Print hex bytes - color matched bytes in red
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < end) {
                // Check if this byte is within the match range
                int is_match = (offset + i >= match_offset && 
                              offset + i < match_offset + match_len);
                
                if (is_match) {
                    printf(COLOR_RED "%02x" COLOR_RESET " ", data[offset + i]);
                } else {
                    printf("%02x ", data[offset + i]);
                }
            } else {
                printf("   ");
            }
        }
        
        printf("  ");
        
        // Print ASCII representation - color matched bytes in red
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < end) {
                uint8_t c = data[offset + i];
                char display = (c >= 32 && c < 127) ? c : '.';
                
                // Check if this byte is within the match range
                int is_match = (offset + i >= match_offset && 
                              offset + i < match_offset + match_len);
                
                if (is_match) {
                    printf(COLOR_RED "%c" COLOR_RESET, display);
                } else {
                    printf("%c", display);
                }
            }
        }
        
        printf("\n");
    }
}

// Disassemble code at match location
void print_disassembly(const uint8_t *data, size_t data_len, size_t match_offset, size_t match_len) {
#ifdef HAVE_CAPSTONE
    csh handle;
    cs_insn *insn;
    
    // Determine architecture - assume x86-64 for now
    // In production, you'd detect this from ELF header
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "        [!] Failed to initialize Capstone\n");
        return;
    }
    
    // Start disassembly a bit before the match for context
    size_t dis_start = (match_offset >= 0x20) ? (match_offset - 0x20) : 0;
    size_t dis_len = match_len + 0x40;
    if (dis_start + dis_len > data_len) {
        dis_len = data_len - dis_start;
    }
    
    printf("\n    Disassembly:\n");
    
    size_t count = cs_disasm(handle, data + dis_start, dis_len, dis_start, 0, &insn);
    
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            // Check if instruction is within the match range
            int is_match = (insn[i].address >= match_offset && 
                          insn[i].address < match_offset + match_len);
            
            if (is_match) {
                // Color matched instructions in red with >> marker
                printf("        " COLOR_RED ">> 0x%lx: %s %s" COLOR_RESET "\n",
                       insn[i].address,
                       insn[i].mnemonic,
                       insn[i].op_str);
            } else {
                // Normal instructions without color
                printf("           0x%lx: %s %s\n",
                       insn[i].address,
                       insn[i].mnemonic,
                       insn[i].op_str);
            }
        }
        
        cs_free(insn, count);
    } else {
        printf("        [!] Failed to disassemble code\n");
    }
    
    cs_close(&handle);
#else
    printf("\n    Disassembly: (Capstone not available - install libcapstone-dev)\n");
#endif
}

// Generate hex dump lines for JSON
void json_hex_dump(FILE *fp, const uint8_t *data, size_t data_len, size_t match_offset, size_t match_len) {
    size_t context = g_hex_dump_size / 2;
    size_t start = (match_offset >= context) ? (match_offset - context) : 0;
    size_t end = match_offset + match_len + context;
    if (end > data_len) end = data_len;
    start = (start / 16) * 16;
    
    fprintf(fp, "          \"hexdump\": [\n");
    int first_line = 1;
    
    for (size_t offset = start; offset < end; offset += 16) {
        if (!first_line) fprintf(fp, ",\n");
        first_line = 0;
        
        fprintf(fp, "            \"        0x%016lx  ", offset);
        
        // Hex bytes
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < end) {
                fprintf(fp, "%02x ", data[offset + i]);
            } else {
                fprintf(fp, "   ");
            }
        }
        
        fprintf(fp, "  ");
        
        // ASCII
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < end) {
                uint8_t c = data[offset + i];
                char display = (c >= 32 && c < 127) ? c : '.';
                fprintf(fp, "%c", display);
            }
        }
        
        fprintf(fp, "\"");
    }
    
    fprintf(fp, "\n          ]");
}

// Generate disassembly for JSON
void json_disassembly(FILE *fp, const uint8_t *data, size_t data_len, size_t match_offset, size_t match_len) {
#ifdef HAVE_CAPSTONE
    csh handle;
    cs_insn *insn;
    
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(fp, ",\n          \"disasm\": []");
        return;
    }
    
    size_t dis_start = (match_offset >= 0x20) ? (match_offset - 0x20) : 0;
    size_t dis_len = match_len + 0x40;
    if (dis_start + dis_len > data_len) {
        dis_len = data_len - dis_start;
    }
    
    size_t count = cs_disasm(handle, data + dis_start, dis_len, dis_start, 0, &insn);
    
    fprintf(fp, ",\n          \"disasm\": [\n");
    
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if (i > 0) fprintf(fp, ",\n");
            
            int is_match = (insn[i].address >= match_offset && 
                          insn[i].address < match_offset + match_len);
            
            if (is_match) {
                fprintf(fp, "            \">> 0x%lx: %s %s\"",
                       insn[i].address, insn[i].mnemonic, insn[i].op_str);
            } else {
                fprintf(fp, "            \"   0x%lx: %s %s\"",
                       insn[i].address, insn[i].mnemonic, insn[i].op_str);
            }
        }
        cs_free(insn, count);
    }
    
    fprintf(fp, "\n          ]");
    cs_close(&handle);
#else
    fprintf(fp, ",\n          \"disasm\": []");
#endif
}

// YARA callback for each match
int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        const char* filepath = (const char*)user_data;
        
        printf("  " COLOR_RED "[+] File match at %s" COLOR_RESET "\n", filepath);
        
        // Get file size and calculate entropy
        struct stat st;
        if (stat(filepath, &st) == 0) {
            printf("      Size: %ld bytes\n", st.st_size);
            
            // Read file for entropy calculation
            FILE* f = fopen(filepath, "rb");
            if (f) {
                uint8_t* file_data = malloc(st.st_size);
                if (file_data) {
                    size_t read_bytes = fread(file_data, 1, st.st_size, f);
                    if (read_bytes == st.st_size) {
                        double entropy = calculate_entropy(file_data, st.st_size);
                        printf("      Entropy: %.3f\n", entropy);
                    }
                    
                    // Process string matches
                    printf("    Rule: " COLOR_PURPLE "%s" COLOR_RESET "\n", rule->identifier);
                    
                    YR_STRING* string;
                    yr_rule_strings_foreach(rule, string) {
                        YR_MATCH* match;
                        yr_string_matches_foreach(context, string, match) {
                            printf("\n    String %s: offset=0x%lx len=%d\n",
                                   string->identifier,
                                   (unsigned long)match->offset,
                                   (int)match->match_length);
                            
                            // Print hex dump around the match
                            if (match->offset < st.st_size) {
                                print_hex_dump(file_data, st.st_size, 
                                             match->offset, match->match_length);
                            }
                            
                            // Try to disassemble if it looks like code
                            // Simple heuristic: if string name contains "opcode" or "shellcode"
                            if (strstr(string->identifier, "opcode") != NULL ||
                                strstr(string->identifier, "shellcode") != NULL ||
                                strstr(string->identifier, "code") != NULL) {
                                print_disassembly(file_data, st.st_size,
                                                match->offset, match->match_length);
                            }
                        }
                    }
                    
                    printf("\n\n");
                    free(file_data);
                }
                fclose(f);
            }
        }
    }
    
    return CALLBACK_CONTINUE;
}

// YARA callback for JSON report mode
int yara_callback_json(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        const char* filepath = (const char*)user_data;
        
        // Get file size and calculate entropy + SHA256
        struct stat st;
        if (stat(filepath, &st) != 0) return CALLBACK_CONTINUE;
        
        FILE* f = fopen(filepath, "rb");
        if (!f) return CALLBACK_CONTINUE;
        
        uint8_t* file_data = malloc(st.st_size);
        if (!file_data) {
            fclose(f);
            return CALLBACK_CONTINUE;
        }
        
        size_t read_bytes = fread(file_data, 1, st.st_size, f);
        fclose(f);
        
        if (read_bytes != st.st_size) {
            free(file_data);
            return CALLBACK_CONTINUE;
        }
        
        double entropy = calculate_entropy(file_data, st.st_size);
        
        char sha256[65];
        calculate_sha256(file_data, st.st_size, sha256);
        
        char escaped_path[MAX_PATH * 2];
        json_escape_string(filepath, escaped_path, sizeof(escaped_path));
        
        // Write match entry (comma separated)
        if (!g_first_match) {
            fprintf(g_json_report, ",\n");
        }
        g_first_match = 0;
        
        fprintf(g_json_report, "    {\n");
        fprintf(g_json_report, "      \"type\": \"file\",\n");
        fprintf(g_json_report, "      \"file\": \"%s\",\n", escaped_path);
        fprintf(g_json_report, "      \"sha256\": \"%s\",\n", sha256);
        fprintf(g_json_report, "      \"size\": %ld,\n", st.st_size);
        fprintf(g_json_report, "      \"entropy\": %.14f,\n", entropy);
        fprintf(g_json_report, "      \"regions\": [\n");
        fprintf(g_json_report, "        {\n");
        fprintf(g_json_report, "          \"address\": \"0x0-0x%lx\",\n", st.st_size);
        fprintf(g_json_report, "          \"perms\": \"r--\",\n");
        fprintf(g_json_report, "          \"entropy\": %.14f,\n", entropy);
        fprintf(g_json_report, "          \"matches\": [\n");
        
        // Process each rule match
        int first_rule = 1;
        
        char escaped_rule[256];
        json_escape_string(rule->identifier, escaped_rule, sizeof(escaped_rule));
        
        if (!first_rule) fprintf(g_json_report, ",\n");
        first_rule = 0;
        
        fprintf(g_json_report, "            {\n");
        fprintf(g_json_report, "              \"rule\": \"%s\",\n", escaped_rule);
        fprintf(g_json_report, "              \"meta\": {\n");
        
        // Extract rule metadata
        int first_meta = 1;
        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (!first_meta) fprintf(g_json_report, ",\n");
            first_meta = 0;
            
            char escaped_id[256], escaped_val[1024];
            json_escape_string(meta->identifier, escaped_id, sizeof(escaped_id));
            
            fprintf(g_json_report, "                \"%s\": ", escaped_id);
            
            if (meta->type == META_TYPE_INTEGER) {
                fprintf(g_json_report, "%ld", (long)meta->integer);
            } else if (meta->type == META_TYPE_STRING) {
                json_escape_string(meta->string, escaped_val, sizeof(escaped_val));
                fprintf(g_json_report, "\"%s\"", escaped_val);
            } else if (meta->type == META_TYPE_BOOLEAN) {
                fprintf(g_json_report, "%s", meta->integer ? "true" : "false");
            }
        }
        
        fprintf(g_json_report, "\n              },\n");
        fprintf(g_json_report, "              \"strings\": [\n");
        
        // Process string matches
        int first_string = 1;
        YR_STRING* string;
        yr_rule_strings_foreach(rule, string) {
            YR_MATCH* match;
            yr_string_matches_foreach(context, string, match) {
                if (!first_string) fprintf(g_json_report, ",\n");
                first_string = 0;
                
                char escaped_str_id[256];
                json_escape_string(string->identifier, escaped_str_id, sizeof(escaped_str_id));
                
                fprintf(g_json_report, "                {\n");
                fprintf(g_json_report, "                  \"identifier\": \"%s\",\n", escaped_str_id);
                fprintf(g_json_report, "                  \"offset\": %lu,\n", (unsigned long)match->offset);
                fprintf(g_json_report, "                  \"length\": %d,\n", match->match_length);
                
                // Hex representation of matched bytes
                fprintf(g_json_report, "                  \"hex\": \"");
                for (int i = 0; i < match->match_length && i < 256; i++) {
                    fprintf(g_json_report, "%02x", file_data[match->offset + i]);
                }
                fprintf(g_json_report, "\",\n");
                
                // Hex dump
                json_hex_dump(g_json_report, file_data, st.st_size, match->offset, match->match_length);
                
                // Disassembly if looks like code
                if (strstr(string->identifier, "opcode") != NULL ||
                    strstr(string->identifier, "shellcode") != NULL ||
                    strstr(string->identifier, "code") != NULL) {
                    json_disassembly(g_json_report, file_data, st.st_size, match->offset, match->match_length);
                }
                
                fprintf(g_json_report, "\n                }");
            }
        }
        
        fprintf(g_json_report, "\n              ]\n");
        fprintf(g_json_report, "            }\n");
        fprintf(g_json_report, "          ]\n");
        fprintf(g_json_report, "        }\n");
        fprintf(g_json_report, "      ]\n");
        fprintf(g_json_report, "    }");
        
        free(file_data);
    }
    
    return CALLBACK_CONTINUE;
}

// Scan a single file with YARA rules
int scan_file(YR_RULES* rules, const char* filepath) {
    if (!g_json_report) {
        printf("[*] Scanning file: " COLOR_YELLOW "%s" COLOR_RESET "\n", filepath);
    }
    
    int result = yr_rules_scan_file(rules, filepath, 0, 
                                     g_json_report ? yara_callback_json : yara_callback, 
                                     (void*)filepath, 0);
    
    if (result != ERROR_SUCCESS) {
        if (!g_json_report) {
            fprintf(stderr, "  [!] Error scanning file: %d\n", result);
        }
        return -1;
    }
    
    return 0;
}

// Count files in directory recursively
int count_files_recursive(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    
    if (S_ISREG(st.st_mode)) {
        return 1;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        return 0;
    }
    
    int count = 0;
    DIR* dir = opendir(path);
    if (!dir) return 0;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        
        count += count_files_recursive(fullpath);
    }
    
    closedir(dir);
    return count;
}

// Scan directory recursively
void scan_directory(YR_RULES* rules, const char* dirpath) {
    DIR* dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "[!] Cannot open directory: %s\n", dirpath);
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        
        struct stat st;
        if (stat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                scan_directory(rules, fullpath);
            } else if (S_ISREG(st.st_mode)) {
                scan_file(rules, fullpath);
            }
        }
    }
    
    closedir(dir);
}

void print_usage(const char* progname) {
    printf("Usage: %s [OPTIONS] <yara_rules> <file_or_directory>\n", progname);
    printf("\n");
    printf("Standalone YARA scanner with detailed match information\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  yara_rules          Path to YARA rules file (.yar)\n");
    printf("  file_or_directory   File or directory to scan\n");
    printf("\n");
    printf("Options:\n");
    printf("  -r, --report        Generate JSON report (scan_report_<sha256>.json)\n");
    printf("  -s, --size <bytes>  Hex dump context size in bytes (default: 256, max: 1024)\n");
    printf("\n");
    printf("Output includes:\n");
    printf("  - File size and entropy\n");
    printf("  - Matched rule names\n");
    printf("  - String match offsets and lengths\n");
    printf("  - Hex dump with context around matches\n");
    printf("  - Disassembly for code patterns\n");
}

int main(int argc, char** argv) {
    int generate_report = 0;
    const char* rules_file = NULL;
    const char* scan_target = NULL;
    
    // Parse arguments - accept -r/--report and -s/--size anywhere
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--report") == 0) {
            generate_report = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) {
            if (i + 1 < argc) {
                int size = atoi(argv[++i]);
                if (size > 0 && size <= HEX_DUMP_CONTEXT_MAX) {
                    g_hex_dump_size = size;
                } else {
                    fprintf(stderr, "[!] Invalid hex dump size: %d (max: %d)\n", size, HEX_DUMP_CONTEXT_MAX);
                    return 1;
                }
            } else {
                fprintf(stderr, "[!] Missing value for -s/--size option\n");
                return 1;
            }
        } else if (!rules_file) {
            rules_file = argv[i];
        } else if (!scan_target) {
            scan_target = argv[i];
        }
    }
    
    if (!rules_file || !scan_target) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize YARA
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Failed to initialize YARA: %d\n", result);
        return 1;
    }
    
    // Extract rule filename from path
    const char* rules_filename = strrchr(rules_file, '/');
    rules_filename = rules_filename ? rules_filename + 1 : rules_file;
    
    if (!generate_report) {
        printf("[*] Loading YARA: %s\n", rules_filename);
    }
    
    // Compile YARA rules
    YR_COMPILER* compiler = NULL;
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Failed to create YARA compiler: %d\n", result);
        yr_finalize();
        return 1;
    }
    
    FILE* rule_file = fopen(rules_file, "r");
    if (!rule_file) {
        fprintf(stderr, "[!] Cannot open rules file: %s\n", rules_file);
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }
    
    int errors = yr_compiler_add_file(compiler, rule_file, NULL, rules_file);
    fclose(rule_file);
    
    if (errors > 0) {
        fprintf(stderr, "[!] Failed to compile YARA rules\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }
    
    YR_RULES* rules = NULL;
    result = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Failed to get compiled rules: %d\n", result);
        yr_finalize();
        return 1;
    }
    
    // Setup JSON report if requested
    char report_filename[MAX_PATH];
    if (generate_report) {
        // Calculate SHA256 of the scan target for report filename
        struct stat st_temp;
        char target_sha256[65] = {0};
        
        if (stat(scan_target, &st_temp) == 0 && S_ISREG(st_temp.st_mode)) {
            // For single file, use its SHA256
            FILE* f_temp = fopen(scan_target, "rb");
            if (f_temp) {
                uint8_t* data_temp = malloc(st_temp.st_size);
                if (data_temp) {
                    if (fread(data_temp, 1, st_temp.st_size, f_temp) == st_temp.st_size) {
                        calculate_sha256(data_temp, st_temp.st_size, target_sha256);
                    }
                    free(data_temp);
                }
                fclose(f_temp);
            }
        } else {
            // For directory, use directory name hash
            calculate_sha256((const uint8_t*)scan_target, strlen(scan_target), target_sha256);
        }
        
        snprintf(report_filename, sizeof(report_filename), "scan_report_%s.json", target_sha256);
        
        g_json_report = fopen(report_filename, "w");
        if (!g_json_report) {
            fprintf(stderr, "[!] Cannot create report file: %s\n", report_filename);
            yr_rules_destroy(rules);
            yr_finalize();
            return 1;
        }
        
        // Write JSON header
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        
        // Get microseconds
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        
        fprintf(g_json_report, "{\n");
        fprintf(g_json_report, "  \"generated\": \"%s.%06ld\",\n", timestamp, ts.tv_nsec / 1000);
        fprintf(g_json_report, "  \"matches\": [\n");
        
        g_first_match = 1;
    }
    
    // Check if target is file or directory
    struct stat st;
    if (stat(scan_target, &st) != 0) {
        fprintf(stderr, "[!] Cannot access: %s\n", scan_target);
        if (g_json_report) fclose(g_json_report);
        yr_rules_destroy(rules);
        yr_finalize();
        return 1;
    }
    
    if (S_ISREG(st.st_mode)) {
        if (!generate_report) {
            printf("[*] File/dir scan mode enabled. Files to scan: 1\n\n");
        }
        scan_file(rules, scan_target);
    } else if (S_ISDIR(st.st_mode)) {
        int file_count = count_files_recursive(scan_target);
        if (!generate_report) {
            printf("[*] File/dir scan mode enabled. Files to scan: %d\n\n", file_count);
        }
        scan_directory(rules, scan_target);
    } else {
        fprintf(stderr, "[!] Target is neither a regular file nor directory\n");
        if (g_json_report) fclose(g_json_report);
        yr_rules_destroy(rules);
        yr_finalize();
        return 1;
    }
    
    // Close JSON report if generated
    if (generate_report && g_json_report) {
        fprintf(g_json_report, "\n  ]\n");
        fprintf(g_json_report, "}\n");
        fclose(g_json_report);
        printf("[*] Report saved to: %s\n", report_filename);
    }
    
    // Cleanup
    yr_rules_destroy(rules);
    yr_finalize();
    
    return 0;
}
