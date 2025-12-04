#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <yara.h>


#include <capstone/capstone.h>


// Don't redefine MAX_PATH if YARA already defined it
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

#define HEX_DUMP_CONTEXT 0x40  // Show 64 bytes of context around match

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_PURPLE  "\033[35m"

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
    size_t start = (match_offset >= 0x10) ? (match_offset - 0x10) : 0;
    size_t end = match_offset + match_len + 0x10;
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

// Scan a single file with YARA rules
int scan_file(YR_RULES* rules, const char* filepath) {
    printf("[*] Scanning file: " COLOR_YELLOW "%s" COLOR_RESET "\n", filepath);
    
    int result = yr_rules_scan_file(rules, filepath, 0, yara_callback, 
                                     (void*)filepath, 0);
    
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "  [!] Error scanning file: %d\n", result);
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
    printf("Usage: %s <yara_rules> <file_or_directory>\n", progname);
    printf("\n");
    printf("Standalone YARA scanner with detailed match information\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  yara_rules          Path to YARA rules file (.yar)\n");
    printf("  file_or_directory   File or directory to scan\n");
    printf("\n");
    printf("Output includes:\n");
    printf("  - File size and entropy\n");
    printf("  - Matched rule names\n");
    printf("  - String match offsets and lengths\n");
    printf("  - Hex dump with context around matches\n");
    printf("  - Disassembly for code patterns\n");
}

int main(int argc, char** argv) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* rules_file = argv[1];
    const char* scan_target = argv[2];
    
    // Initialize YARA
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "[!] Failed to initialize YARA: %d\n", result);
        return 1;
    }
    
    // Extract rule filename from path
    const char* rules_filename = strrchr(rules_file, '/');
    rules_filename = rules_filename ? rules_filename + 1 : rules_file;
    
    printf("[*] Loading YARA: %s\n", rules_filename);
    
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
    
    // Check if target is file or directory
    struct stat st;
    if (stat(scan_target, &st) != 0) {
        fprintf(stderr, "[!] Cannot access: %s\n", scan_target);
        yr_rules_destroy(rules);
        yr_finalize();
        return 1;
    }
    
    if (S_ISREG(st.st_mode)) {
        printf("[*] File/dir scan mode enabled. Files to scan: 1\n\n");
        scan_file(rules, scan_target);
    } else if (S_ISDIR(st.st_mode)) {
        int file_count = count_files_recursive(scan_target);
        printf("[*] File/dir scan mode enabled. Files to scan: %d\n\n", file_count);
        scan_directory(rules, scan_target);
    } else {
        fprintf(stderr, "[!] Target is neither a regular file nor directory\n");
        yr_rules_destroy(rules);
        yr_finalize();
        return 1;
    }
    
    // Cleanup
    yr_rules_destroy(rules);
    yr_finalize();
    
    return 0;
}
