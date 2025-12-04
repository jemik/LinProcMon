# scan_engine - Standalone YARA Scanner

A standalone YARA scanner that provides detailed match information including hex dumps, entropy calculation, disassembly of matched code patterns, and comprehensive JSON reporting.

## Features

- **Recursive Directory Scanning**: Scan entire directories and subdirectories
- **JSON Report Generation**: Generate detailed JSON reports with all match information
- **Configurable Hex Dumps**: Adjustable hex dump context size (default: 256 bytes, max: 1024 bytes)
- **Detailed Match Information**:
  - File SHA256 hash
  - File size and Shannon entropy
  - Matched YARA rule names with metadata
  - String match offsets and lengths
  - Hex dump with context around matches
  - Automatic disassembly for code patterns (x86-64)
- **Color-Coded Output**: Easy-to-read terminal output with color highlighting
- **Portable Build Options**: Support for static and dynamic linking

## Dependencies

- **libyara**: YARA library for pattern matching (required)
- **libcrypto** (OpenSSL): For SHA256 calculation (required)
- **libcapstone**: Capstone disassembly framework (optional)
- **libm**: Math library for entropy calculation (required)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libyara-dev libssl-dev libcapstone-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install yara-devel openssl-devel capstone-devel
```

## Building

### Dynamic Build (Default)
```bash
# Using the provided Makefile
make -f Makefile.scan_engine

# Or manually
gcc -o scan_engine scan_engine.c -lyara -lcrypto -lcapstone -lm -Wall -O2
```

### Static Build (Portable)
```bash
# Build static binary that works on any Linux system
make -f Makefile.scan_engine static
```

**Note**: Capstone is optional. If not available, the scanner will work without disassembly features.

## Usage

```bash
./scan_engine [OPTIONS] <yara_rules.yar> <file_or_directory>
```

### Options

- `-r, --report` - Generate JSON report (scan_report_<sha256>.json)
- `-s, --size <bytes>` - Hex dump context size in bytes (default: 256, max: 1024)

### Examples

**Scan a single file:**
```bash
./scan_engine rules/malware.yar suspicious_binary
```

**Scan a directory recursively:**
```bash
./scan_engine rules/shellcode.yar sandbox_output/memory_dumps/
```

**Generate JSON report:**
```bash
./scan_engine -r ELF_MSF_REV_SHELL.yar memory_dumps/
```

**Generate report with larger hex dumps:**
```bash
./scan_engine -r -s 512 rules.yar target_dir/
```

**Maximum hex dump context:**
```bash
./scan_engine -r -s 1024 rules.yar sample.bin
```

## Output Format

### Terminal Output (Color-Coded)

```
[*] Loading YARA: ELF_MSF_REV_SHELL.yar
[*] File/dir scan mode enabled. Files to scan: 5

[*] Scanning file: memory_dumps/memfd_dump_123456_malware.bin
  [+] File match at memory_dumps/memfd_dump_123456_malware.bin
      Size: 74 bytes
      Entropy: 5.069
    Rule: ELF_TROJ_MSF_SHELL

    String $opcode: offset=0x30 len=14
        Hex dump @ 0x20:
        0x0000000000000020  2a 58 0f 05 6a 03 5e 48 ff ce 6a 21 58 0f 05 75   *X..j.^H..j!X..u
        0x0000000000000030  f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53  .j;X.H./bin/sh.S
        0x0000000000000040  48 89 e7 52 57 48 89 e6 0f 05                     H..RWH....

    Disassembly:
         0x24: push 3
         0x26: pop rsi
         0x27: dec rsi
         0x2a: push 0x21
         0x2c: pop rax
         0x2d: syscall 
         0x2f: jne 0x27
      >> 0x31: push 0x3b
      >> 0x33: pop rax
      >> 0x34: cdq 
      >> 0x35: movabs rbx, 0x68732f6e69622f
         0x3f: push rbx
         0x40: mov rdi, rsp
         0x43: push rdx
         0x44: push rdi
         0x45: mov rsi, rsp
         0x48: syscall 
```

**Color Scheme:**
- Yellow: File paths
- Purple: Rule names
- Red: Match indicators, matched bytes, matched instructions (>>)

### JSON Report Format

When using `-r` or `--report`, generates a file named `scan_report_<sha256>.json`:

```json
{
  "generated": "2025-12-04 10:51:51.629051",
  "matches": [
    {
      "type": "file",
      "file": "memory_dumps/memfd_dump_123456_malware.bin",
      "sha256": "ae21b93ab9ab6d1ce5eb8cf9a4d414687cbafec0af76f881156471d55cc2b792",
      "size": 74,
      "entropy": 5.06882671756724,
      "regions": [
        {
          "address": "0x0-0x4a",
          "perms": "r--",
          "entropy": 5.06882671756724,
          "matches": [
            {
              "rule": "ELF_TROJ_MSF_SHELL",
              "meta": {
                "description": "Detects Metasploit reverse shell elf payload",
                "author": "Jesper Mikkelsen",
                "score": 80
              },
              "strings": [
                {
                  "identifier": "$opcode",
                  "offset": 48,
                  "length": 14,
                  "hex": "f66a3b589948bb2f62696e2f7368",
                  "hexdump": [
                    "        0x0000000000000020  2a 58 0f 05 6a 03 5e 48 ff ce 6a 21 58 0f 05 75   *X..j.^H..j!X..u",
                    "        0x0000000000000030  f6 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53   .j;X.H./bin/sh.S",
                    "        0x0000000000000040  48 89 e7 52 57 48 89 e6 0f 05                     H..RWH...."
                  ],
                  "disasm": [
                    "   0x24: push 3",
                    "   0x26: pop rsi",
                    ">> 0x31: push 0x3b",
                    ">> 0x33: pop rax",
                    "   0x40: mov rdi, rsp"
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

## Creating YARA Rules

Example YARA rule for detecting Metasploit reverse shells:

```yara
rule ELF_TROJ_MSF_SHELL {
    meta:
        description = "Detects Metasploit reverse shell in ELF binaries"
        author = "Security Researcher"
        date = "2025-12-04"
        
    strings:
        $opcode = { 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 }
        $socket_call = { 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 }
        
    condition:
        uint32(0) == 0x464c457f and  // ELF magic
        any of ($opcode, $socket_call)
}
```

## Output Fields

- **SHA256**: File hash for unique identification
- **Size**: File size in bytes
- **Entropy**: Shannon entropy (0-8, higher = more random/encrypted)
- **Rule**: Name of the matched YARA rule
- **Meta**: All metadata fields from the YARA rule
- **String**: Identifier and position of matched string
- **Hex**: Raw hex representation of matched bytes
- **Hexdump**: Formatted hex dump with ASCII representation and configurable context
- **Disasm**: x86-64 assembly code (marked with >> for matched instructions)

## Tips

1. **Disassembly Trigger**: Automatic disassembly is triggered for strings containing:
   - `opcode`
   - `shellcode`
   - `code`

2. **Entropy Interpretation**:
   - < 4.0: Low entropy (text, uncompressed)
   - 4.0-6.0: Medium entropy (code, mixed data)
   - > 6.0: High entropy (compressed/encrypted)

3. **Hex Dump Size**: Adjust based on your needs:
   - 256 bytes (default): Good balance for most use cases
   - 512 bytes: More context for complex patterns
   - 1024 bytes: Maximum context for detailed analysis

4. **Performance**: For large directories, consider using specific YARA rules to reduce false positives

5. **Report Naming**: JSON reports are named using SHA256 of the scan target:
   - For files: SHA256 of file contents
   - For directories: SHA256 of directory path

## Integration

Can be used standalone or integrated into analysis pipelines:

```bash
# Scan all dumps from LinProcMon
find sandbox_* -name "*.bin" -exec ./scan_engine rules.yar {} \;

# Generate JSON reports for batch analysis
for dir in sandbox_*; do
    ./scan_engine -r -s 512 rules.yar "$dir"
done

# Parse JSON reports with jq
jq '.matches[].file' scan_report_*.json

# Extract all matched rule names
jq -r '.matches[].regions[].matches[].rule' scan_report_*.json | sort -u

# Find high entropy files
jq -r '.matches[] | select(.entropy > 6.5) | .file' scan_report_*.json
```

## Portability

The scanner supports two build modes:

**Dynamic Build** (default):
- Smaller binary (~50KB)
- Requires libraries installed on target system
- Use for development and systems with dependencies

**Static Build**:
- Larger binary (~5-10MB)
- Works on any Linux system (same architecture)
- Ideal for deployment and analysis environments
- Build with: `make -f Makefile.scan_engine static`

## License

Same as LinProcMon project

## Author

Part of LinProcMon - Linux Process Monitor for malware analysis
