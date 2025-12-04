# scan_engine - Standalone YARA Scanner

A standalone YARA scanner that provides detailed match information including hex dumps, entropy calculation, and disassembly of matched code patterns.

## Features

- **Recursive Directory Scanning**: Scan entire directories and subdirectories
- **Detailed Match Information**:
  - File size and Shannon entropy
  - Matched YARA rule names
  - String match offsets and lengths
  - Hex dump with context around matches
  - Automatic disassembly for code patterns (x86-64)
- **Clean Output Format**: Easy to read and parse

## Dependencies

- **libyara**: YARA library for pattern matching
- **libcapstone**: Capstone disassembly framework
- **libm**: Math library (for entropy calculation)

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install libyara-dev libcapstone-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install yara-devel capstone-devel
```

## Building

```bash
# Using the provided Makefile
make -f Makefile.scan_engine

# Or manually
gcc -o scan_engine scan_engine.c -lyara -lcapstone -lm -Wall -O2
```

## Usage

```bash
./scan_engine <yara_rules.yar> <file_or_directory>
```

### Examples

**Scan a single file:**
```bash
./scan_engine rules/malware.yar suspicious_binary
```

**Scan a directory recursively:**
```bash
./scan_engine rules/shellcode.yar sandbox_output/memory_dumps/
```

**Scan with custom YARA rules:**
```bash
./scan_engine ELF_MSF_REV_SHELL.yar memory_dumps/
```

## Output Format

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

- **Size**: File size in bytes
- **Entropy**: Shannon entropy (0-8, higher = more random/encrypted)
- **Rule**: Name of the matched YARA rule
- **String**: Identifier and position of matched string
- **Hex dump**: Raw bytes around the match with ASCII representation
- **Disassembly**: x86-64 assembly code (marked with >> for matched bytes)

## Tips

1. **Disassembly Trigger**: Automatic disassembly is triggered for strings containing:
   - `opcode`
   - `shellcode`
   - `code`

2. **Entropy Interpretation**:
   - < 4.0: Low entropy (text, uncompressed)
   - 4.0-6.0: Medium entropy (code, mixed data)
   - > 6.0: High entropy (compressed/encrypted)

3. **Performance**: For large directories, consider using specific YARA rules to reduce false positives

## Integration

Can be used standalone or integrated into analysis pipelines:

```bash
# Scan all dumps from LinProcMon
find sandbox_* -name "*.bin" -exec ./scan_engine rules.yar {} \;

# JSON output (future feature)
./scan_engine --json rules.yar samples/ > results.json
```

## License

Same as LinProcMon project

## Author

Part of LinProcMon - Linux Process Monitor for malware analysis
