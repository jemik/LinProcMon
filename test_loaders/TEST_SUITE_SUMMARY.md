# Test Suite: Meterpreter Detection Verification

## Overview

This test suite verifies that LinProcMon successfully:
1. **Detects** all 5 malware techniques
2. **Dumps** memory containing payloads
3. **Enables** YARA scanning of meterpreter signatures

## Test Files Created

### Loaders (C source)
- `1_memfd_loader.c` - Fileless execution via memfd_create()
- `2_rwx_injection_loader.c` - Code injection to RWX memory
- `3_deleted_binary_loader.c` - Binary replacement (deleted file)
- `4_heap_execution_loader.c` - Shellcode on executable heap
- `5_preload_loader.c` - LD_PRELOAD library hijacking

### Scripts
- `compile_all.sh` - Compiles all 5 loaders
- `run_all_tests.sh` - Orchestrates testing all loaders
- `scan_dumps.sh` - Scans memory dumps with YARA

### Detection Rules
- `meterpreter_detection.yar` - 8 YARA rules for meterpreter signatures

### Documentation
- `README.md` - Complete test suite documentation
- `QUICK_START.md` - Quick testing guide with commands

## Quick Test Run

```bash
# 1. Compile all loaders
cd test_loaders
chmod +x *.sh
./compile_all.sh

# 2. Run test 2 (easiest to verify)
./test_output/2_rwx_injection_loader &
TEST_PID=$!

# 3. Monitor with LinProcMon (in another terminal)
cd ..
sudo ./realtime_memdump_tool -p $TEST_PID -o test2_report.json

# 4. Wait for completion (30 seconds)

# 5. Verify results
cd test_loaders
./scan_dumps.sh
```

## Expected Output

### From Loader
```
[*] Test Case 2: RWX Memory Injection
[*] This simulates malware injecting code into RWX memory
[+] Allocated RWX memory at: 0x7f1234567000
[+] Copied 31 bytes of shellcode to RWX region
[+] Added meterpreter signature patterns for YARA detection
[+] Sleeping 30 seconds to allow memory dump...
[!] Monitor should detect: RWX memory region
[!] Memory dump should contain shellcode + meterpreter signatures
[!] YARA should match meterpreter patterns
```

### From LinProcMon
```
[ALERT] RWX memory detected! PID=12345
[!] Executable memory in suspicious location | PID=12345 | 7f1234567000-7f1234568000 (rwxp)
[*] Dumping memory region: 7f1234567000-7f1234568000 (4096 bytes)
[+] Memory dump saved: test2_report.json_12345_7f1234567000_memory.dump
```

### From YARA Scan
```
Meterpreter_Stage_Marker test2_report.json_12345_7f1234567000_memory.dump
Meterpreter_Configuration test2_report.json_12345_7f1234567000_memory.dump
Shellcode_Generic_Execve test2_report.json_12345_7f1234567000_memory.dump
RWX_Suspicious_Pattern test2_report.json_12345_7f1234567000_memory.dump

Total YARA rule matches: 4
[✓] Successfully detected meterpreter signatures in memory dumps
[✓] LinProcMon correctly captured malicious payloads
```

## Verification Matrix

| Test | Detection Alert | Memory Dump | YARA Matches | Status |
|------|----------------|-------------|--------------|--------|
| 1. memfd | "memfd execution" | ✓ memfd region | Shellcode patterns | ⬜ Not tested |
| 2. RWX | "RWX regions" | ✓ Anonymous RWX | 3-4 meterpreter rules | ⬜ Not tested |
| 3. Deleted | "deleted file" | ✓ Process memory | Config strings | ⬜ Not tested |
| 4. Heap | "Executable heap" | ✓ Heap region | 4-5 meterpreter rules | ⬜ Not tested |
| 5. Preload | "LD_PRELOAD" | ✓ Library .so | Stage URLs | ⬜ Not tested |

## Meterpreter Signatures Embedded

Each test loader contains realistic meterpreter indicators:

### Strings
- `linux/x64/meterpreter` - Linux x64 meterpreter payload
- `core_loadlib` - Core library loading function
- `socket_connect` - Socket connection function
- `linux/meterpreter/reverse_tcp` - Payload type
- `LHOST=127.0.0.1 LPORT=4444` - Connection config
- Stage URLs with /stage path

### Binary Patterns
- `MSSF` magic bytes (Metasploit Stream Socket Format)
- ELF header: `7F 45 4C 46 02 01 01` (x64 ELF signature)
- IP address bytes: `7F 00 00 01` (127.0.0.1)
- Port bytes: `11 5C` (4444 in network order)
- x64 shellcode opcodes: `48 31 D2` (xor rdx), `B0 3B` (execve), `0F 05` (syscall)

### Memory Layout
- Shellcode at region start
- Signatures at offsets: +256, +512, +1024, +2048, +4096
- Configuration blocks interspersed
- Realistic staging URLs

## Safety Features

⚠️ **All loaders are safe for testing:**

1. **No actual execution** - Shellcode execution lines are commented out
2. **30-second timeout** - Process exits automatically
3. **Local-only config** - All IPs are 127.0.0.1 (localhost)
4. **Test shellcode** - Uses simple execve("/bin/sh") not real meterpreter
5. **No network** - No connections attempted

To run with real meterpreter:
```bash
# Generate real payload
msfvenom -p linux/x64/meterpreter/reverse_tcp \
         LHOST=127.0.0.1 LPORT=4444 -f c > real.c

# Replace payload[] array in loader
# ⚠️ Only in isolated test VM!
```

## Troubleshooting

### Compilation Errors
```bash
# Missing includes
sudo apt-get install build-essential linux-headers-$(uname -r)

# memfd_create not found
# Kernel < 3.17 - skip test 1
```

### Runtime Errors
```bash
# Permission denied on ptrace
sudo sysctl kernel.yama.ptrace_scope=0

# Process exits immediately
# Run loader directly to see error:
./test_output/2_rwx_injection_loader
```

### No YARA Matches
```bash
# Check dump has content
ls -lh *.dump

# Manual string search
strings test2_report.json_*_memory.dump | grep -i meterpreter

# Verify YARA installed
yara --version
```

## Next Steps After Testing

1. **Document results** - Fill in verification matrix
2. **Collect screenshots** - Show alerts + YARA matches  
3. **Performance test** - Time memory dump speed
4. **Scale test** - Run all 5 loaders simultaneously
5. **Real malware** - Test with actual meterpreter samples (isolated VM only!)

## Files Generated During Testing

```
test_loaders/
├── test_output/
│   ├── 1_memfd_loader          (executable)
│   ├── 2_rwx_injection_loader  (executable)
│   ├── 3_deleted_binary_loader (executable)
│   ├── 4_heap_execution_loader (executable)
│   ├── 5_preload_victim        (executable)
│   └── malicious_preload.so    (shared library)
├── test1_report.json           (JSON report)
├── test1_report.json_12345_*_memory.dump  (memory dumps)
├── test2_report.json
├── test2_report.json_12346_*_memory.dump
└── ... (test3-5 similar)
```

## Success Criteria

✅ **Complete success requires:**
- All 5 loaders compile without warnings
- Each loader runs 30 seconds without crashing
- LinProcMon generates JSON report per test
- Each report contains expected alert type
- Memory dumps created (size > 0 bytes)
- YARA matches ≥2 rules per dump
- No false negatives (all detected)
- No false positives (legitimate process not alerted)

## Contact & Support

Issues with test suite:
1. Check `QUICK_START.md` for detailed commands
2. Review `README.md` for troubleshooting
3. Run loaders with `strace -f` to debug
4. Check LinProcMon JSON report format

This test suite validates LinProcMon's core value proposition: **detecting fileless malware and capturing payloads for forensic analysis.**
