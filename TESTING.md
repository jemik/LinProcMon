# LinProcMon Testing Guide

## Quick Start

### Run All Tests
Test all 5 unpacking scenarios with eBPF integration:
```bash
cd test_loaders
sudo ./run_all_tests.sh
```

### Run Individual Tests

Run a single malware sample with eBPF integration:
```bash
sudo ./run_integrated.sh <MALWARE_SAMPLE>
```

Examples:
```bash
# Test 1: memfd fileless execution
sudo ./run_integrated.sh ./test_loaders/test_output/1_memfd_loader

# Test 2: RWX injection
sudo ./run_integrated.sh ./test_loaders/test_output/2_rwx_injection_loader

# Test 3: Deleted binary
sudo ./run_integrated.sh ./test_loaders/test_output/3_deleted_binary_loader

# Test 4: Heap execution
sudo ./run_integrated.sh ./test_loaders/test_output/4_heap_execution_loader

# Test 5: LD_PRELOAD hijacking
export LD_PRELOAD=./test_loaders/test_output/malicious_preload.so
sudo -E ./run_integrated.sh ./test_loaders/test_output/5_preload_victim
```

## What Gets Tested

### Test Case 1: memfd Fileless Execution
- **Technique**: `memfd_create()` + `fexecve()`
- **Detection**: MEMFD_CREATE eBPF event + memfd file scanning
- **Expected Dump**: 74-byte Meterpreter stub

### Test Case 2: RWX Memory Injection
- **Technique**: `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` + shellcode copy
- **Detection**: MMAP_EXEC eBPF event with `prot=7`
- **Expected Dump**: Shellcode from RWX region

### Test Case 3: Deleted Binary Replacement
- **Technique**: Write binary, execute, delete file
- **Detection**: `/proc/PID/exe` points to "(deleted)" file
- **Expected Dump**: Binary from memory (reconstructed)

### Test Case 4: Heap Execution
- **Technique**: Heap allocation + `mprotect(PROT_EXEC)` + shellcode
- **Detection**: MPROTECT_EXEC eBPF event
- **Expected Dump**: Shellcode from heap region

### Test Case 5: LD_PRELOAD Hijacking
- **Technique**: `LD_PRELOAD` environment variable + malicious .so
- **Detection**: Environment variable scan + library mapping
- **Expected Dump**: Preloaded library executable sections

## Comprehensive Detection Strategies

The tool implements **6 independent strategies** to ensure bulletproof unpacking:

| Strategy | eBPF Event | Detection Method | Trigger |
|----------|------------|------------------|---------|
| 1. memfd | MEMFD_CREATE | Scan /proc/PID/fd/ | memfd file descriptors |
| 2. RWX | MMAP_EXEC | Check prot flags | `(prot & 0x7) == 0x7` |
| 3. Anonymous | MMAP_EXEC | Check MAP_ANONYMOUS | `flags & 0x20` |
| 4. mprotect | MPROTECT_EXEC | Runtime permission change | `prot & 0x4` |
| 5. Deleted | - | /proc/PID/exe readlink | `(deleted)` suffix |
| 6. LD_PRELOAD | - | /proc/PID/environ scan | `LD_PRELOAD=` |

## Verifying Results

### Check Memory Dumps
```bash
# List all sandbox directories
ls -ld sandbox_*

# Check dumps in latest sandbox
ls -lh sandbox_$(ls -t sandbox_* | head -1)/memory_dumps/

# View dump count per test
for dir in sandbox_*; do
    echo "$dir: $(find $dir -name '*.bin' | wc -l) dumps"
done
```

### Inspect JSON Reports
```bash
# View test 1 report
cat test_loaders/test_output/test_1_report.json | jq '.memory_dumps'

# Check for duplicate SHA1s (should be none)
cat test_loaders/test_output/test_1_report.json | jq '.memory_dumps[].sha1' | sort | uniq -d

# View all alerts
cat test_loaders/test_output/test_1_report.json | jq '.alerts'
```

### Run YARA Scans
```bash
# Scan a specific sandbox
cd sandbox_20251128_143022
python3 ../test_loaders/yara_scan_sandbox.py

# Scan all dumps
find . -name "*.bin" -exec yara ../test_loaders/meterpreter_rules.yar {} \;
```

## Expected Output

### Successful Detection
```
[eBPF] MMAP_EXEC detected in PID 12345 (1_memfd_loader)
[+] Dumping memfd files from PID 12345...
[+] Dumped 74 bytes from memfd:meterpreter (deleted)
[+] SHA1: c48c00b1f4c9d9c5e4d7e8f0a1b2c3d4e5f6a7b8
[!] YARA MATCH: Meterpreter_Stub in memory_dumps/memdump_12345_memfd_0.bin
```

### No Duplicates
The SHA1 deduplication ensures each unique payload is dumped only once:
```
[+] Dumped 74 bytes from PID 12345 (SHA1: c48c00b1...)
[DEBUG] Skipping duplicate dump for PID 12346 (same SHA1)
```

## Troubleshooting

### No Memory Dumps Created
1. Check eBPF events are being captured:
   ```bash
   tail -f /tmp/ebpf_*.log
   ```

2. Verify `--full_dump` flag is set in `run_integrated.sh`

3. Check sandbox detection is working:
   ```bash
   grep "SANDBOX" /tmp/ebpf_*.log
   ```

### Compilation Errors
```bash
# Rebuild all test loaders
cd test_loaders
./compile_all.sh
```

### Permission Issues
All commands require root:
```bash
sudo ./run_integrated.sh <binary>
sudo ./test_loaders/run_all_tests.sh
```

## Architecture

### eBPF Integration Flow
```
run_integrated.sh
    ├── Starts eBPF monitor (ebpf_standalone)
    │   └── Captures: MMAP_EXEC, MPROTECT_EXEC, MEMFD_CREATE, EXECVE
    │
    └── Starts memory dumper (realtime_memdump_tool)
        ├── Reads eBPF events via named pipe
        ├── Sandbox mode: tracks process tree
        ├── Multiple dump strategies:
        │   ├── dump_memfd_files()
        │   ├── dump_memory_region() on MMAP_EXEC
        │   ├── dump_memory_region() on MPROTECT_EXEC
        │   ├── check_exe_link() for deleted binaries
        │   └── check_env_vars() for LD_PRELOAD
        │
        └── Generates: sandbox_*/report.json with:
            ├── memory_dumps[] (SHA1 deduplicated)
            ├── processes[] (with creation_method)
            ├── alerts[] (RWX, memfd, deleted, etc.)
            └── file_operations[], network_connections[]
```

### SHA1 Deduplication
- Each dump is hashed before writing
- Hash stored in `memdump_hashes[]` array
- Duplicate SHA1s are skipped
- Result: No duplicate payloads in `report.json`

### Separation of Concerns
- **EDR Telemetry**: `sandbox_proc_mutex` (process tree, alerts, network)
- **Memory Forensics**: `memdump_mutex` (dumps, SHA1 tracking)
- **No Lock Contention**: Independent operation, atomic report generation
