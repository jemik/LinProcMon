# Test Loaders - File Index

## Quick Access

- **[QUICK_START.md](QUICK_START.md)** - Start here! Fast testing guide with copy-paste commands
- **[README.md](README.md)** - Complete documentation of test suite
- **[TEST_SUITE_SUMMARY.md](TEST_SUITE_SUMMARY.md)** - Expected results and verification

## Scripts (Run These)

Execute in this order:

1. **`setup.sh`** - Make all scripts executable (run once)
2. **`compile_all.sh`** - Compile all 5 test loaders
3. **`run_automated_tests.sh`** - Full automated test with monitoring (requires sudo)
4. **`scan_dumps.sh`** - YARA scan of memory dumps

Alternative:
- **`run_all_tests.sh`** - Interactive test runner (manual monitoring)

## Source Code (Test Loaders)

Each demonstrates a different detection technique:

1. **`1_memfd_loader.c`** - memfd_create() fileless execution
2. **`2_rwx_injection_loader.c`** - RWX memory code injection
3. **`3_deleted_binary_loader.c`** - Binary replacement via (deleted) file
4. **`4_heap_execution_loader.c`** - Executable heap shellcode
5. **`5_preload_loader.c`** - LD_PRELOAD library hijacking

## Detection Rules

- **`meterpreter_detection.yar`** - 8 YARA rules for meterpreter signatures

## Compiled Output

After running `compile_all.sh`, executables will be in:
- `test_output/` directory
  - `1_memfd_loader` (executable)
  - `2_rwx_injection_loader` (executable)
  - `3_deleted_binary_loader` (executable)
  - `4_heap_execution_loader` (executable)
  - `5_preload_victim` (executable)
  - `malicious_preload.so` (shared library)

## Generated During Tests

- `test1_report.json` through `test5_report.json` - LinProcMon JSON reports
- `*.dump` files - Memory dumps of suspicious regions
- Temporary files in `/tmp/` from test 3

## Typical Workflow

```bash
# First time setup
./setup.sh

# Compile loaders
./compile_all.sh

# Run all tests (automated)
sudo ./run_automated_tests.sh

# Or run individual test manually
./test_output/2_rwx_injection_loader &
sudo ../realtime_memdump_tool -p $! -o test2.json

# Scan results
./scan_dumps.sh

# View report
cat test2.json | jq '.alerts'
```

## What Each Test Validates

| File | Technique | Expected Alert | YARA Signatures |
|------|-----------|----------------|-----------------|
| 1_memfd_loader.c | Fileless execution | "memfd execution" | Shellcode patterns |
| 2_rwx_injection_loader.c | Code injection | "RWX regions" | 3-4 meterpreter rules |
| 3_deleted_binary_loader.c | Binary replacement | "deleted file" | Config strings |
| 4_heap_execution_loader.c | Heap shellcode | "Executable heap" | 4-5 meterpreter rules |
| 5_preload_loader.c | Library hijacking | "LD_PRELOAD" | Stage URLs |

## Documentation Files

- **QUICK_START.md** - Fastest way to run tests (5 min read)
- **README.md** - Full documentation with troubleshooting (15 min read)
- **TEST_SUITE_SUMMARY.md** - Expected results and success criteria (10 min read)
- **INDEX.md** - This file (navigation help)

## Safety Notes

⚠️ All loaders are safe:
- Shellcode execution lines are commented out
- Processes exit after 30 seconds
- Only loads payloads into memory, doesn't execute
- All network configs are localhost (127.0.0.1)

## Support

Having issues?

1. Check **QUICK_START.md** for common commands
2. Review **README.md** troubleshooting section
3. Run loader directly to see errors: `./test_output/1_memfd_loader`
4. Check system requirements: Linux kernel 3.17+, gcc, sudo access

## Success Indicators

You've successfully completed testing when:
- [x] All 5 loaders compile without errors
- [x] Each test runs 30 seconds without crashing
- [x] JSON reports generated (test1-test5_report.json)
- [x] Memory dumps created (*.dump files, size > 0)
- [x] YARA finds 2+ matches per dump
- [x] All expected alert types present in reports

## File Size Summary

| File Type | Typical Size |
|-----------|--------------|
| Source .c files | 3-5 KB each |
| Compiled binaries | 15-20 KB each |
| JSON reports | 1-10 KB each |
| Memory dumps | 4 KB - 1 MB each |
| YARA rules | 5 KB |
| Scripts | 1-3 KB each |
| Documentation | 5-15 KB each |

Total test suite: ~100 KB source, ~500 KB with compiled outputs
