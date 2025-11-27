# Quick Start: Testing LinProcMon Detection Capabilities

## Automated Test Suite

Run all 5 tests automatically:

```bash
cd test_loaders
./run_all_tests.sh
```

For each test, the script will:
1. Compile the loader
2. Execute it in the background
3. Display the PID
4. Wait for you to run LinProcMon
5. Continue to next test

## Manual Step-by-Step Testing

### Test 1: memfd Fileless Execution

```bash
# Compile and run
cd test_loaders
gcc -o test_output/1_memfd_loader 1_memfd_loader.c
sudo ../realtime_memdump_tool --threads 8 --full_dump --sandbox-timeout 1 --sandbox test_output/1_memfd_loader -o test1_report.json

# Expected: "memfd execution" alert in output
# Expected: Memory dump of executable memfd region
```

### Test 2: RWX Memory Injection

```bash
# Compile and run
gcc -o test_output/2_rwx_injection_loader 2_rwx_injection_loader.c
sudo ../realtime_memdump_tool --threads 8 --full_dump --sandbox-timeout 1 --sandbox test_output/2_rwx_injection_loader -o test2_report.json

# Expected: "RWX regions" alert
# Expected: Memory dump containing meterpreter signatures
```

### Test 3: Deleted Binary Replacement

```bash
# Compile and run
gcc -o test_output/3_deleted_binary_loader 3_deleted_binary_loader.c
sudo ../realtime_memdump_tool --threads 8 --full_dump --sandbox-timeout 1 --sandbox test_output/3_deleted_binary_loader -o test3_report.json

# Expected: "running from deleted file" alert
# Expected: Child process running from (deleted) is monitored
```

### Test 4: Heap Execution

```bash
# Compile and run
gcc -o test_output/4_heap_execution_loader 4_heap_execution_loader.c
sudo ../realtime_memdump_tool --threads 8 --full_dump --sandbox-timeout 1 --sandbox test_output/4_heap_execution_loader -o test4_report.json

# Expected: "Executable heap" alert
# Expected: Memory dump of heap with shellcode
```

### Test 5: LD_PRELOAD Hijacking

```bash
# Compile as shared library
gcc -shared -fPIC -o test_output/malicious_preload.so 5_preload_loader.c -ldl
gcc -o test_output/5_preload_victim 5_preload_loader.c

# Run with LD_PRELOAD environment variable
export LD_PRELOAD=test_output/malicious_preload.so
sudo -E ../realtime_memdump_tool --threads 8 --full_dump --sandbox-timeout 1 --sandbox test_output/5_preload_victim -o test5_report.json
unset LD_PRELOAD

# Expected: "LD_PRELOAD" alert in environment check
# Expected: Memory dump of preloaded library
```

## Verify Results

### Check JSON Reports

```bash
# View alerts in report
jq '.alerts' test1_report.json

# Check memory dumps section
jq '.memory_dumps' test1_report.json

# Count alerts
jq '.alerts | length' test1_report.json
```

### Scan Memory Dumps with YARA

```bash
# Scan all dumps
./scan_dumps.sh

# Scan specific dump file
yara -s meterpreter_detection.yar test1_report.json_*_memory.dump

# Show matching strings
yara -s -m meterpreter_detection.yar *.dump
```

### Expected YARA Matches per Test

**Test 1 (memfd):**
- `Shellcode_Generic_Execve` (shellcode patterns)
- `Memory_Injection_Indicators` (memfd_create reference)

**Test 2 (RWX):**
- `Meterpreter_Stage_Marker` (metsrv.dll, ReflectiveLoader)
- `Meterpreter_Configuration` (LHOST/LPORT strings)
- `Shellcode_Generic_Execve` (shellcode)
- `RWX_Suspicious_Pattern` (meterpreter strings)

**Test 3 (Deleted Binary):**
- `Meterpreter_Stage_Marker` (marker strings)
- `Meterpreter_Configuration` (stage info)
- `Shellcode_Generic_Execve` (embedded shellcode)

**Test 4 (Heap Execution):**
- `Meterpreter_Stage_Marker` (metsrv.dll, ws2_32.dll)
- `Meterpreter_Configuration` (full config block)
- `Meterpreter_Network_Config` (IP:port bytes)
- `Shellcode_Generic_Execve` (shellcode)

**Test 5 (LD_PRELOAD):**
- `Meterpreter_Configuration` (stage URLs)
- `LD_PRELOAD_Indicators` (preload strings)
- `Shellcode_Generic_Execve` (shellcode)

## Success Criteria

✅ **All tests pass if:**
1. Each loader runs for 30 seconds without crashing
2. LinProcMon generates JSON report for each test
3. Reports contain expected alert types
4. Memory dump files are created (size > 0)
5. YARA scan matches at least 2-3 rules per dump
6. No false negatives (all 5 techniques detected)

## Troubleshooting

### Loader crashes with "memfd_create: Function not implemented"
- Kernel too old (need 3.17+)
- Skip test 1, others should work

### LinProcMon shows "Process no longer exists"
- Loader exited too quickly
- Check for compilation errors
- Run loader directly to see error messages

### No YARA matches in dump
- Dump file empty → Check if memory region was dumped
- Payload not in dump → Increase sleep time in loader
- YARA rules too strict → Try `strings dump_file | grep -i meterpreter`

### Permission denied errors
- Run LinProcMon with `sudo`
- Check `/proc/sys/kernel/yama/ptrace_scope` (should be 0 or 1)

## Next Steps

After successful testing:

1. **Generate real meterpreter payload:**
   ```bash
   msfvenom -p linux/x64/meterpreter/reverse_tcp \
            LHOST=127.0.0.1 LPORT=4444 \
            -f c > real_payload.c
   ```

2. **Replace test shellcode** with real payload in loaders

3. **Test in isolated VM** - Never run real meterpreter on production systems

4. **Expand YARA rules** - Add more meterpreter stage signatures

5. **Benchmark performance** - How long does dumping take? CPU usage?

## Clean Up

```bash
# Remove compiled binaries
rm -rf test_output/

# Remove memory dumps
rm -f *.dump

# Remove JSON reports
rm -f test*_report.json
```
