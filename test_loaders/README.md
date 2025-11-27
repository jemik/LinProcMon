# Test Loaders for LinProcMon Detection Verification

This directory contains 5 test loaders that demonstrate each detection capability of LinProcMon. Each loader embeds meterpreter-like signatures and shellcode patterns to verify that:

1. **Detection works correctly** - LinProcMon alerts on suspicious behavior
2. **Memory dumps capture payloads** - Shellcode and signatures are preserved
3. **YARA scanning succeeds** - Signatures are identifiable in dumps

## Test Cases

### 1. memfd Fileless Execution (`1_memfd_loader.c`)
- **Technique**: Creates anonymous file descriptor with `memfd_create()`
- **Payload**: Writes ELF header + shellcode to memfd
- **Detection**: Should trigger "memfd execution" alert
- **Memory**: Shellcode visible in executable memfd mapping

### 2. RWX Memory Injection (`2_rwx_injection_loader.c`)
- **Technique**: Allocates RWX memory with `mmap()`
- **Payload**: Copies shellcode + Linux meterpreter signatures to RWX region
- **Detection**: Should trigger "RWX regions" alert
- **Memory**: Multiple meterpreter markers (linux/x64/meterpreter, core_loadlib, etc.)

### 3. Deleted Binary Replacement (`3_deleted_binary_loader.c`)
- **Technique**: Copies itself to /tmp, executes, then deletes binary
- **Payload**: Embedded shellcode + meterpreter config strings
- **Detection**: Should trigger "running from deleted file" alert
- **Memory**: Process running from (deleted) contains payload

### 4. Heap Execution (`4_heap_execution_loader.c`)
- **Technique**: Allocates heap, copies payload, makes executable with `mprotect()`
- **Payload**: Shellcode + Linux meterpreter markers + configuration
- **Detection**: Should trigger "Executable heap" alert
- **Memory**: Heap region contains extensive meterpreter signatures

### 5. LD_PRELOAD Hijacking (`5_preload_loader.c`)
- **Technique**: Shared library with constructor function
- **Payload**: Library contains shellcode + meterpreter stage URLs
- **Detection**: Should trigger "LD_PRELOAD environment variable" alert
- **Memory**: Preloaded library contains payload + config

## Usage

### Compile All Loaders
```bash
cd test_loaders
./run_all_tests.sh
```

This will:
1. Compile all 5 loaders
2. Run each test sequentially
3. Prompt you to run LinProcMon for each test
4. Wait for memory dumps to complete

### Run Individual Tests

```bash
# Compile
gcc -o 1_memfd_loader 1_memfd_loader.c

# Run test
./1_memfd_loader &
TEST_PID=$!

# Monitor with LinProcMon
sudo ../realtime_memdump_tool -p $TEST_PID -o test1_report.json
```

### Scan Memory Dumps with YARA

```bash
# Scan all dumps
./scan_dumps.sh

# Scan specific dump
yara -s meterpreter_detection.yar test1_report.json_12345_memory.dump
```

## Expected Results

For each test, you should see:

1. **Console Output**:
   - Loader announces technique being used
   - Shows memory addresses and payload locations
   - Sleeps 30 seconds for monitoring

2. **LinProcMon Alerts**:
   - JSON report contains appropriate alert type
   - Alert severity marked as high
   - Process information captured

3. **Memory Dumps**:
   - `.dump` files created for suspicious regions
   - File size > 0 (contains actual memory content)
   - Dumps contain shellcode bytes

4. **YARA Matches**:
   - Multiple rules match each dump
   - `Meterpreter_Stage_Marker` detects DLL names
   - `Meterpreter_Configuration` detects config strings
   - `Shellcode_Generic_Execve` detects shellcode patterns

## YARA Rules

The `meterpreter_detection.yar` file contains 8 rules:

- `Meterpreter_Stage_Marker` - Detects linux/x64/meterpreter, core_loadlib
- `Meterpreter_Configuration` - Detects LHOST/LPORT config
- `Meterpreter_MSSF_Header` - Detects MSSF magic bytes
- `Meterpreter_Network_Config` - Detects IP:Port patterns
- `Shellcode_Generic_Execve` - Detects x64 execve shellcode
- `RWX_Suspicious_Pattern` - Detects code in RWX regions
- `LD_PRELOAD_Indicators` - Detects preload hijacking
- `Memory_Injection_Indicators` - Detects injection APIs

## Safety Notes

⚠️ **All shellcode execution is commented out** - These loaders only:
- Load payloads into memory
- Keep them resident for 30 seconds
- Exit without executing shellcode

The actual `execve()` and function pointer calls are commented for safety. The goal is to test **detection and dumping**, not actual exploitation.

## Verification Checklist

After running all tests, verify:

- [ ] All 5 loaders compile without errors
- [ ] Each loader runs for ~30 seconds without crashing
- [ ] LinProcMon generates JSON reports for each test
- [ ] Reports contain expected alert types
- [ ] Memory dumps are created (check file size > 0)
- [ ] YARA scan finds meterpreter signatures
- [ ] At least 3-5 YARA rules match per dump

## Troubleshooting

**No memory dumps created:**
- Check LinProcMon ran with sudo
- Verify PID was correct
- Check disk space in output directory

**YARA finds no matches:**
- Verify dump files are not empty
- Check if loader ran long enough (30 seconds)
- Try `strings dump_file | grep -i meterpreter`

**Loader crashes immediately:**
- Check for segfaults with `dmesg`
- Run with `strace` to see syscall failures
- Verify kernel supports memfd_create (Linux 3.17+)

## Real Meterpreter Testing

To test with actual meterpreter payloads:

```bash
# Generate meterpreter shellcode
msfvenom -p linux/x64/meterpreter/reverse_tcp \
         LHOST=127.0.0.1 LPORT=4444 \
         -f c -o meterpreter_payload.c

# Replace payload[] array in loaders with generated shellcode
# Recompile and run tests
```

⚠️ **Only do this in isolated test environments!**
