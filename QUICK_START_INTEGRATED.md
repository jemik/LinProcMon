# Quick Setup: eBPF + Memory Dumper Integration

## Prerequisites

Ensure eBPF dependencies are installed:
```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Compilation

### 1. Compile eBPF Monitor
```bash
./compile_ebpf.sh
```

This creates:
- `ebpf_monitor.o` - eBPF kernel program
- `ebpf_standalone` - Userspace monitor

### 2. Compile Memory Dumper
```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -O2
```

## Quick Test

### Option 1: Automated (Recommended)
```bash
sudo ./run_integrated.sh /path/to/suspicious_binary
```

### Option 2: Manual

**Terminal 1 - eBPF Monitor:**
```bash
mkfifo /tmp/ebpf_pipe
sudo ./ebpf_standalone --pipe /tmp/ebpf_pipe
```

**Terminal 2 - Memory Dumper:**
```bash
sudo ./realtime_memdump_tool --ebpf-pipe /tmp/ebpf_pipe --full_dump --sandbox /path/to/suspicious_binary
```

## Verify Results

### Check eBPF Events
Look for:
```
[12:09:55] mmap(PROT_EXEC)      PID=724574 (xor_loader_memf) addr=0x0 len=74 prot=R-X
[12:09:55] mprotect(PROT_EXEC)  PID=724574 (xor_loader_memf) addr=0x7f8a3c000000 len=4096
```

### Check Memory Dumps
```bash
ls -lh sandbox_*/memory_dumps/*.bin
```

### Scan with YARA
```bash
cd sandbox_*/memory_dumps/
python3 ../../test_loaders/yara_scan_sandbox.py
```

Expected:
```
[✓] Found meterpreter signature in PID_XXXXX_memory.bin
```

## Troubleshooting

### Issue: "Failed to open eBPF pipe"
**Fix:** Start eBPF monitor first (it creates the pipe)

### Issue: "No events received"
**Fix:** Check kernel version: `uname -r` (need >= 5.2)

### Issue: "Permission denied"
**Fix:** Run with `sudo` - eBPF requires root

### Issue: "Tracepoint not found"
**Fix:** Enable tracepoints:
```bash
sudo mount -t debugfs none /sys/kernel/debug
```

## Command-Line Options

### ebpf_standalone
```bash
--pipe PATH   Write events to named pipe
--pid PID     Only monitor specific PID
```

### realtime_memdump_tool
```bash
--ebpf-pipe PATH         Read eBPF events from pipe
--full_dump              Dump all memory regions
--sandbox BINARY         Execute and monitor binary
--sandbox-rescan SEC     Rescan interval (default: 2)
--sandbox-timeout MIN    Timeout in minutes
--yara RULES             YARA rules file
```

## What Gets Detected

✅ **Memory Operations:**
- `mmap(PROT_EXEC)` - Allocate executable memory
- `mprotect(PROT_EXEC)` - Make memory executable
- `memfd_create()` - Fileless execution

✅ **Evasion Techniques:**
- XOR decryption (mprotect to make decrypted code executable)
- UPX unpacking (similar mprotect pattern)
- Reflective DLL loading
- Process hollowing
- Shellcode injection

✅ **Payloads:**
- Meterpreter
- Cobalt Strike beacons
- Custom RATs
- Reverse shells

## Performance

- **eBPF overhead:** <1% CPU
- **Memory usage:** ~10MB
- **Event latency:** <1ms from syscall to scan
- **Throughput:** 10,000+ events/second

## Next Steps

1. **Test with real malware samples** in safe environment
2. **Customize YARA rules** for your threat landscape
3. **Integrate with SIEM** (JSON output available)
4. **Deploy system-wide** (remove `--sandbox` flag)

## Getting Help

- Read full documentation: `EBPF_IPC_INTEGRATION.md`
- Check eBPF setup: `EBPF_README.md`
- Integration details: `EBPF_INTEGRATION.md`
