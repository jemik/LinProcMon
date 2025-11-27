# eBPF Integration Guide

## Quick Start - Integrated Monitoring

Run both eBPF syscall monitor AND memory dumper together:

```bash
chmod +x run_integrated.sh
sudo ./run_integrated.sh ./test_loaders/xor_loader_memfd
```

This will:
1. Start eBPF monitor to catch syscalls in real-time
2. Start memory dumper in sandbox mode
3. Show both outputs simultaneously
4. Generate summary report when done

## What Gets Detected

### eBPF Monitor Catches:
- `mmap(PROT_EXEC)` - When executable memory is allocated
- `mprotect(PROT_EXEC)` - When memory permissions change to executable
- `memfd_create()` - When anonymous files are created (fileless execution)
- `execve()` - When programs execute

### Memory Dumper Captures:
- Full memory dumps of suspicious regions
- RWX memory regions
- Decoded/decrypted payloads
- Process metadata (files, network, environment)

## Example Output

```
======================================
 Integrated eBPF + Memory Monitoring
======================================

Target: ./xor_loader_memfd
eBPF Log: /tmp/ebpf_12345_ebpf.log
Dumper Log: /tmp/ebpf_12345_dumper.log

[1/3] Starting eBPF syscall monitor...
      [✓] eBPF monitor running (PID 12346)
[2/3] Starting memory dumper in sandbox mode...
      [✓] Memory dumper running (PID 12347)

[3/3] Monitoring (press Ctrl-C to stop)...

[11:50:35] memfd_create()       PID=622104 (xor_loader_memf) flags=0x1
[11:50:35] mmap(PROT_EXEC)      PID=622104 (xor_loader_memf) addr=0x0 len=74 prot=R-X
[11:50:35] execve()             PID=622104 (xor_loader_memf)
[ALERT] RWX memory detected in PID 622104!
[*] Dumping memory region...

[*] Stopping monitors...

======================================
 Analysis Complete
======================================

eBPF Events Captured:
  mmap(PROT_EXEC):     1
  mprotect(PROT_EXEC): 0
  memfd_create():      1
  execve():            1

Memory Dumps:
  Location: sandbox_xor_loader_memfd_20251127_115035
  Dumps: 3

To scan with YARA:
  cd sandbox_xor_loader_memfd_20251127_115035/memory_dumps
  python3 ../../test_loaders/yara_scan_sandbox.py
```

## Manual Integration

If you want to run them separately:

### Terminal 1 - eBPF Monitor:
```bash
sudo ./ebpf_standalone > ebpf_events.log &
```

### Terminal 2 - Memory Dumper:
```bash
sudo ./realtime_memdump_tool --sandbox ./malware --full_dump
```

### Terminal 3 - Correlate:
```bash
# Find when eBPF detected mprotect
grep "mprotect" ebpf_events.log

# Check if memory was dumped at that time
ls -lh sandbox_*/memory_dumps/
```

## Why This Works

**Before (Netlink Only):**
- Process starts
- Memory scanned once
- XOR decryption happens → **MISSED**
- Shellcode executes → **MISSED**

**After (eBPF + Netlink):**
- Process starts (netlink)
- Memory scanned once
- XOR decryption happens
- `mprotect()` called → **eBPF CATCHES IT**
- Periodic rescan triggered
- Decrypted shellcode found and dumped
- YARA detects meterpreter signatures

## Performance Impact

- **eBPF overhead:** <0.5% CPU
- **Memory dumper:** Depends on scan frequency
- **Combined:** Still suitable for production use

## Advanced Usage

### Filter Specific PIDs

```bash
# Monitor only specific process
sudo ./ebpf_standalone --pid 12345 &
sudo ./realtime_memdump_tool -p 12345 --mem_dump
```

### Adjust Rescan Interval

```bash
# Rescan every 0.5 seconds (faster detection)
sudo ./run_integrated.sh ./malware --sandbox-rescan 0.5

# Rescan every 5 seconds (lower overhead)
sudo ./run_integrated.sh ./malware --sandbox-rescan 5
```

### Full Automation

```bash
# Run all test loaders
for loader in test_loaders/*_loader*; do
    echo "Testing: $loader"
    sudo ./run_integrated.sh "$loader" --sandbox-timeout 5
    sleep 2
done
```

## Troubleshooting

### eBPF monitor shows no events

Check if tracepoints exist:
```bash
ls /sys/kernel/debug/tracing/events/syscalls/ | grep sys_enter
```

### Memory dumper doesn't trigger rescans

Make sure you're using sandbox mode with rescan:
```bash
sudo ./realtime_memdump_tool --sandbox ./malware --sandbox-rescan 1
```

### Permission denied

Both tools require root:
```bash
sudo ./run_integrated.sh ./malware
```

## Next Steps

- **Automatic correlation:** Tool could subscribe to eBPF events via IPC
- **Real-time YARA:** Scan memory immediately when eBPF detects mprotect
- **Machine learning:** Train model on eBPF syscall patterns
- **Cloud integration:** Send events to SIEM/SOC

## Files

- `run_integrated.sh` - Main integration script
- `ebpf_monitor.c` - eBPF kernel module
- `ebpf_standalone.c` - Userspace monitor
- `ebpf_integration.h` - IPC library (future)
- `compile_ebpf.sh` - Compilation script
