# LinProcMon

Real-time Linux process monitoring tool designed to detect malware, memory injection, fileless execution, and in-memory payload unpacking techniques. **Now with multi-threaded architecture for high-load container environments!**

## Overview

LinProcMon is a powerful security monitoring tool that uses the Linux kernel's netlink connector to receive real-time notifications about process execution events. It analyzes process memory mappings to detect suspicious behavior patterns commonly used by malware, including:

- **Memory Injection Detection**: Identifies code execution from memfd_create, /dev/shm, and anonymous memory regions
- **Process Hollowing**: Detects reflective DLL loading and process replacement techniques
- **RWX Memory Regions**: Flags writable+executable memory (JIT spray, self-modifying code, unpacking)
- **Fileless Execution**: Catches execution from deleted files, memfd, and temporary locations
- **Heap/Stack Execution**: Identifies shellcode execution in non-standard memory regions
- **Environment Variable Inspection**: Detects LD_PRELOAD and LD_LIBRARY_PATH hijacking
- **Optional Memory Dumping**: Dumps suspicious memory regions for forensic analysis (disabled by default for performance)
- **YARA Integration**: Optional malware scanning of dumped memory regions

## Features

- ✅ **Multi-threaded architecture** - Producer-consumer pattern prevents buffer overflow in high-load environments
- ✅ **Sandbox mode** - Execute and monitor specific binaries, Python scripts, or bash scripts with full process tree tracking
- ✅ Real-time process monitoring via netlink connector (16MB kernel buffer)
- ✅ Comprehensive memory injection detection
- ✅ Optional memory dumping (--mem_dump flag)
- ✅ Optional YARA rule scanning
- ✅ **Docker/container aware** - Filters noisy infrastructure processes (runc, containerd-shim)
- ✅ Continuous monitoring mode (rescans running processes)
- ✅ Quiet mode for production use (--quiet)
- ✅ Configurable worker threads (1-8 threads)
- ✅ Low overhead, suitable for production environments
- ✅ Detailed alerting with reason codes
- ✅ Self-contained static binary support (no dependencies)

## Installation

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential gcc make
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum groupinstall "Development Tools"
sudo yum install gcc make
```

### Optional: Install YARA (for malware scanning)

**Ubuntu/Debian:**
```bash
sudo apt-get install libyara-dev yara
```

**RHEL/CentOS:**
```bash
sudo yum install yara yara-devel
```

**Or build from source:**
```bash
wget https://github.com/VirusTotal/yara/archive/v4.3.2.tar.gz
tar -xvf v4.3.2.tar.gz
cd yara-4.3.2
./bootstrap.sh
./configure --enable-cuckoo --enable-magic
make
sudo make install
sudo ldconfig
```

## Compilation

### Option 1: Self-Contained Static Binary (No Dependencies) - Recommended for Production

This creates a portable binary that works on any Linux system:

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -static -pthread -O2
```

**Pros:** Works on any Linux system without installing dependencies, optimized performance  
**Cons:** No YARA scanning support, larger binary size (~1.5MB)

### Option 2: With YARA Support (Dynamic Linking)

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -O2
```

**Pros:** Full YARA malware scanning capabilities  
**Cons:** Requires libyara installed on target system

### Option 3: Debug Build with Warnings

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -g -Wall -Wextra
```

## Usage

### Basic Usage

**Real-time monitoring (must run as root):**
```bash
sudo ./realtime_memdump_tool
```

This monitors all new process executions and alerts on suspicious memory patterns.

**Production monitoring (recommended - quiet mode, no memory dumps):**
```bash
sudo ./realtime_memdump_tool --quiet
```

Fast detection with minimal I/O overhead. Only logs critical alerts.

**High-load environments (Docker/Kubernetes hosts):**
```bash
sudo ./realtime_memdump_tool --quiet --threads 8
```

Uses 8 worker threads to handle extreme process churn without buffer overflow.

### Advanced Usage

**With memory dumping enabled (forensics mode):**
```bash
sudo ./realtime_memdump_tool --quiet --mem_dump
```

**With YARA scanning:**
```bash
sudo ./realtime_memdump_tool --yara /path/to/rules.yar --mem_dump
```

**Full forensics mode with YARA:**
```bash
sudo ./realtime_memdump_tool --yara malware_rules.yar --mem_dump --threads 4
```

**Continuous monitoring (rescans all processes every 30 seconds):**
```bash
sudo ./realtime_memdump_tool --continuous --quiet
```

**Show help:**
```bash
./realtime_memdump_tool --help
```

### Sandbox Mode (New!)

Execute and monitor a specific binary or script for malicious behavior:

**Monitor binary execution:**
```bash
sudo ./realtime_memdump_tool --sandbox ./malware
```

**With command-line arguments:**
```bash
sudo ./realtime_memdump_tool --sandbox ./malware arg1 arg2
```

**Monitor Python script:**
```bash
sudo ./realtime_memdump_tool --sandbox python3 script.py arg1
# Or with .py extension auto-detection:
sudo ./realtime_memdump_tool --sandbox script.py arg1
```

**Monitor bash script:**
```bash
sudo ./realtime_memdump_tool --sandbox bash script.sh
# Or with .sh extension auto-detection:
sudo ./realtime_memdump_tool --sandbox script.sh
```

**Sandbox with memory dumping:**
```bash
sudo ./realtime_memdump_tool --sandbox --mem_dump ./suspicious_binary
```

**Sandbox with YARA scanning:**
```bash
sudo ./realtime_memdump_tool --sandbox --mem_dump --yara rules.yar ./malware
```

**What sandbox mode monitors:**
- All processes in the sandbox process tree (parent, children, grandchildren)
- Memory injection, RWX regions, memfd execution, process hollowing
- File creation in suspicious directories (/tmp, /dev/shm, /var/tmp)
- Network socket creation
- Spawned child processes and their behavior

The tool automatically exits when the sandbox process and all its children terminate.

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--sandbox <bin>` | **Sandbox mode**: Execute and monitor specific binary/script with full process tree tracking |
| `--quiet, -q` | Quiet mode (suppress non-critical messages, compact alerts) |
| `--threads <N>` | Number of worker threads (1-8, default: 4) |
| `--mem_dump` | Enable memory dumping to disk (default: off for performance) |
| `--yara <file>` | Enable YARA scanning with specified rules file (requires --mem_dump) |
| `--continuous` | Enable continuous monitoring (rescan processes every 30s) |
| `--help, -h` | Show help message |

### Recommended Configurations

**Malware Analysis (sandbox mode):**
```bash
sudo ./realtime_memdump_tool --sandbox --mem_dump --yara rules.yar ./malware.bin
```

**SOC/SIEM Integration (maximum performance):**
```bash
sudo ./realtime_memdump_tool --quiet --threads 8 > /var/log/procmon.log 2>&1
```

**Incident Response (capture evidence):**
```bash
sudo ./realtime_memdump_tool --mem_dump --yara rules.yar --threads 4
```

**Container Host Monitoring:**
```bash
sudo ./realtime_memdump_tool --quiet --threads 8
# Automatically filters runc, containerd-shim, docker-proxy noise
```

## Output

### Real-Time Alerts (Quiet Mode)

```
[+] Quiet mode enabled (only critical alerts)
[+] Started 8 worker threads for async processing
[+] Listening for process creation events (real-time)...
[!] Executable memory in suspicious location | PID=12345 | 7f8a2c000000-7f8a2c100000 (r-xs) /memfd:malware (deleted)
[!] RWX permissions (writable+executable) | PID=12346 | 7fff2a000000-7fff2a001000 (rwxp) 
```

### Real-Time Alerts (Verbose Mode)

```
[EXEC] PID=12345 PPID=1234 (thread=140234567890)
========================================
[INFO] Process: suspicious_binary
[INFO] Cmdline: /tmp/suspicious_binary --payload
[!] ALERT: RWX permissions (writable+executable) in PID 12345
[!]   Region: 7f8a2c000000-7f8a2c100000 (rwxp) 
[+] Dumped 1048576 bytes to dump_12345_0x7f8a2c000000-0x7f8a2c100000.bin
[YARA] Match: MalwareFamily_Indicator
[!] Total suspicious regions found: 1
========================================
```

### Statistics (on exit with Ctrl+C)

```
[!] Exiting...
[*] Statistics:
    Total events processed: 15234
    Suspicious findings: 3
    Race conditions (normal): 128
    Queue drops (overload): 0
```

### Sandbox Mode Statistics

When running in sandbox mode, additional statistics are shown:

```
[!] Exiting...
[*] Statistics:
    Total events processed: 47
    Suspicious findings: 2
    Race conditions (normal): 0
    Queue drops (overload): 0
    Sandbox events: 47
    Files created: 3
    Sockets created: 1
```

**Metrics:**
- `Sandbox events`: Number of events from the monitored process tree
- `Files created`: Files created in suspicious directories (/tmp, /dev/shm, /var/tmp)
- `Sockets created`: Network sockets opened by the sandbox process tree

### Memory Dumps (when --mem_dump is enabled)

Suspicious memory regions are automatically dumped to files:
```
dump_<PID>_0x<START>-0x<END>.bin
```

Example:
```
dump_12345_0x7f8a2c000000-0x7f8a2c100000.bin
```

## Detection Capabilities

### Memory Injection Techniques

| Technique | Detection Method |
|-----------|-----------------|
| memfd_create execution | Detects executable memory backed by memfd |
| /dev/shm execution | Flags code execution from shared memory |
| Process hollowing | Identifies anonymous executable mappings |
| Reflective DLL loading | Catches runtime-mapped executable code |
| LD_PRELOAD injection | Scans environment variables |

### Unpacking & Self-Modifying Code

| Indicator | Description |
|-----------|-------------|
| RWX regions | Memory that is writable AND executable |
| Large anonymous writable | Potential staged payloads (>1MB) |
| Heap execution | Code executing from heap memory |
| Stack execution | Code executing from stack memory |

### Fileless Execution

| Pattern | Detection |
|---------|-----------|
| Deleted binaries | Processes running from (deleted) files |
| /tmp execution | Execution from temporary directories |
| Anonymous mappings | Code without backing file |

## Example YARA Rules

Create a simple YARA rule file (`malware_rules.yar`):

```yara
rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings in memory"
    strings:
        $s1 = "/bin/sh" ascii
        $s2 = "wget" ascii
        $s3 = "curl" ascii
        $s4 = "chmod +x" ascii
    condition:
        2 of ($s*)
}

rule Base64_Encoded_Command {
    meta:
        description = "Detects base64 encoded commands"
    strings:
        $b1 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
    condition:
        $b1
}
```

## Performance Considerations

### Multi-Threaded Architecture

- **Main thread**: Drains netlink socket at maximum speed (non-blocking, no I/O delays)
- **Worker threads**: Process events asynchronously (parse /proc, dump memory, scan with YARA)
- **Event queue**: 1024-event ring buffer with mutex protection
- **Result**: Main thread never blocks, preventing "No buffer space available" errors

### Resource Usage

- **CPU Usage**: 
  - Idle: ~1-2% (main thread + 4 workers)
  - Burst: ~5-10% during high process creation rate
  - With --mem_dump: +10-30% (disk I/O bound)
- **Memory Usage**: 
  - Base: ~5-10MB
  - Per event in queue: ~16 bytes
  - Memory dumps: variable (depends on region size)
- **Disk I/O**: 
  - Without --mem_dump: None (detection only)
  - With --mem_dump: High (can generate GB of dumps)
- **Network**: None (uses kernel netlink, no network traffic)

### Performance Tuning

**For high-load container environments:**
```bash
# Increase worker threads
sudo ./realtime_memdump_tool --quiet --threads 8

# Disable memory dumping (detection only)
sudo ./realtime_memdump_tool --quiet --threads 8

# If still seeing buffer overflow, increase kernel buffer:
sudo sysctl -w net.core.rmem_max=33554432  # 32MB
```

**For low-resource systems:**
```bash
# Use fewer threads
sudo ./realtime_memdump_tool --quiet --threads 2
```

### Reducing False Positives

Some legitimate programs use RWX memory (JIT compilers, browsers, VMs). The tool automatically filters:

**Ignored Docker/container processes:**
- `runc` - Container runtime executor
- `containerd-shim` - Container lifecycle manager  
- `docker-proxy` - Port forwarding daemon
- `dockerd` - Docker daemon
- `containerd` - Container runtime

**Additional filtering recommendations:**
1. Use YARA rules to validate dumped memory
2. Correlate with other indicators (suspicious paths, environment variables)
3. Whitelist specific applications (modify `should_ignore_process()`)
4. Run in test environment first to establish baseline

## Troubleshooting

### "Permission denied" errors
```bash
# Tool requires root privileges (CAP_NET_ADMIN capability)
sudo ./realtime_memdump_tool
```

### "No buffer space available"
The multi-threaded architecture prevents this, but if you still see errors:

```bash
# Increase kernel receive buffer max
sudo sysctl -w net.core.rmem_max=33554432  # 32MB

# Increase worker threads
sudo ./realtime_memdump_tool --quiet --threads 8

# Check queue drops in statistics (Ctrl+C)
# If queue_drops > 0, increase threads or disable --mem_dump
```

### High CPU usage
```bash
# Reduce worker threads
sudo ./realtime_memdump_tool --quiet --threads 2

# Disable memory dumping (detection only)
sudo ./realtime_memdump_tool --quiet

# Use continuous mode sparingly (rescans all processes)
```

### YARA not working
```bash
# Verify YARA is installed
yara --version

# Check library path
ldconfig -p | grep yara

# Recompile with YARA support
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -O2
```

### Too many memory dumps filling disk
```bash
# Disable memory dumping by default
sudo ./realtime_memdump_tool --quiet

# Only enable when investigating specific alerts
sudo ./realtime_memdump_tool --quiet --mem_dump

# Clean up old dumps periodically
find . -name "dump_*.bin" -mtime +7 -delete
```

### Docker/container noise
The tool automatically filters common container infrastructure processes:
- runc, containerd-shim, docker-proxy, dockerd, containerd

If still seeing noise, add custom filtering in `should_ignore_process()` function.

## Use Cases

### Security Operations Center (SOC)
- Deploy on critical servers for real-time threat detection
- Integrate with SIEM by parsing log output (use --quiet for structured logs)
- Automated memory collection for incident response (use --mem_dump on-demand)
- **Container/Kubernetes monitoring**: Automatically filters noisy infrastructure processes

### Incident Response
- Run during suspected compromise to catch in-memory malware
- Collect evidence (memory dumps) for forensic analysis
- Identify persistence mechanisms (LD_PRELOAD, modified binaries)
- **Fast detection mode**: Use without --mem_dump for rapid threat hunting

### Malware Analysis Lab
- Monitor sandbox environments for packer/unpacker behavior
- Capture decrypted payloads from memory
- Study malware injection techniques
- Multi-threaded processing handles high analysis workload
- **Sandbox mode**: Execute specific samples and monitor their complete behavior (file/network operations, process tree)

### Malware Sandbox (New!)
- Execute suspicious binaries in isolated environment with full monitoring
- Track all spawned processes and their behavior
- Monitor file creation in temporary directories
- Detect network connections and C2 communication attempts
- Automatically capture memory dumps of suspicious regions
- Support for Python/bash script analysis

### Threat Hunting
- Continuous monitoring mode to detect dormant threats
- Baseline normal behavior, alert on deviations
- Hunt for fileless malware and living-off-the-land techniques
- **Production-safe**: Minimal overhead in --quiet mode without memory dumping

### Container Security
- Monitor Docker/Kubernetes hosts for container escape attempts
- Detect malicious containers using memfd execution
- Filter benign container infrastructure (runc, containerd)
- Handle extreme process churn (100+ processes/second)

## Limitations

- Linux-specific (requires netlink connector and /proc filesystem)
- Requires root/CAP_NET_ADMIN privileges
- May generate false positives with JIT compilers (browsers, Java, .NET, Node.js)
- Memory dumps (when enabled) can consume significant disk space
- Cannot prevent execution, only detect and alert
- Short-lived processes may exit before analysis (race conditions - tracked in stats)
- **Note**: Docker infrastructure processes are automatically filtered

## Contributing

Contributions are welcome! Areas for improvement:

- Additional process filtering patterns
- Better heuristics for reducing false positives
- Integration with threat intelligence feeds
- Network activity correlation
- eBPF-based implementation for even lower overhead
- Kubernetes API integration for pod-aware monitoring
- Systemd service file and auto-start configuration

## Architecture

### Multi-Threaded Design

```
┌─────────────────────┐
│   Netlink Socket    │ (kernel events)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Main Thread       │ (producer - non-blocking)
│  - Drains socket    │
│  - Pushes to queue  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Event Queue       │ (1024 events, mutex-protected)
│  - Ring buffer      │
│  - Tracks drops     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Worker Threads     │ (consumers - 1-8 configurable)
│  - Parse /proc      │
│  - Detect threats   │
│  - Dump memory      │
│  - YARA scan        │
└─────────────────────┘
```

**Key Benefits:**
- Main thread never blocks on I/O
- Worker threads process events in parallel
- Queue absorbs burst traffic
- Graceful degradation (drops tracked but doesn't crash)

## License

[Add your license here]

## Author

[Add author information here]

## Acknowledgments

- Uses Linux netlink connector for process events
- Inspired by various EDR and process monitoring tools
- YARA integration for malware detection
