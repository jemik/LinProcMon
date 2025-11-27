# LinProcMon

Real-time Linux process monitoring tool designed to detect malware, memory injection, fileless execution, and in-memory payload unpacking techniques. **Production-ready with crash-resistant architecture and eBPF syscall monitoring for bulletproof malware detection!**

## ⚠️ DISCLAIMER

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

**USE AT YOUR OWN RISK.** This tool is intended for security research, malware analysis, and system monitoring. Users are responsible for:
- Ensuring compliance with applicable laws and regulations
- Obtaining proper authorization before monitoring systems
- Understanding the tool's impact on system resources
- Managing disk space consumption from memory dumps
- Filtering false positives in production environments

This tool performs kernel-level monitoring and memory analysis which may affect system stability on some configurations. Test thoroughly before production deployment.

---

## Overview

LinProcMon combines Linux netlink connector monitoring with **optional eBPF syscall hooks** for comprehensive malware detection. It analyzes process memory mappings and syscall activity to detect sophisticated evasion techniques.

- **Memory Injection Detection**: Identifies code execution from memfd_create, /dev/shm, and anonymous memory regions
- **Process Replacement**: Detects binary replacement and ELF manipulation techniques
- **RWX Memory Regions**: Flags writable+executable memory (JIT spray, self-modifying code, unpacking)
- **Runtime Unpacking Detection**: Periodic memory rescanning catches XOR decryption, UPX unpacking, and custom packers
- **Fileless Execution**: Catches execution from deleted files, memfd, and temporary locations
- **Heap/Stack Execution**: Identifies shellcode execution in non-standard memory regions
- **Environment Variable Inspection**: Detects LD_PRELOAD and LD_LIBRARY_PATH hijacking
- **Optional Memory Dumping**: Dumps suspicious memory regions for forensic analysis (disabled by default for performance)
- **YARA Integration**: Optional malware scanning of dumped memory regions

## Features

### Core Detection Capabilities

- ✅ **eBPF Syscall Monitoring** - Kernel-level hooks for `mmap()`, `mprotect()`, `memfd_create()`, `execve()`
- ✅ **Event-Driven Scanning** - Sub-millisecond response to memory operations (not periodic polling)
- ✅ **XOR Decryption Detection** - Catches `mprotect(PROT_EXEC)` when malware decrypts payloads
- ✅ **Memory Injection Detection** - Identifies code execution from memfd_create, /dev/shm, anonymous regions
- ✅ **Process Replacement** - Detects binary replacement and ELF manipulation techniques
- ✅ **RWX Memory Regions** - Flags writable+executable memory (JIT spray, self-modifying code)
- ✅ **Runtime Unpacking Detection** - Catches XOR decryption, UPX unpacking, custom packers
- ✅ **Fileless Execution** - Detects execution from deleted files, memfd, temporary locations
- ✅ **Heap/Stack Execution** - Identifies shellcode execution in non-standard memory regions
- ✅ **Environment Variable Inspection** - Detects LD_PRELOAD and LD_LIBRARY_PATH hijacking

### Architecture & Performance

- ✅ **Crash-resistant architecture** - Handles high-activity malware (30+ spawned processes)
- ✅ **Multi-threaded design** - Producer-consumer pattern prevents buffer overflow
- ✅ **Sandbox mode** - Execute and monitor specific binaries with full process tree tracking
- ✅ **Named pipe IPC** - eBPF monitor communicates with memory dumper in real-time
- ✅ **Process filtering** - Only dumps sandbox processes, respects `--max-dumps` limit
- ✅ **Docker/container aware** - Filters noisy infrastructure processes (runc, containerd-shim)
- ✅ **Low overhead** - eBPF <1% CPU, suitable for production environments

### Enhanced Analysis Features

- ✅ **Enhanced file monitoring** - Tracks operations in 15+ high-risk locations with risk scoring
- ✅ **Hidden file detection** - Identifies concealment attempts (files starting with '.')
- ✅ **Comprehensive JSON reporting** - SHA-1/SHA-256 hashes, file types, dropped file collection
- ✅ **Bulletproof data capture** - Immediate-write temp files survive crashes
- ✅ **JSON integrity** - Automatic escaping prevents corruption from malicious paths
- ✅ **Process deduplication** - Hash-based tracking eliminates duplicate entries
- ✅ **Sandbox timeout** - Configure analysis duration for persistent malware
- ✅ **Full memory dump** - Single contiguous dump for reverse engineering
- ✅ **YARA Integration** - Optional malware scanning of dumped memory regions

## Recent Improvements (November 2025)

### eBPF + Memory Dumper Integration (NEW!)

**Complete event-driven malware detection pipeline:**

```
┌──────────────┐   Named Pipe    ┌─────────────────────┐
│ eBPF Monitor │   (CSV Events)  │  Memory Dumper Tool │
│              ├─────────────────►│                     │
│ • mmap(X)    │                  │ • Immediate scan    │
│ • mprotect(X)│                  │ • Memory dump       │
│ • memfd_*    │                  │ • YARA scan         │
│ • execve()   │                  │ • JSON report       │
└──────────────┘                  └─────────────────────┘
```

**Key Features:**
- **Kernel-level detection**: eBPF hooks cannot be bypassed by userspace rootkits
- **Real-time response**: <1ms from syscall to memory scan (not 2-second polling)
- **Catches XOR decryption**: `mprotect(PROT_EXEC)` triggers immediate dump before payload disappears
- **Integrated workflow**: `run_integrated.sh` manages both tools automatically
- **Process filtering**: Only dumps sandbox processes, respects `--max-dumps` limit
- **IPC via named pipe**: CSV format for simple, reliable communication

**Documentation:**
- `INTEGRATION_COMPLETE.md` - Full integration guide
- `EBPF_IPC_INTEGRATION.md` - Technical architecture details
- `QUICK_START_INTEGRATED.md` - Quick start guide
- `EBPF_README.md` - eBPF standalone usage

**Quick Start:**
```bash
# One-step setup and compilation
sudo ./setup_ebpf.sh

# Run integrated analysis
sudo ./run_integrated.sh /path/to/suspicious_binary

# Results
ls sandbox_*/memory_dumps/*.bin       # Memory dumps
cat sandbox_*/analysis_report_*.json  # Full JSON report
```

### eBPF Syscall Monitoring

- **Kernel-level syscall hooks**: Monitor `mmap()`, `mprotect()`, `memfd_create()`, `execve()` in real-time
- **Bulletproof detection**: Cannot be bypassed - hooks directly into kernel tracepoints
- **Catches what netlink misses**: XOR decryption via `mprotect()`, fileless execution, memory injections
- **Standalone or integrated**: Run `ebpf_standalone` monitor independently or trigger scans from events
- **Sub-millisecond latency**: Events delivered from kernel to userspace in <1ms
- **See**: `EBPF_README.md` for full documentation and examples

### Crash Resistance & Stability
- **Stack overflow prevention**: Heap allocation for large buffers, reduced thread-local storage
- **Safe memory operations**: 1MB buffer chunks for memory dumps (down from 16MB)
- **Process existence validation**: Multiple checks throughout analysis to handle short-lived processes
- **Iteration limits**: Max 1024 file descriptors, 512 network sockets, 500 memory regions
- **Graceful error handling**: Safe errno handling for EIO/EFAULT during memory reads

### Runtime Unpacking & Decryption Detection
- **Periodic memory rescanning**: Alert cache cleared every 2 seconds in sandbox mode
- **Detects XOR/RC4 decryption**: Catches payload decryption at runtime
- **Detects UPX unpacking**: Identifies when packers decompress code into memory
- **Detects custom packers**: Generic approach catches any runtime code modification
- **Configurable rescan interval**: `--sandbox-rescan <seconds>` for fine-tuning
- **Low overhead**: Smart caching prevents duplicate alerts while still catching changes

### Data Integrity
- **JSON string escaping**: Prevents corruption from special characters in file paths, command lines
- **Buffer reuse fix**: Separate string copies avoid static buffer conflicts in fprintf calls
- **Hash-based deduplication**: O(1) PID lookup with atomic operations prevents duplicate process entries
- **Immediate-write architecture**: Data written to temp files before processing, survives crashes
- **Cmdline fallback**: Uses process name when cmdline is unavailable (short-lived processes)

### Performance & Reliability
- **Reduced memory footprint**: Thread-local buffers down to 2KB from 8KB
- **Safer bounds checking**: Explicit length validation for readlink, fread, sscanf operations
- **Process monitoring limits**: Periodic existence checks prevent chasing dead processes
- **Network data accuracy**: Fixed IP address reporting with proper variable handling

These improvements make LinProcMon production-ready for analyzing complex, high-activity malware samples that spawn dozens of child processes and perform intensive file/network operations.

## Installation

### Quick Install (eBPF + Memory Dumper)

**Automated setup (recommended):**
```bash
# Install dependencies, compile everything, and verify
sudo ./setup_ebpf.sh
```

This installs:
- Clang, LLVM, libbpf (for eBPF compilation)
- OpenSSL development libraries (for hashing)
- Compiles `ebpf_monitor.o` (kernel program)
- Compiles `ebpf_standalone` (userspace monitor)
- Compiles `realtime_memdump_tool` (memory scanner)
- Makes all scripts executable

**Quick test:**
```bash
sudo ./run_integrated.sh /bin/ls
```

### Manual Installation

#### Step 1: Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential gcc make \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    linux-headers-$(uname -r) libssl-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum groupinstall "Development Tools"
sudo yum install gcc make clang llvm libbpf-devel \
    elfutils-libelf-devel zlib-devel kernel-devel openssl-devel
```

#### Step 2: Compile eBPF Components

```bash
# Compile eBPF kernel program
./compile_ebpf.sh

# Or manually:
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -D__BPF_TRACING__ \
    -c ebpf_monitor.c -o ebpf_monitor.o

gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz -O2
```

#### Step 3: Compile Memory Dumper

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -O2
```

### Prerequisites (Standalone Memory Dumper Only)

If you only want the memory dumper without eBPF:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential gcc make libssl-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum groupinstall "Development Tools"
sudo yum install gcc make openssl-devel
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

### Integrated System (eBPF + Memory Dumper) - Recommended

**Automated (easiest):**
```bash
sudo ./setup_ebpf.sh
```

**Manual compilation:**
```bash
# Step 1: Compile eBPF components
./compile_ebpf.sh

# Step 2: Compile memory dumper
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -O2

# Step 3: Run integrated
sudo ./run_integrated.sh /path/to/malware
```

### Standalone Memory Dumper (Without eBPF)

### Option 1: With Full Features (Recommended)

Includes sandbox reporting, file hashing, and JSON output:

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -O2
```

**Pros:** Full sandbox features, JSON reports, SHA hashing, optimized  
**Cons:** Requires OpenSSL development libraries

### Option 2: With YARA Support (Dynamic Linking)

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -lssl -lcrypto -O2
```

**Pros:** Full YARA malware scanning capabilities + complete sandbox reporting  
**Cons:** Requires libyara and OpenSSL installed on target system

### Option 3: Minimal Build (Without Sandbox Reporting)

If you don't need the enhanced sandbox features with JSON reporting:

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -pthread -O2
```

**Note:** This disables file hashing and JSON reporting in sandbox mode.

### Option 4: Debug Build with Warnings

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -lssl -lcrypto -g -Wall -Wextra
```

### Dependencies for Enhanced Sandbox Features

For comprehensive sandbox reporting with JSON output, file hashing, and dropped file collection:

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install openssl-devel
```

## Usage

### Integrated eBPF + Memory Dumper (Recommended)

**Quick malware analysis:**
```bash
sudo ./run_integrated.sh /path/to/suspicious_binary
```

This automatically:
1. Creates named pipe for IPC
2. Starts eBPF monitor (detects syscalls)
3. Starts memory dumper (scans on eBPF events)
4. Executes and monitors the binary
5. Generates comprehensive JSON report

**With custom options:**
```bash
# 10-minute timeout, YARA scanning
sudo ./run_integrated.sh /path/to/malware --yara rules.yar --sandbox-timeout 10

# With additional memory dumper options
sudo ./run_integrated.sh /path/to/malware --full_dump --max-dumps 5
```

**Results:**
```bash
# Memory dumps
ls sandbox_*/memory_dumps/*.bin

# JSON report
cat sandbox_*/analysis_report_*.json

# eBPF event log
cat /tmp/ebpf_*_ebpf.log
```

### Standalone Memory Dumper (Without eBPF)

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

### Sandbox Mode

Execute and monitor a specific binary or script for malicious behavior with **comprehensive JSON reporting**. **IMPORTANT**: `--sandbox` must always be the LAST argument, as everything after it is passed to the sandboxed program.

📋 **See [SANDBOX_FEATURES.md](SANDBOX_FEATURES.md) for complete documentation on enhanced sandbox features including JSON reporting, file collection, and analysis workflow.**

**Monitor binary execution:**
```bash
sudo ./realtime_memdump_tool --sandbox ./malware
# Creates: sandbox_<SHA1>/ directory with full JSON report
```

**With command-line arguments:**
```bash
sudo ./realtime_memdump_tool --sandbox ./malware arg1 arg2
```

**With timeout (for malware that kills parent process):**
```bash
sudo ./realtime_memdump_tool --sandbox-timeout 5 --sandbox ./malware
# Monitors for 5 minutes regardless of process state
```

**Monitor Python script:**
```bash
sudo ./realtime_memdump_tool --sandbox script.py arg1
# Auto-detects .py extension and uses python3
```

**Monitor bash script:**
```bash
sudo ./realtime_memdump_tool --sandbox script.sh
# Auto-detects .sh extension and uses bash
```

**Sandbox with full memory dump (recommended for unpacking analysis):**
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox ./packed_malware
# Creates single contiguous dump file: memdump_PID_name.bin
```

**Sandbox with individual region dumps:**
```bash
sudo ./realtime_memdump_tool --mem_dump --sandbox ./suspicious_binary
# Creates dump_PID_0xSTART-0xEND.bin for each suspicious region
```

**Complete malware analysis:**
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --yara rules.yar --sandbox ./malware
# 10-minute timeout, full memory dump, YARA scanning
```

**What sandbox mode monitors:**
- All processes in the sandbox process tree (parent, children, grandchildren)
- Memory injection, RWX regions, memfd execution, process hollowing
- **File operations in 15+ high-risk locations** (persistence, staging, hidden files)
- **Risk-scored file activity** with categorization (persistence, library_hijack, temp_staging, etc.)
- **Automatic dropped file collection** with SHA-1/SHA-256 hashes and file type detection
- Network socket creation
- Spawned child processes and their behavior

📋 **See [FILE_MONITORING.md](FILE_MONITORING.md) for complete documentation on enhanced file monitoring capabilities, risk scoring, and monitored locations.**

**Automatic exit conditions:**
- Without timeout: Exits when sandbox process tree terminates
- With timeout: Exits after specified duration (catches persistent payloads)

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--ebpf-pipe <path>` | **Read eBPF events from named pipe (IPC with eBPF monitor)** |
| `--sandbox <bin>` | **Sandbox mode**: Execute and monitor specific binary/script. **Must be last argument!** |
| `--sandbox-timeout <min>` | Sandbox timeout in minutes (0=wait for exit, default: 0) |
| `--sandbox-rescan <sec>` | Rescan interval for unpacking detection (default: 2 seconds) |
| `--max-dumps <N>` | Maximum number of processes to dump (0=unlimited, default: 0) |
| `--full_dump` | Dump entire process memory to single file (implies --mem_dump) |
| `--mem_dump` | Dump individual suspicious memory regions to separate files |
| `--quiet, -q` | Quiet mode (suppress non-critical messages, compact alerts) |
| `--threads <N>` | Number of worker threads (1-8, default: 4) |
| `--yara <file>` | Enable YARA scanning with specified rules file (requires --mem_dump or --full_dump) |
| `--continuous` | Enable continuous monitoring (rescan processes every 30s) |
| `--help, -h` | Show help message |

### Recommended Configurations

**Integrated malware analysis (eBPF + Memory Dumper):**
```bash
# Full analysis with eBPF event-driven scanning
sudo ./run_integrated.sh /path/to/malware

# With YARA scanning and timeout
sudo ./run_integrated.sh /path/to/malware --yara rules.yar --sandbox-timeout 10

# Limit memory dumps (e.g., only first 3 processes)
sudo ./run_integrated.sh /path/to/malware --full_dump --max-dumps 3
```

**Standalone malware analysis (without eBPF):**
```bash
# Sandbox mode with full memory dump
sudo ./realtime_memdump_tool --full_dump --yara rules.yar --sandbox ./malware.bin

# With timeout for persistent payloads
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --sandbox ./malware.bin
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

### Memory Dumps

**Individual region dumps (--mem_dump):**
Suspicious memory regions are automatically dumped to separate files:
```
dump_<PID>_0x<START>-0x<END>.bin
```

Example:
```
dump_12345_0x7f8a2c000000-0x7f8a2c100000.bin
```

**Full memory dump (--full_dump - recommended for reverse engineering):**
Entire process memory dumped to single contiguous file:
```
memdump_<PID>_<processname>.bin
memdump_<PID>_<processname>.map
```

Example:
```
memdump_12345_malware.bin  <- Load this into Ghidra/IDA
memdump_12345_malware.map  <- Memory offset -> virtual address mapping
```

**Memory map file format:**
```
[0x00000000] -> 0x0000000000400000-0x0000000000401000 r-xp 4096 bytes /path/to/binary [DUMPED 4096 bytes]
[0x00001000] -> 0x0000000000600000-0x0000000000601000 rwxp 4096 bytes  [DUMPED 4096 bytes]
[0x00002000] -> 0x00007f1234567000-0x00007f1234568000 r-xp 4096 bytes /memfd:malware [DUMPED 4096 bytes]
```

The map file shows which file offset corresponds to which virtual address, making reverse engineering straightforward.

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

### Malware Sandbox
- Execute suspicious binaries in isolated environment with full monitoring
- Track all spawned processes and their behavior
- Monitor file creation in temporary directories
- Detect network connections and C2 communication attempts
- Automatically capture full memory dumps for unpacking analysis
- Support for Python/bash script analysis
- Timeout-based analysis for malware that kills parent processes

**Example workflow:**
```bash
# Step 1: Execute malware with full monitoring (10-minute timeout)
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --sandbox ./packed_malware

# Step 2: Analyze the memory dump in Ghidra/IDA
ghidra memdump_12345_packed_malware.bin

# Step 3: Use the .map file to locate specific regions
cat memdump_12345_packed_malware.map | grep -i memfd
```

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

### Integrated System (eBPF + Memory Dumper)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Integrated Malware Detection                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                ┌───────────────────┴───────────────────┐
                │                                       │
        ┌───────▼────────┐                    ┌────────▼─────────┐
        │ ebpf_standalone│                    │ realtime_memdump │
        │                │                    │      _tool       │
        │ • Hooks kernel │  Named Pipe (FIFO)│                  │
        │   tracepoints  ├───────────────────►│ • Reads events  │
        │ • Detects:     │   CSV format       │ • Immediate scan│
        │   - mmap(X)    │                    │ • Memory dump   │
        │   - mprotect(X)│                    │ • YARA scan     │
        │   - memfd_*    │                    │ • JSON report   │
        │   - execve()   │                    │                  │
        └────────────────┘                    └──────────────────┘
              ▲                                        │
              │                                        │
        ┌─────┴─────┐                          ┌──────▼───────┐
        │  Kernel   │                          │   Sandbox    │
        │Tracepoints│                          │   Process    │
        └───────────┘                          └──────────────┘
```

**Event Flow:**
1. Sandbox process executes `mprotect(PROT_EXEC)` to decrypt payload
2. eBPF tracepoint fires instantly (<1μs)
3. Event written to named pipe in CSV format
4. Memory dumper reads event, queues immediate scan
5. Worker thread scans process memory
6. Suspicious regions dumped to disk
7. YARA scan identifies malware family
8. Results written to JSON report

### Multi-Threaded Design (Memory Dumper)

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

## Testing & Verification

### Meterpreter Detection Test Suite

A comprehensive test suite is included to verify all 5 detection capabilities work correctly and that memory dumps contain identifiable malware signatures.

**Location**: `test_loaders/`

**Quick Start**:
```bash
cd test_loaders
chmod +x *.sh
./compile_all.sh                    # Compile all test loaders
sudo ./run_automated_tests.sh       # Run full automated test suite
./scan_dumps.sh                     # Scan dumps with YARA
```

**Test Cases**:
1. **memfd Fileless Execution** - Verifies memfd_create() detection
2. **RWX Memory Injection** - Tests RWX region detection + YARA scanning
3. **Deleted Binary Replacement** - Validates (deleted) file detection
4. **Heap Execution** - Confirms executable heap detection
5. **LD_PRELOAD Hijacking** - Tests environment variable inspection

Each test embeds meterpreter-like signatures (metsrv.dll, ReflectiveLoader, LHOST/LPORT configs) to verify:
- ✅ Detection alerts trigger correctly
- ✅ Memory dumps capture payloads
- ✅ YARA rules identify malware signatures

**Documentation**:
- `test_loaders/QUICK_START.md` - Quick testing guide
- `test_loaders/README.md` - Complete test suite documentation
- `test_loaders/TEST_SUITE_SUMMARY.md` - Expected results & verification matrix

**Safety**: All shellcode execution is commented out. Loaders only keep payloads in memory for 30 seconds without executing them.

## License

[Add your license here]

## Author

[Add author information here]

## Acknowledgments

- Uses Linux netlink connector for process events
- Inspired by various EDR and process monitoring tools
- YARA integration for malware detection
