# LinProcMon

Real-time Linux process monitoring tool designed to detect malware, memory injection, fileless execution, and in-memory payload unpacking techniques.

## Overview

LinProcMon is a powerful security monitoring tool that uses the Linux kernel's netlink connector to receive real-time notifications about process execution events. It analyzes process memory mappings to detect suspicious behavior patterns commonly used by malware, including:

- **Memory Injection Detection**: Identifies code execution from memfd_create, /dev/shm, and anonymous memory regions
- **Process Hollowing**: Detects reflective DLL loading and process replacement techniques
- **RWX Memory Regions**: Flags writable+executable memory (JIT spray, self-modifying code, unpacking)
- **Fileless Execution**: Catches execution from deleted files, memfd, and temporary locations
- **Heap/Stack Execution**: Identifies shellcode execution in non-standard memory regions
- **Environment Variable Inspection**: Detects LD_PRELOAD and LD_LIBRARY_PATH hijacking
- **Memory Dumping**: Automatically dumps suspicious memory regions for forensic analysis
- **YARA Integration**: Optional malware scanning of dumped memory regions

## Features

- ✅ Real-time process monitoring via netlink connector
- ✅ Comprehensive memory injection detection
- ✅ Automatic memory dumping of suspicious regions
- ✅ Optional YARA rule scanning
- ✅ Continuous monitoring mode (rescans running processes)
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

### Option 1: Self-Contained Static Binary (No Dependencies)

This creates a portable binary that works on any Linux system:

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -static -pthread
```

**Pros:** Works on any Linux system without installing dependencies  
**Cons:** No YARA scanning support, larger binary size

### Option 2: With YARA Support (Dynamic Linking)

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread
```

**Pros:** Full YARA malware scanning capabilities  
**Cons:** Requires libyara installed on target system

### Option 3: Optimized Build with Warnings

```bash
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread -O2 -Wall -Wextra
```

## Usage

### Basic Usage

**Real-time monitoring (must run as root):**
```bash
sudo ./realtime_memdump_tool
```

This monitors all new process executions and alerts on suspicious memory patterns.

### Advanced Usage

**With YARA scanning:**
```bash
sudo ./realtime_memdump_tool --yara /path/to/rules.yar
```

**Continuous monitoring (rescans all processes every 30 seconds):**
```bash
sudo ./realtime_memdump_tool --continuous
```

**Both YARA and continuous monitoring:**
```bash
sudo ./realtime_memdump_tool --yara malware_rules.yar --continuous
```

**Show help:**
```bash
./realtime_memdump_tool --help
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--yara <file>` | Enable YARA scanning with specified rules file |
| `--continuous` | Enable continuous monitoring (rescan processes every 30s) |
| `--help, -h` | Show help message |

## Output

### Real-Time Alerts

```
[EXEC] New process PID=12345 PPID=1234
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

### Memory Dumps

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

- **CPU Usage**: Minimal (~1-2% during idle, spikes during process creation bursts)
- **Memory Usage**: ~5-10MB base, increases with memory dumps
- **Disk I/O**: Only when dumping suspicious regions
- **Network**: None (uses kernel netlink, no network traffic)

### Reducing False Positives

Some legitimate programs use RWX memory (JIT compilers, browsers, VMs). To reduce noise:

1. Filter out known good processes in the code
2. Use YARA rules to validate dumped memory
3. Correlate with other indicators (suspicious paths, environment variables)
4. Whitelist specific PIDs or process names

## Troubleshooting

### "Permission denied" errors
```bash
# Tool requires root privileges
sudo ./realtime_memdump_tool
```

### "No buffer space available"
The tool automatically handles this, but if you see persistent errors:
- Increase kernel buffer: `sysctl -w net.core.rmem_max=2097152`
- Reduce monitoring scope (disable --continuous)

### YARA not working
```bash
# Verify YARA is installed
yara --version

# Recompile with YARA support
gcc -o realtime_memdump_tool realtime_memdump_tool.c -DENABLE_YARA -lyara -pthread
```

### Too many memory dumps
Adjust detection thresholds in the code or implement filtering logic.

## Use Cases

### Security Operations Center (SOC)
- Deploy on critical servers for real-time threat detection
- Integrate with SIEM by parsing log output
- Automated memory collection for incident response

### Incident Response
- Run during suspected compromise to catch in-memory malware
- Collect evidence (memory dumps) for forensic analysis
- Identify persistence mechanisms (LD_PRELOAD, modified binaries)

### Malware Analysis Lab
- Monitor sandbox environments for packer/unpacker behavior
- Capture decrypted payloads from memory
- Study malware injection techniques

### Threat Hunting
- Continuous monitoring mode to detect dormant threats
- Baseline normal behavior, alert on deviations
- Hunt for fileless malware and living-off-the-land techniques

## Limitations

- Linux-specific (requires netlink connector and /proc filesystem)
- Requires root/CAP_NET_ADMIN privileges
- May generate false positives with JIT compilers (browsers, Java, .NET)
- Memory dumps can consume significant disk space
- Cannot prevent execution, only detect and alert

## Contributing

Contributions are welcome! Areas for improvement:

- Process whitelisting/filtering
- Better heuristics for reducing false positives
- Integration with threat intelligence feeds
- Network activity correlation
- Container-aware monitoring

## License

[Add your license here]

## Author

[Add author information here]

## Acknowledgments

- Uses Linux netlink connector for process events
- Inspired by various EDR and process monitoring tools
- YARA integration for malware detection
