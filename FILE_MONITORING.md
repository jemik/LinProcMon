# Enhanced File Monitoring Capabilities

## Overview

The tool now includes comprehensive file monitoring covering real-world malware scenarios including:
- Critical persistence locations
- Temporary staging areas
- Hidden file detection
- Library hijacking attempts
- Fileless execution indicators
- Risk scoring and categorization

## Monitored Locations

### Critical Persistence (Risk: 95-100)

#### Cron-based Persistence
- `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`
- `/var/spool/cron/`
- **Risk Score**: 95
- **Category**: persistence
- **Technique**: Scheduled tasks for persistence

#### Service-based Persistence
- `/etc/init.d/` - SysV init scripts
- `/etc/rc.local` - Legacy startup script
- `/etc/systemd/system/` - Systemd service files
- **Risk Score**: 95
- **Category**: persistence
- **Technique**: Service installation for persistence

#### Dynamic Linker Hijacking
- `/etc/ld.so.preload`
- **Risk Score**: 95
- **Category**: persistence
- **Technique**: LD_PRELOAD hijacking - loads malicious .so into every process

#### Boot Persistence
- `/boot/`
- **Risk Score**: 100 (CRITICAL)
- **Category**: boot_persistence
- **Technique**: Bootloader/kernel modification for maximum persistence

### Library Hijacking (Risk: 90)

#### Shared Library Injection
- `/lib/`, `/lib64/`
- `/usr/lib/`, `/usr/local/lib/`
- **Risk Score**: 90 (if hidden or in writable subdirectory)
- **Category**: library_hijack
- **Technique**: Malicious .so files loaded by legitimate processes
- **Detection**: Hidden .so files or files in user-writable lib directories

### Temporary/Staging (Risk: 70-85)

#### Memory-Only/Staging Locations
- `/tmp/` - World-writable temporary directory
- `/var/tmp/` - Persistent temporary directory
- `/dev/shm/` - Memory-backed filesystem (often used with memfd_create)
- **Risk Score**: 70 (normal), 85 (hidden files)
- **Category**: temp_staging
- **Technique**: Staging area for malware before execution, memory-only payloads

### Runtime/Fileless Execution (Risk: 80)

#### Fileless Execution Indicators
- `/run/` - Runtime data directory
- `/proc/<pid>/fd/` - File descriptor manipulation
- `/proc/<pid>/mem` - Direct memory access
- **Risk Score**: 80
- **Category**: runtime_fileless
- **Technique**: Fileless execution via memfd, fexecve, or reflective loading

### User-Level Persistence (Risk: 60-75)

#### User Configuration Directories
- `~/.config/` - User application configuration
- `~/.cache/` - User application cache
- `~/.local/share/` - User application data
- **Risk Score**: 60 (normal), 75 (hidden files)
- **Category**: user_persistence
- **Technique**: Fake config files, autostart entries

#### Shell Persistence
- `~/.bashrc` - Bash startup script
- `~/.bash_profile` - Bash login script
- `~/.profile` - Shell-agnostic profile
- `~/.ssh/` - SSH configuration and keys
- **Risk Score**: 60 (normal), 75 (hidden files)
- **Category**: user_persistence
- **Technique**: Shell startup script modification, SSH key injection

### Staging Areas (Risk: 55-85)

#### Root Staging
- `/root/` (excluding `/root/.cache/`)
- **Risk Score**: 65 (normal), 85 (hidden files)
- **Category**: root_staging
- **Technique**: Root user staging for privilege escalation

#### User Staging
- `/home/<user>/` (for scripts: .sh, .py, .pl)
- **Risk Score**: 55
- **Category**: user_staging
- **Technique**: User-level staging area

### Hidden Files (Risk: 50+)

#### Concealment Attempts
- Any file starting with `.` (dot) in any location
- **Risk Score**: 50+ (higher in combination with other factors)
- **Category**: hidden_file
- **Technique**: File concealment from basic `ls` commands

## Detection Methods

### File Descriptor Monitoring

The tool monitors `/proc/<pid>/fd/` to detect file access:

```
/proc/<pid>/fd/3 -> /tmp/.hidden_script
/proc/<pid>/fdinfo/3 -> flags: 0100 (O_CREAT)
```

**Detected Operations:**
- **Created**: File opened with `O_CREAT` flag (0100)
- **Written**: File opened with write access (`O_WRONLY` 01 or `O_RDWR` 02)
- **Accessed**: File opened read-only in suspicious location

### Real-Time Monitoring

For each sandbox process, the tool:
1. Scans `/proc/<pid>/fd/` for open file descriptors
2. Resolves symbolic links to actual file paths
3. Filters out non-file descriptors (sockets, pipes, anon_inode)
4. Checks file path against high-risk location database
5. Reads `/proc/<pid>/fdinfo/<fd>` to determine operation type
6. Calculates risk score based on location and file characteristics
7. Queues file for background copying and hashing (async)

### File Capture

When a suspicious file operation is detected:
1. File is immediately logged with PID, risk score, and category
2. Operation queued for background processing (non-blocking)
3. Background worker copies file to `sandbox_<SHA1>/dropped_files/`
4. Filename sanitized: `/etc/ld.so.preload` → `etc_ld.so.preload`
5. SHA-1 and SHA-256 hashes calculated
6. File type detected (ELF, PE, script, python, text, binary)
7. Full details logged: size, type, hashes

### Handling Edge Cases

**Deleted Files:**
- If file is deleted before copy, logs "no longer accessible"
- Still tracks the operation for forensics

**No Read Access:**
- If file exists but can't be read (permissions), logs "no read access"
- Records PID and file size for the report

**Access-Only Operations:**
- Read-only access to suspicious locations logged without file copy
- Useful for detecting reconnaissance behavior

## Risk Scoring System

### Score Ranges

- **100**: CRITICAL - Boot persistence
- **90-99**: VERY HIGH - Dynamic linker hijacking, library injection
- **80-89**: HIGH - Runtime fileless execution, critical persistence
- **70-79**: HIGH - Temporary staging, temp file creation
- **60-69**: MEDIUM-HIGH - User persistence locations
- **50-59**: MEDIUM - Hidden files, user staging
- **<50**: LOW - Normal file operations (not logged)

### Score Modifiers

- **+15-20**: Hidden file (starts with `.`)
- **+10**: Script file extension (.sh, .py, .pl)
- **+10**: In writable subdirectory of privileged location

### Automatic Threat Escalation

Files with risk score ≥ 80 automatically increment `suspicious_found` counter.

## Output Format

### Console Output
```
[SANDBOX] File created: /tmp/.hidden (PID=1234, Risk=85, Category=temp_staging)
[SANDBOX] Captured created: /tmp/.hidden (1024 bytes, type: bash_script, SHA-1: a1b2c3...)
[SANDBOX] File written: /etc/cron.d/malware (PID=1234, Risk=95, Category=persistence)
[SANDBOX] File accessed: /etc/passwd (PID=1234, Risk=50, Category=hidden_file)
```

### Dropped Files Directory
```
sandbox_<SHA1>/
└── dropped_files/
    ├── tmp_.hidden             # Captured: /tmp/.hidden
    ├── etc_cron.d_malware      # Captured: /etc/cron.d/malware
    ├── home_user_.bashrc       # Captured: /home/user/.bashrc
    └── dev_shm_payload         # Captured: /dev/shm/payload
```

### JSON Report (Future Enhancement)
```json
{
  "file_operations": [
    {
      "pid": 1234,
      "operation": "created",
      "path": "/tmp/.hidden",
      "risk_score": 85,
      "category": "temp_staging",
      "captured": true,
      "sha1": "a1b2c3d4...",
      "sha256": "e5f6g7h8...",
      "size": 1024,
      "file_type": "bash_script"
    }
  ]
}
```

## Usage Examples

### Basic Sandbox with File Monitoring
```bash
sudo ./realtime_memdump_tool --sandbox-timeout 10 --sandbox ./suspicious_binary
```

### With Full Memory Dumps
```bash
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 10 --sandbox ./malware
```

### Monitoring Output
```
[SANDBOX] File created: /tmp/.update (PID=5678, Risk=85, Category=temp_staging)
[SANDBOX] Captured created: /tmp/.update (4096 bytes, type: ELF, SHA-1: a1b2c3d4...)
[SANDBOX] File written: /home/user/.config/autostart/update.desktop (PID=5679, Risk=75, Category=user_persistence)
[SANDBOX] Captured written: /home/user/.config/autostart/update.desktop (256 bytes, type: text, SHA-1: e5f6g7h8...)
[SANDBOX] File created: /etc/cron.d/update (PID=5679, Risk=95, Category=persistence)
[!] Permission denied: Cannot copy /etc/cron.d/update (requires root)
[+] Sandbox report finalized: sandbox_a1b2c3d4/report.json
```

## Detection Techniques by Malware Type

### Fileless Malware
- Monitors `/dev/shm/` for staging
- Tracks `/proc/<pid>/fd/` for memfd_create usage
- Detects `/run/` for runtime-only storage

### Rootkits
- Monitors `/lib*/` for malicious .so files
- Tracks `/etc/ld.so.preload` modifications
- Detects `/boot/` modifications

### Persistent Backdoors
- Monitors all cron directories
- Tracks systemd service creation
- Detects shell rc file modifications
- Monitors SSH directory changes

### Droppers/Loaders
- Tracks temporary file creation patterns
- Monitors execution from `/tmp/`, `/var/tmp/`
- Detects hidden executable creation

### Cryptominers
- Monitors for hidden process persistence
- Tracks user-level autostart entries
- Detects scheduling via cron

## Performance Impact

**Non-Blocking Design:**
- File detection: <1μs per check (in-memory path matching)
- File copying: Background thread (doesn't block event processing)
- Hash calculation: Background thread (SHA-1 + SHA-256 async)
- Queue capacity: 128 pending file operations

**Resource Usage:**
- Memory: ~200KB for file operation queue
- CPU: <1% for file monitoring (background threads)
- I/O: Async file copying prevents blocking

## Limitations

1. **Requires Read Access**: Can't copy files without read permission
2. **Deleted Files**: Files deleted before copy attempt are logged but not captured
3. **Large Files**: Files >100MB may take time to hash (handled in background)
4. **Race Conditions**: File may change between detection and capture
5. **Symlink Following**: Currently follows symlinks (may expose false positives)

## Future Enhancements

- [ ] inotify-based monitoring for real-time file system events
- [ ] Automatic file deletion tracking (files that disappear)
- [ ] Yara scanning of captured files
- [ ] Binary diffing for modified system binaries
- [ ] Network transfer detection (files sent over network)
- [ ] Compression bomb detection
- [ ] Encrypted file detection
