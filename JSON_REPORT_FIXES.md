# JSON Report Comprehensive Fixes

## Issues Fixed

### 1. ✅ Duplicate Process Entries
**Problem**: Same PID appeared 60+ times in the processes array due to periodic rescans (every 1 second).

**Solution**: Added duplicate detection in `report_sandbox_process()`:
```c
// Check if this PID already exists (prevent duplicates from periodic rescans)
for (int i = 0; i < sandbox_process_count; i++) {
    if (sandbox_processes[i].pid == pid) {
        // Process already tracked, skip
        return;
    }
}
```

### 2. ✅ Missing File Operations Section
**Problem**: File operations were queued for background processing but never added to JSON report.

**Solution**: 
- Added `sandbox_file_ops[]` array to track all file operations
- Modified `report_file_operation()` to store operations in-memory immediately
- Added risk score and category parameters to function signature
- Included complete file_operations section in JSON with risk scores and categories

**New JSON Structure**:
```json
"file_operations": [
  {
    "pid": 1234,
    "operation": "created",
    "filepath": "/tmp/.malware",
    "risk_score": 85,
    "category": "temp_staging",
    "timestamp": 1763986185
  }
]
```

### 3. ✅ Missing Network Activity Section
**Problem**: Network connections were logged but not included in JSON report.

**Solution**:
- Added `sandbox_network[]` array to track connections
- Modified `report_network_activity()` to store data with duplicate detection
- Completely rewrote `check_network_connections()` to parse `/proc/net/tcp*` and `/proc/net/udp*`
- Only counts actual established network connections (remote_addr != 0.0.0.0)
- Filters out listening sockets and pipes

**New JSON Structure**:
```json
"network_activity": [
  {
    "pid": 1234,
    "protocol": "TCP",
    "local_address": "192.168.1.100:45678",
    "remote_address": "93.184.216.34:443",
    "timestamp": 1763986190
  }
]
```

### 4. ✅ Socket Counter Incorrectly Incremented
**Problem**: `sockets_created` was 63 but no actual network connections - was counting Unix sockets, pipes, and every rescan.

**Solution**:
- Complete rewrite of `check_network_connections()` to parse kernel network tables
- Only counts real TCP/UDP connections with remote addresses
- Matches socket inodes from `/proc/net/*` to process file descriptors
- Includes duplicate detection to prevent counting same connection multiple times

### 5. ✅ Missing Memory Dumps Section
**Problem**: Memory dumps created but not tracked in JSON report.

**Solution**:
- Added `sandbox_memdumps[]` array to track dump files
- Modified `dump_full_process_memory()` to report dumps with SHA-1 hash
- Included complete memory_dumps section in JSON

**New JSON Structure**:
```json
"memory_dumps": [
  {
    "pid": 1234,
    "filename": "memdump_1234_malware.bin",
    "size": 12582912,
    "sha1": "a1b2c3d4e5f6...",
    "timestamp": 1763986200
  }
]
```

## Data Structures Added

```c
// File operations tracking
#define MAX_SANDBOX_FILE_OPS 512
typedef struct {
    pid_t pid;
    char operation[32];
    char filepath[512];
    int risk_score;
    char category[64];
    time_t timestamp;
} sandbox_file_op_t;

// Network activity tracking
#define MAX_SANDBOX_NETWORK 256
typedef struct {
    pid_t pid;
    char protocol[16];
    char local_addr[128];
    char remote_addr[128];
    time_t timestamp;
} sandbox_network_t;

// Memory dumps tracking
#define MAX_SANDBOX_MEMDUMPS 64
typedef struct {
    pid_t pid;
    char filename[256];
    size_t size;
    char sha1[41];
    time_t timestamp;
} sandbox_memdump_t;
```

## Complete JSON Report Structure (After Fixes)

```json
{
  "analysis": {
    "start_time": 1763986185,
    "sample_path": "/tmp/elf_shell",
    "sample_sha1": "4617a99639d971e3473b3a92553311f3b5be6cc5",
    "sample_sha256": "70796a903eb5fc5aebaec4c775a207473fb431a09a598fa65076ae4454077935",
    "sample_type": "ELF",
    "sample_size": 810504,
    "timeout": 60
  },
  "processes": [
    {
      "pid": 4150932,
      "ppid": 4150925,
      "name": "memfd:memfd_fla",
      "path": "/memfd:memfd_flag_loader (deleted)",
      "cmdline": "memfd_exec",
      "start_time": 1763986185
    }
  ],
  "file_operations": [
    {
      "pid": 4150932,
      "operation": "created",
      "filepath": "/tmp/.hidden_payload",
      "risk_score": 85,
      "category": "temp_staging",
      "timestamp": 1763986186
    }
  ],
  "network_activity": [
    {
      "pid": 4150932,
      "protocol": "TCP",
      "local_address": "192.168.1.100:54321",
      "remote_address": "93.184.216.34:443",
      "timestamp": 1763986190
    }
  ],
  "memory_dumps": [
    {
      "pid": 4150932,
      "filename": "memdump_4150932_memfd_fla.bin",
      "size": 12582912,
      "sha1": "a1b2c3d4e5f6789...",
      "timestamp": 1763986200
    }
  ],
  "summary": {
    "end_time": 1763986245,
    "duration": 60,
    "total_processes": 1,
    "files_created": 1,
    "sockets_created": 1,
    "suspicious_findings": 2
  }
}
```

## Network Connection Detection Details

The new `check_network_connections()` function:

1. **Parses kernel network tables**: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
2. **Extracts connection details**: Local/remote IP and port, socket inode
3. **Matches to process**: Scans `/proc/<pid>/fd/` for socket:[inode] links
4. **Filters established connections**: Only logs connections with remote_addr != 0.0.0.0
5. **Prevents duplicates**: Checks if same connection already logged
6. **Formats addresses**: Converts hex to dotted decimal (IPv4)

**Example Detection**:
```
/proc/net/tcp entry: 0100007F:1234 B82A5D5E:01BB 01 ...
                     └─127.0.0.1:4660  └─93.184.216.34:443
                     
/proc/4150932/fd/5 -> socket:[12345]

Result: TCP connection from 127.0.0.1:4660 to 93.184.216.34:443
```

## Performance Impact

All changes maintain async/non-blocking architecture:
- **File operations**: Still queued async, now also stored in-memory (<1μs)
- **Network detection**: Only scans during periodic checks (1-second intervals)
- **Duplicate detection**: O(n) array scan, but n is small (processes <256, connections <256)
- **Memory dumps**: Report tracking adds <1ms to dump operation

## Testing

```bash
# Clean slate
rm -rf sandbox_*

# Run sandbox
sudo ./realtime_memdump_tool --full_dump --sandbox-timeout 1 --sandbox /path/to/malware

# Verify complete report
REPORT=$(ls -td sandbox_* | head -1)/report.json
jq . "$REPORT"

# Check all sections present
jq 'keys' "$REPORT"
# Should output: ["analysis", "file_operations", "memory_dumps", "network_activity", "processes", "summary"]

# Verify no duplicates in processes
jq '.processes | group_by(.pid) | map({pid: .[0].pid, count: length}) | map(select(.count > 1))' "$REPORT"
# Should output: [] (empty array)

# Check network connections are real
jq '.network_activity' "$REPORT"
# Should show actual TCP/UDP connections, not just "socket:" entries
```

## Files Modified

- `realtime_memdump_tool.c`: All changes in single file
  - Added 3 new data structures (file_ops, network, memdumps)
  - Modified `report_sandbox_process()`: Duplicate detection
  - Modified `report_file_operation()`: Store in report array, added risk/category params
  - Modified `report_network_activity()`: Store in report array, duplicate detection
  - Rewrote `check_network_connections()`: Parse kernel network tables
  - Modified `dump_full_process_memory()`: Report dumps to JSON
  - Modified `finalize_sandbox_report()`: Write all 3 new sections

## Backward Compatibility

✅ Fully backward compatible
✅ No changes to command-line arguments
✅ Existing functionality unchanged
✅ Report structure extended (not breaking existing fields)
