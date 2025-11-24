# JSON Report Completion Fix

## Problem

The sandbox JSON report (`report.json`) was incomplete, containing only the opening analysis section:

```json
{
  "analysis": {
    "start_time": 1763982123,
    "sample_path": "/tmp/elf_shell",
    "sample_sha1": "...",
    "sample_sha256": "...",
    "sample_type": "ELF",
    "sample_size": 810504,
    "timeout": 60
  },
```

The report was missing the `processes` array and `summary` section, and lacked the closing brace.

## Root Cause

The program had **two exit paths** but only one called the `finalize_sandbox_report()` function:

1. **Signal handler path** (Ctrl+C): `cleanup()` → `finalize_sandbox_report()` → `exit(0)` ✅
2. **Normal exit path** (timeout/process exit): `running=0` → loop exits → `main()` returns → **NO CLEANUP** ❌

When the sandbox naturally completed (timeout expired or process exited), the main loop would set `running=0`, exit the `while` loop, and return from `main()` **without** calling `cleanup()`, leaving the JSON report incomplete.

## Solution

### 1. Call cleanup() on Normal Exit

Modified the end of `main()` to explicitly call `cleanup()` before returning:

```c
while (running) {
    // ... main loop ...
}

// Normal exit - call cleanup to finalize reports
cleanup(0);
return 0;
```

### 2. Prevent Double Cleanup

Modified `cleanup()` to handle being called from both signal handlers and normal exit:

```c
void cleanup(int sig) {
    static int cleanup_called = 0;
    
    // Prevent double cleanup
    if (cleanup_called) {
        return;
    }
    cleanup_called = 1;
    
    // ... cleanup logic ...
    
    // Only call exit() if we were called from a signal handler
    if (sig != 0) {
        exit(0);
    }
}
```

**Key changes:**
- Added static flag to prevent re-entry
- Takes `sig` parameter: 0 = normal exit, non-zero = signal
- Only calls `exit(0)` if invoked by signal handler
- If called from main, returns control to main for normal program termination

### 3. Increased File Operation Flush Time

Increased the sleep time before finalizing the report to ensure all background file operations complete:

```c
// Give file worker time to finish pending operations
usleep(200000);  // 200ms (was 100ms)
```

### 4. Added More Signal Handlers

Registered additional signal handlers to catch more termination scenarios:

```c
signal(SIGINT, cleanup);   // Ctrl+C
signal(SIGTERM, cleanup);  // kill command
signal(SIGHUP, cleanup);   // Terminal closed
```

## Expected Result

Now the complete JSON report is generated:

```json
{
  "analysis": {
    "start_time": 1763982123,
    "sample_path": "/tmp/elf_shell",
    "sample_sha1": "4617a99639d971e3473b3a92553311f3b5be6cc5",
    "sample_sha256": "70796a903eb5fc5aebaec4c775a207473fb431a09a598fa65076ae4454077935",
    "sample_type": "ELF",
    "sample_size": 810504,
    "timeout": 60
  },
  "processes": [
    {
      "pid": 12345,
      "ppid": 1,
      "name": "elf_shell",
      "path": "/tmp/elf_shell",
      "cmdline": "/tmp/elf_shell",
      "start_time": 1763982123
    }
  ],
  "summary": {
    "end_time": 1763982183,
    "duration": 60,
    "total_processes": 1,
    "files_created": 0,
    "sockets_created": 0,
    "suspicious_findings": 0
  }
}
```

## Testing

To verify the fix works:

```bash
# Clean up old sandbox directories
rm -rf sandbox_*

# Run sandbox with timeout (will exit naturally)
sudo ./realtime_memdump_tool --sandbox-timeout 1 --sandbox /bin/sleep 2

# Check report completion
REPORT_DIR=$(ls -td sandbox_* | head -1)
cat "$REPORT_DIR/report.json"

# Validate JSON (if jq available)
jq . "$REPORT_DIR/report.json"

# Check for all sections
jq 'keys' "$REPORT_DIR/report.json"
# Should output: ["analysis", "processes", "summary"]
```

## Exit Scenarios Covered

| Scenario | Trigger | cleanup() Called | Report Complete |
|----------|---------|------------------|-----------------|
| Ctrl+C (SIGINT) | User interrupts | ✅ (signal) | ✅ |
| kill (SIGTERM) | External kill | ✅ (signal) | ✅ |
| Terminal close (SIGHUP) | Terminal exit | ✅ (signal) | ✅ |
| Sandbox timeout | Time limit reached | ✅ (normal) | ✅ |
| Process exit | Sandbox completes | ✅ (normal) | ✅ |

All exit paths now properly finalize the JSON report!

## Files Modified

- `realtime_memdump_tool.c`:
  - Modified `main()` to call `cleanup(0)` before return
  - Modified `cleanup()` to handle both signal and normal exit
  - Added SIGTERM and SIGHUP handlers
  - Increased file operation flush time to 200ms
  - Added static guard against double cleanup

## Backward Compatibility

✅ Fully backward compatible - all existing functionality preserved
✅ No changes to command-line arguments or usage
✅ Performance unchanged (cleanup only happens on exit)
