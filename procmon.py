import psutil
import time
import logging
from datetime import datetime
import os
import re

RED_BG = "\033[41m"
RESET = "\033[0m"

logging.basicConfig(
    filename='process_log.txt',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

seen_pids = set(p.pid for p in psutil.process_iter())

# Heuristic regex patterns for /proc/<pid>/maps
MAPS_PATTERNS = [
    r"memfd:",                        # memfd_create usage
    r"/tmp/.*\.so",                   # temp-shared objects
    r"/dev/shm/.*",                   # shared memory execution
    r"\[anon\].*rwx",                 # RWX anonymous memory
    r"\[heap\].*rwx",                 # RWX heap (rare & dangerous)
    r"/.*\(deleted\)",                # Deleted ELF still mapped
    r"/proc/self/exe",               # Self-injection
    r"^.*rwxp.*$",                    # Executable anonymous pages
]

def inspect_memory_maps(pid):
    """Parse /proc/<pid>/maps for suspicious memory segments."""
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, 'r') as f:
            content = f.read()
            for pattern in MAPS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    return pattern
    except Exception:
        return None
    return None

def log_new_processes():
    global seen_pids
    current_pids = set(p.pid for p in psutil.process_iter())
    new_pids = current_pids - seen_pids

    for pid in new_pids:
        try:
            p = psutil.Process(pid)
            name = p.name()
            cmdline = p.cmdline()
            cmd_str = ' '.join(cmdline) if cmdline else ''
            ppid = p.ppid()

            memory_match = inspect_memory_maps(pid)
            log_msg = f"New process: Name='{name}' PID={pid} PPID={ppid} CMD='{cmd_str}'"

            if memory_match:
                log_msg += f" [MEMORY SUSPICIOUS: matched '{memory_match}']"
                logging.info(log_msg)
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"{now}. {RED_BG}MEMORY SUSPICIOUS match '{memory_match}'{RESET} Name='{name}' PID={pid} PPID={ppid} CMD='{cmd_str}'")
            else:
                logging.info(log_msg)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    seen_pids = current_pids

if __name__ == "__main__":
    print("🛡️  Monitoring new processes with REAL memory heuristic detection. Ctrl+C to stop.")
    try:
        while True:
            log_new_processes()
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Monitoring stopped.")