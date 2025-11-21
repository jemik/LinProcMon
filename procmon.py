import psutil
import time
import logging
from datetime import datetime

# ANSI color codes for terminal output
RED_BG = "\033[41m"
RESET = "\033[0m"

# Set up logging to file
logging.basicConfig(
    filename='process_log.txt',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Suspicious command patterns (heuristics)
SUSPICIOUS_KEYWORDS = [
    "memfd_create",
    "memfd",
    "/dev/shm/",
    "/proc/self",
    "/tmp/",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "mmap",
    "mprotect",
    "sh -c",
    "python -c",
    "perl -e",
    "ruby -e",
    "eval",
    "exec",
    "base64",
    "curl | sh",
    "wget | sh",
]

seen_pids = set(p.pid for p in psutil.process_iter())

def is_suspicious_command(cmdline):
    cmdline_str = ' '.join(cmdline).lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in cmdline_str:
            return keyword
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
            suspicious_hit = is_suspicious_command(cmdline)

            log_msg = f"New process: Name='{name}' PID={pid} PPID={ppid} CMD='{cmd_str}'"

            if suspicious_hit:
                log_msg += f" [SUSPICIOUS: matched '{suspicious_hit}']"
                # Log to file
                logging.info(log_msg)
                # Print to screen with red background
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"{now}. {RED_BG}SUSPICIOUS match '{suspicious_hit}'{RESET} Name='{name}' PID={pid} PPID={ppid} CMD='{cmd_str}'")
            else:
                logging.info(log_msg)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    seen_pids = current_pids

if __name__ == "__main__":
    print("🛡️  Monitoring new processes with heuristic detection. Press Ctrl+C to stop.")
    try:
        while True:
            log_new_processes()
            time.sleep(1)
    except KeyboardInterrupt:
        print("🛑 Monitoring stopped.")