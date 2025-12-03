#!/usr/bin/env python3
"""
process_mem_scanner_v3.py
Advanced Multithreaded Linux Memory Scanner (YARA 4.5.4)

FEATURES:
- Multithreaded scanning of processes (maps + FD)
- Filters: --only-exec, --only-anon, --only-memfd
- Entropy scoring for memory regions + FD blobs
- Auto-JSON output (--json)
- Auto dump of matched regions (--dump-dir)
- Progress bar with ETA
- Full YARA 4.5.4 compatibility (StringMatchInstance.matched_data)
"""

import argparse
import os
import sys
import time
import math
import json
import hashlib
import datetime
import psutil
import yara
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# =====================================================================
# Utility Functions
# =====================================================================

def shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = {b: data.count(b) for b in set(data)}
    probs = [count / len(data) for count in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


def compute_sha256(path):
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def get_proc_info(proc):
    info = {}
    try:
        info["pid"] = proc.pid
        info["ppid"] = proc.ppid()
        info["exe"] = proc.exe()
        info["cmdline"] = " ".join(proc.cmdline())
        info["name"] = proc.name()
        info["sha256"] = compute_sha256(info["exe"])
    except Exception:
        pass
    return info


def progress_bar(prefix, current, total, start_time, bar_length=50):
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    eta = time.strftime("%H:%M:%S", time.gmtime(remaining))

    frac = current / total
    filled = int(bar_length * frac)
    bar = "+" * filled + "-" * (bar_length - filled)
    print(
        f"\r{prefix} | {current}/{total} [{bar}] ETA {eta}",
        end="",
        flush=True,
    )


# =====================================================================
# Memory Region Scanning
# =====================================================================

def scan_maps(pid, rules, max_read, only_exec, only_anon):
    results = []

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        proc = psutil.Process(pid)
    except Exception:
        return results

    try:
        maps_f = open(maps_path, "r")
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        return results

    with maps_f, mem_f:
        for line in maps_f:
            parts = line.split()
            if len(parts) < 2:
                continue

            addr_range, perms = parts[0], parts[1]

            # Filters
            if only_exec and "x" not in perms:
                continue
            if only_anon and (len(parts) < 6 or parts[5] != "0"):
                continue

            if "r" not in perms:
                continue

            start_s, end_s = addr_range.split("-")
            start = int(start_s, 16)
            end = int(end_s, 16)
            size = end - start

            if size <= 0:
                continue

            read_size = min(size, max_read)

            try:
                mem_f.seek(start)
                data = mem_f.read(read_size)
            except Exception:
                continue

            if not data:
                continue

            try:
                matches = rules.match(data=data)
            except Exception:
                continue

            if matches:
                ent = shannon_entropy(data)
                results.append({
                    "pid": pid,
                    "type": "maps",
                    "region_start": start,
                    "entropy": ent,
                    "matches": matches,
                    "data": data,
                })

    return results


# =====================================================================
# FD Scan
# =====================================================================

def scan_fds(pid, rules, max_read, only_memfd):
    results = []
    fd_dir = f"/proc/{pid}/fd"

    if not os.path.isdir(fd_dir):
        return results

    try:
        fds = os.listdir(fd_dir)
    except Exception:
        return results

    for fd in fds:
        fd_path = os.path.join(fd_dir, fd)

        try:
            target = os.readlink(fd_path)
        except Exception:
            continue

        if only_memfd and not target.startswith("memfd:"):
            continue

        if target.startswith("socket:") or target.startswith("pipe:"):
            continue

        try:
            with open(fd_path, "rb", 0) as f:
                data = f.read(max_read)
        except Exception:
            continue

        if not data:
            continue

        try:
            matches = rules.match(data=data)
        except Exception:
            continue

        if matches:
            ent = shannon_entropy(data)
            results.append({
                "pid": pid,
                "type": "fd",
                "fd_path": fd_path,
                "fd_target": target,
                "entropy": ent,
                "matches": matches,
                "data": data,
            })

    return results


# =====================================================================
# Worker Function
# =====================================================================

def scan_process(pid, rules, args):
    try:
        proc = psutil.Process(pid)
    except Exception:
        return []

    # Skip scanner itself
    if pid in (os.getpid(), os.getppid()):
        return []

    out = []

    # scan maps
    out.extend(scan_maps(
        pid,
        rules,
        args.max_region_size,
        args.only_exec,
        args.only_anon,
    ))

    # scan fds
    out.extend(scan_fds(
        pid,
        rules,
        args.max_region_size,
        args.only_memfd,
    ))

    return out


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="Process Memory Scanner V3")
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule")
    parser.add_argument("--max-region-size", type=int, default=25*1024*1024)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--json", help="Output results to JSON file")
    parser.add_argument("--dump-dir", help="Directory to dump matched region blobs")
    parser.add_argument("--only-exec", action="store_true", help="Scan only executable regions")
    parser.add_argument("--only-anon", action="store_true", help="Scan only anonymous memory")
    parser.add_argument("--only-memfd", action="store_true", help="Scan only memfd-backed FDs")
    args = parser.parse_args()

    # Compile YARA
    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] YARA compile error: {e}")
        sys.exit(1)

    print(Fore.CYAN + f"[*] Loaded YARA rule: {args.rule}")

    # Collect processes
    procs = [p.pid for p in psutil.process_iter()]
    total = len(procs)

    print(f"[*] Found {total} processes")
    print(f"[*] Scanning using {args.threads} threads...\n")

    start_time = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_process, pid, rules, args): pid for pid in procs}

        for idx, fut in enumerate(as_completed(futures), start=1):
            progress_bar("Scanning", idx, total, start_time)
            res = fut.result()
            if res:
                results.extend(res)

    print("\n\n[+] Scan completed.")
    print(f"[+] Found {len(results)} matching regions\n")

    # Dump results
    if args.dump_dir:
        os.makedirs(args.dump_dir, exist_ok=True)
        for i, entry in enumerate(results):
            path = os.path.join(args.dump_dir, f"dump_{i}_{entry['pid']}.bin")
            with open(path, "wb") as f:
                f.write(entry["data"])
            entry["dump_path"] = path

    # JSON output
    if args.json:
        json_out = []
        for r in results:
            json_out.append({
                "pid": r["pid"],
                "type": r["type"],
                "target": r.get("fd_target"),
                "entropy": r["entropy"],
                "matches": [m.rule for m in r["matches"]],
            })

        with open(args.json, "w") as f:
            json.dump(json_out, f, indent=2)

        print(f"[+] JSON written to {args.json}")

    # Pretty print matches
    for r in results:
        print(Fore.YELLOW + f"\nPID {r['pid']} - Type: {r['type']}")
        print(f"Entropy: {r['entropy']:.3f}")
        if r["type"] == "fd":
            print(f"FD: {r.get('fd_path')} -> {r.get('fd_target')}")

        for m in r["matches"]:
            print(Fore.GREEN + f"  YARA Match: {m.rule}")
            for s in m.strings:
                for inst in s.instances:
                    print(f"    String {s.identifier} offset={inst.offset}, len={len(inst.matched_data)}")

        if "dump_path" in r:
            print(Fore.CYAN + f"  Dumped: {r['dump_path']}")

    print("\n[✓] Finished.\n")


if __name__ == "__main__":
    main()