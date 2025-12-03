#!/usr/bin/env python3
"""
process_mem_scanner_v3.2.py
Multithreaded Linux memory + FD scanner using YARA 4.5.4

New in v3.2:
- Per-process timeout (default 60 sec)
- Skips zombie + kernel threads automatically
- NEVER hangs on /proc/<pid>/mem again
- Full v3.1 human-readable output including:
  * PID, PPID, EXE, CMD, SHA256
  * Parent + children
  * Entropy of region/FD
  * YARA rule + meta
  * String + offset + len
  * 256-byte hex dump with match highlighted in RED
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
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


# =====================================================================
# Utility
# =====================================================================

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freq.values()]
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


def get_proc_info(proc: psutil.Process):
    info = {}
    try:
        info["pid"] = proc.pid
        info["ppid"] = proc.ppid()
        info["name"] = proc.name()
        info["exe"] = proc.exe()
        info["cmdline"] = " ".join(proc.cmdline())
        info["sha256"] = compute_sha256(info["exe"])
    except Exception:
        pass
    return info


def print_proc_info(title, info, indent=""):
    print(f"{indent}{title}:")
    if not info:
        print(f"{indent}  <unavailable>")
        return
    print(f"{indent}  PID   : {info.get('pid')}")
    print(f"{indent}  Name  : {info.get('name')}")
    print(f"{indent}  PPID  : {info.get('ppid')}")
    print(f"{indent}  EXE   : {info.get('exe')}")
    print(f"{indent}  CMD   : {info.get('cmdline')}")
    print(f"{indent}  SHA256: {info.get('sha256')}")


def progress_bar(prefix, current, total, start_time, bar_length=50):
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    eta = time.strftime("%H:%M:%S", time.gmtime(remaining)) if remaining > 0 else "--:--:--"

    frac = current / total
    filled = int(bar_length * frac)
    bar = "+" * filled + "-" * (bar_length - filled)

    print(f"\r{prefix} | {current}/{total} [{bar}] ETA {eta}", end="", flush=True)


# =====================================================================
# HEX DUMP
# =====================================================================

def hex_dump_with_highlight(data: bytes, base_addr: int, match_offset: int,
                            match_len: int, context: int = 256):

    half = context // 2
    start = max(0, match_offset - half)
    end = min(len(data), match_offset + match_len + half)
    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"        Hex dump (0x{snippet_base:016x} - 0x{snippet_base + len(snippet):016x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        addr = snippet_base + i

        hex_parts, ascii_parts = [], []
        for j, b in enumerate(line):
            gi = start + i + j
            in_match = (match_offset <= gi < match_offset + match_len)

            h = f"{b:02x}"
            c = chr(b) if 32 <= b <= 126 else '.'

            if in_match:
                h = Fore.RED + h + Style.RESET_ALL
                c = Fore.RED + c + Style.RESET_ALL

            hex_parts.append(h)
            ascii_parts.append(c)

        print(f"        0x{addr:016x}  {' '.join(hex_parts):<48}  {''.join(ascii_parts)}")


# =====================================================================
# MEMORY SCAN
# =====================================================================

def scan_maps(pid, rules, max_read, only_exec, only_anon):
    results = []

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        proc = psutil.Process(pid)
        status = proc.status()
        if status in ("zombie", "dead"):
            return results
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

            if only_exec and "x" not in perms:
                continue
            if only_anon:
                if len(parts) < 6 or parts[5] != "0":
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
                region_data = mem_f.read(read_size)
            except Exception:
                continue

            if not region_data:
                continue

            try:
                matches = rules.match(data=region_data)
            except Exception:
                continue

            if matches:
                ent = shannon_entropy(region_data)
                results.append({
                    "pid": pid,
                    "type": "maps",
                    "region_start": start,
                    "entropy": ent,
                    "matches": matches,
                    "data": region_data,
                })

    return results


# =====================================================================
# FD SCAN
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
# PER-PID WORKER
# =====================================================================

def scan_process(pid, rules, args):

    # Skip kernel threads (no EXE)
    try:
        proc = psutil.Process(pid)
        if not proc.exe():
            return []
    except Exception:
        return []

    if pid in (os.getpid(), os.getppid()):
        return []

    results = []
    results.extend(scan_maps(pid, rules, args.max_region_size,
                             args.only_exec, args.only_anon))
    results.extend(scan_fds(pid, rules, args.max_region_size,
                             args.only_memfd))

    return results


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="Process Memory Scanner v3.2")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--max-region-size", type=int, default=25*1024*1024)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=60,
                        help="Max seconds per process scan (default 60)")
    parser.add_argument("--json", help="Write JSON summary")
    parser.add_argument("--dump-dir", help="Dump matched region blobs")
    parser.add_argument("--only-exec", action="store_true")
    parser.add_argument("--only-anon", action="store_true")
    parser.add_argument("--only-memfd", action="store_true")
    args = parser.parse_args()

    # Compile YARA rules
    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] YARA compile error: {e}")
        sys.exit(1)

    print(Fore.CYAN + f"[*] Loaded rule: {args.rule}")

    procs = [p.pid for p in psutil.process_iter()]
    total = len(procs)
    print(f"[*] Found {total} processes")

    start_time = time.time()
    results = []
    timeouts = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_process, pid, rules, args): pid for pid in procs}

        for idx, fut in enumerate(as_completed(futures), start=1):
            progress_bar("Scanning processes", idx, total, start_time)

            pid = futures[fut]

            try:
                res = fut.result(timeout=args.timeout)
            except TimeoutError:
                timeouts.append(pid)
                print(Fore.RED + f"\n[!] Timeout scanning PID {pid} — skipped.")
                continue
            except Exception:
                continue

            if res:
                results.extend(res)

    print("\n\n[+] Scan complete.")
    print(f"[+] Matches: {len(results)}")
    print(f"[+] Timeouts: {len(timeouts)} → {timeouts}\n")

    # Dump matched blobs
    if args.dump_dir:
        os.makedirs(args.dump_dir, exist_ok=True)
        for i, entry in enumerate(results):
            dump_name = f"{entry['pid']}_{entry['type']}_{i}.bin"
            entry["dump_path"] = os.path.join(args.dump_dir, dump_name)
            with open(entry["dump_path"], "wb") as f:
                f.write(entry["data"])

    # JSON output
    if args.json:
        summary = []
        for r in results:
            summary.append({
                "pid": r["pid"],
                "type": r["type"],
                "entropy": r["entropy"],
                "region_start": r.get("region_start"),
                "fd_path": r.get("fd_path"),
                "fd_target": r.get("fd_target"),
                "matches": [m.rule for m in r["matches"]],
                "dump_path": r.get("dump_path"),
            })
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] JSON summary written to {args.json}\n")

    # HUMAN-READABLE DETAILED OUTPUT
    if not results:
        print("[*] No YARA matches found.")
        return

    results.sort(key=lambda r: (r["pid"], r["type"], r.get("region_start", 0)))

    current_pid = None

    for entry in results:
        pid = entry["pid"]

        if pid != current_pid:
            current_pid = pid
            ts = datetime.datetime.now().isoformat(timespec="seconds")
            print(Fore.CYAN + f"[{ts}] MATCH in PID {pid}")

            # Process info
            try:
                proc = psutil.Process(pid)
                pinfo = get_proc_info(proc)
            except:
                pinfo = None
            print_proc_info("Process", pinfo)

            # Parent
            try:
                parent = proc.parent()
                ppar = get_proc_info(parent) if parent else None
            except:
                ppar = None
            print_proc_info("Parent", ppar)

            # Children
            try:
                children = proc.children()
            except:
                children = []
            if children:
                print("Children:")
                for ch in children:
                    cinfo = get_proc_info(ch)
                    print_proc_info(f"  Child PID {cinfo.get('pid')}", cinfo, indent="  ")
            else:
                print("Children: <none>")
            print()

        # Region header
        if entry["type"] == "maps":
            print(Fore.YELLOW + f"  [MEMORY] start=0x{entry['region_start']:016x} entropy={entry['entropy']:.3f}")
            base_addr = entry["region_start"]
        else:
            print(Fore.YELLOW + f"  [FD] {entry.get('fd_path')} -> {entry.get('fd_target')} entropy={entry['entropy']:.3f}")
            base_addr = 0

        # Detailed YARA matches
        for m in entry["matches"]:
            print(Fore.MAGENTA + f"    YARA Match: {m.rule}")

            if m.meta:
                meta_str = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"      Meta: {meta_str}")

            for s in m.strings:
                for inst in s.instances:
                    off = inst.offset
                    matched = inst.matched_data
                    length = len(matched)
                    va = base_addr + off

                    if entry["type"] == "maps":
                        print(Fore.GREEN + f"      String {s.identifier} Offset=0x{va:016x} len={length}")
                    else:
                        print(Fore.GREEN + f"      String {s.identifier} Offset={off} len={length}")

                    hex_dump_with_highlight(entry["data"], base_addr, off, length)

        if entry.get("dump_path"):
            print(Fore.CYAN + f"      Blob dumped to: {entry['dump_path']}")

        print("-" * 80)

    print("\n[✓] Done.\n")


if __name__ == "__main__":
    main()