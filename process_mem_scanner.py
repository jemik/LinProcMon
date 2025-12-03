#!/usr/bin/env python3
"""
process_mem_scanner_v5.5 — Hybrid YARA Memory Scanner

NEW IN v5.5:
    • Parallel Phase 2 deep scanning (ProcessPoolExecutor)
    • JSON reporting (--json-report <file>)
    • Improved result structure
    • Self-exclusion (scanner PID + parent PID)
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import math
import json
import datetime
from concurrent.futures import (
    ThreadPoolExecutor,
    ProcessPoolExecutor,
    as_completed
)

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

# ======================================================================
# Utility
# ======================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()


def shannon_entropy(data):
    if not data:
        return 0.0
    freqs = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freqs.values()]
    return -sum(p * math.log2(p) for p in probs)


def compute_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def detect_arch(exe_path):
    try:
        with open(exe_path, "rb") as f:
            hdr = f.read(0x40)
    except Exception:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64-bit ELF
        if e_machine == 0x3E:
            return "x86_64"
        if e_machine == 0xB7:
            return "arm64"
    else:
        if e_machine == 0x03:
            return "x86"
        if e_machine == 0x28:
            return "arm"
    return "x86_64"


def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86": return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64": return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm": return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


# ======================================================================
# Indicator detection
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr, perms, _, _, inode = parts[:5]
                path = parts[5] if len(parts) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    indicators.append(f"RWX region: {addr} {perms}")
                if "x" in perms and inode == "0" and path in ("", "0"):
                    indicators.append(f"Anonymous executable region: {addr}")
                if "x" in perms and "memfd:" in path:
                    indicators.append(f"memfd executable region: {addr} {path}")
    except Exception:
        pass

    try:
        current = None
        with open(smaps_path, "r") as f:
            for line in f:
                if "-" in line and ":" not in line:
                    current = line.split()[0]
                if line.startswith("VmFlags:"):
                    flags = line.split(":")[1].strip().split()
                    if "ex" in flags and ("mr" in flags or "mw" in flags):
                        indicators.append(f"VmFlags RW→RX: {current}")
    except Exception:
        pass

    return indicators


# ======================================================================
# Safe memory read
# ======================================================================

def read_region(pid, start, size, max_bytes):
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as f:
            f.seek(start)
            return f.read(min(size, max_bytes))
    except Exception:
        return None


# ======================================================================
# Deep scan worker (for multiprocessing)
# ======================================================================

def deep_worker(args):
    pid, rule_path, dump_dir, max_read, no_fd_scan = args

    result = {
        "pid": pid,
        "memory_regions": [],
        "fd_matches": [],
        "injection_indicators": [],
        "errors": []
    }

    try:
        rules = yara.compile(filepath=rule_path)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception as e:
        result["errors"].append(f"map read: {e}")
        return result

    # Indicators
    indicators = detect_injection_indicators(pid)
    result["injection_indicators"] = indicators

    # Architecture
    try:
        exe = psutil.Process(pid).exe()
        arch = detect_arch(exe)
    except:
        arch = "x86_64"
    md = get_disassembler(arch)

    # Deep scan memory
    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue
        addr_range, perms = parts[0], parts[1]

        if "r" not in perms:
            continue

        start_s, end_s = addr_range.split("-")
        start = int(start_s, 16)
        end = int(end_s, 16)
        size = end - start
        if size <= 0:
            continue

        region = read_region(pid, start, size, max_read)
        if not region:
            continue

        try:
            matches = rules.match(data=region)
        except:
            continue

        if not matches:
            continue

        region_entry = {
            "address": addr_range,
            "perms": perms,
            "entropy": shannon_entropy(region),
            "matches": []
        }

        # record matches
        for m in matches:
            for s in m.strings:
                ident = s.identifier
                for inst in s.instances:
                    off = inst.offset
                    abs_off = start + off
                    mlen = len(inst.matched_data)

                    region_entry["matches"].append({
                        "rule": m.rule,
                        "string": ident,
                        "absolute_offset": hex(abs_off),
                        "length": mlen
                    })

        # dump region if requested
        if dump_dir:
            outdir = os.path.join(dump_dir, f"pid_{pid}")
            os.makedirs(outdir, exist_ok=True)
            dump_path = os.path.join(outdir, f"region_{addr_range.replace('-', '_')}.bin")
            try:
                with open(dump_path, "wb") as f:
                    f.write(region)
                region_entry["dump_file"] = dump_path
            except Exception as e:
                result["errors"].append(f"Dump error: {e}")

        result["memory_regions"].append(region_entry)

    # FD scanning
    if not no_fd_scan:
        fd_path = f"/proc/{pid}/fd"
        if os.path.isdir(fd_path):
            for fd in os.listdir(fd_path):
                full = os.path.join(fd_path, fd)
                try:
                    target = os.readlink(full)
                except:
                    continue

                if target.startswith("socket:") or target.startswith("pipe:"):
                    continue

                try:
                    with open(full, "rb") as f:
                        data = f.read(max_read)
                except:
                    continue

                try:
                    fd_matches = rules.match(data=data)
                except:
                    continue

                if fd_matches:
                    entry = {
                        "fd": fd,
                        "target": target,
                        "rules": [m.rule for m in fd_matches]
                    }

                    if dump_dir:
                        outdir = os.path.join(dump_dir, f"pid_{pid}")
                        os.makedirs(outdir, exist_ok=True)
                        dump_path = os.path.join(outdir, f"fd_{fd}.bin")
                        try:
                            with open(dump_path, "wb") as f:
                                f.write(data)
                            entry["dump"] = dump_path
                        except Exception as e:
                            result["errors"].append(f"FD dump: {e}")

                    result["fd_matches"].append(entry)

    return result


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Hybrid YARA Memory Scanner v5.5 (parallel deep scan)")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--max-read", type=int, default=5*1024*1024)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--deep-workers", type=int, default=4,
                        help="Number of workers for Phase 2 deep scanning")
    parser.add_argument("--no-fd-scan", action="store_true",
                        help="Disable FD scanning")
    parser.add_argument("--json-report",
                        help="Save full scan results to a JSON file")
    args = parser.parse_args()

    # self PID exclusion
    self_pid = os.getpid()
    parent_pid = os.getppid()

    print(Fore.CYAN + f"[*] Scanner PID={self_pid}, Parent PID={parent_pid}")
    print(Fore.CYAN + f"[*] Loading YARA rule: {args.rule}")

    rules = yara.compile(filepath=args.rule)

    # Phase 1 — Threaded YARA scan
    print("[*] Enumerating processes...")
    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Found {len(pids)} processes.\n")

    print(Fore.CYAN + "[*] Phase 1 — threaded YARA PID scan\n")
    matched = {}

    def scan_one(pid):
        if pid == self_pid or pid == parent_pid:
            return pid, []
        try:
            res = rules.match(pid=pid)
            return pid, res
        except:
            return pid, []

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = {exe.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()

            if pid == self_pid or pid == parent_pid:
                continue

            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe_path = proc.exe()
                    cmd = " ".join(proc.cmdline())
                except:
                    name = exe_path = cmd = "<unknown>"

                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | {name} | {exe_path} | {cmd} "
                    f"| Rules: {[m.rule for m in res]}"
                )

    print(f"\n[*] Phase 1 complete. {len(matched)} matched processes.\n")

    if not matched:
        print(Fore.YELLOW + "[*] No matches found.")
        return

    # Phase 2 — Parallel deep scan
    print(Fore.CYAN + "[*] Phase 2 — deep forensic scanning (parallel)\n")

    tasks = [
        (pid, args.rule, args.dump_dir, args.max_read, args.no_fd_scan)
        for pid in matched
        if pid not in (self_pid, parent_pid)
    ]

    results = {}

    with ProcessPoolExecutor(max_workers=args.deep_workers) as exe:
        futures = {exe.submit(deep_worker, t): t[0] for t in tasks}
        for fut in as_completed(futures):
            pid = futures[fut]
            try:
                results[pid] = fut.result()
                print(Fore.GREEN + f"[+] Deep scan complete for PID {pid}")
            except Exception as e:
                print(Fore.RED + f"[!] Deep scan failed for PID {pid}: {e}")
                results[pid] = {"pid": pid, "error": str(e)}

    # JSON Report
    if args.json_report:
        report = {
            "timestamp": now_iso(),
            "scanner_pid": self_pid,
            "matches": []
        }

        for pid, res in results.items():
            entry = {
                "pid": pid,
                "memory_regions": res.get("memory_regions", []),
                "fd_matches": res.get("fd_matches", []),
                "injection_indicators": res.get("injection_indicators", []),
                "errors": res.get("errors", [])
            }

            # Add metadata from Phase 1
            try:
                proc = psutil.Process(pid)
                entry["name"] = proc.name()
                entry["exe"] = proc.exe()
                entry["cmd"] = " ".join(proc.cmdline())
                entry["sha256"] = compute_sha256(proc.exe())
            except:
                entry["name"] = "<unknown>"
                entry["exe"] = "<unknown>"
                entry["cmd"] = "<unknown>"
                entry["sha256"] = None

            report["matches"].append(entry)

        try:
            with open(args.json_report, "w") as f:
                json.dump(report, f, indent=2)
            print(Fore.GREEN + f"\n[*] JSON report saved → {args.json_report}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON report: {e}")


if __name__ == "__main__":
    main()