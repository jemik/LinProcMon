#!/usr/bin/env python3
"""
process_mem_scanner v5.6 — CLEAN + FIXED + FULL VERBOSE

WORKS WITH:
    yara-python 4.5.4  (uses s.instances[].offset!)

PHASE 1:
    Threaded YARA scan of all PIDs

PHASE 2:
    ProcessPool deep scan
    - Memory region enumeration
    - Per-match snippet extraction (256 bytes)
    - Hex dump
    - Full disassembly
    - Injection indicator detection
    - Optional FD scan
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import base64
import hashlib
import datetime
import json
import math

from colorama import Fore, Style, init as colorama_init
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from capstone import *

colorama_init(autoreset=True)

SNIP_BEFORE = 128
SNIP_AFTER  = 128

# ======================================================================
# UTILS
# ======================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()

def entropy(data: bytes):
    if not data:
        return 0.0
    freqs = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freqs.values()]
    return -sum(p * math.log2(p) for p in probs)

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(8192), b""):
                h.update(c)
        return h.hexdigest()
    except:
        return None

# ======================================================================
# ARCH DETECTION
# ======================================================================

def detect_arch(path):
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x40)
    except:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei = hdr[4]
    mach = struct.unpack("<H", hdr[18:20])[0]

    if ei == 2:
        if mach == 0x3E: return "x86_64"
        if mach == 0xB7: return "arm64"
    else:
        if mach == 0x03: return "x86"
        if mach == 0x28: return "arm"

    return "x86_64"

def get_dis(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":    return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":  return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":    return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

# ======================================================================
# HEX DUMP
# ======================================================================

def hex_dump(base, buf: bytes):
    out = []
    for i in range(0, len(buf), 16):
        chunk = buf[i:i+16]
        hexp = " ".join(f"{b:02x}" for b in chunk)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"        0x{base+i:016x}  {hexp:<48}  {asc}")
    return "\n".join(out)

# ======================================================================
# SNIPPET EXTRACTION
# ======================================================================

def extract_snippet(region_bytes, region_va_start, match_offset, match_len):
    start = max(0, match_offset - SNIP_BEFORE)
    end   = min(len(region_bytes), match_offset + match_len + SNIP_AFTER)
    data  = region_bytes[start:end]
    va    = region_va_start + start
    return data, va

# ======================================================================
# INJECTION INDICATORS
# ======================================================================

def detect_injection(pid):
    out = []
    maps = f"/proc/{pid}/maps"
    smaps = f"/proc/{pid}/smaps"

    try:
        with open(maps) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr, perms = parts[0], parts[1]
                path = parts[5] if len(parts) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    out.append(f"RWX region: {addr}")

                if "x" in perms and "memfd:" in path:
                    out.append(f"memfd exec: {addr} {path}")

                if "x" in perms and len(path.strip()) == 0:
                    out.append(f"Anon exec region: {addr}")

    except:
        pass

    return out

# ======================================================================
# READ MEMORY REGION
# ======================================================================

def read_region(pid, start, size, max_read):
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
            f.seek(start)
            return f.read(min(size, max_read))
    except:
        return None

# ======================================================================
# DEEP WORKER
# ======================================================================

def deep_worker(task):
    pid, rule_path, max_read, no_fd_scan = task
    result = {
        "pid": pid,
        "regions": [],
        "fd_matches": [],
        "indicators": [],
        "errors": []
    }

    try:
        rules = yara.compile(filepath=rule_path)
    except Exception as e:
        result["errors"].append(f"rule compile: {e}")
        return result

    # arch
    try:
        exe = psutil.Process(pid).exe()
        arch = detect_arch(exe)
    except:
        arch = "x86_64"

    dis = get_dis(arch)

    # injection indicators
    result["indicators"] = detect_injection(pid)

    # maps
    try:
        with open(f"/proc/{pid}/maps") as f:
            lines = f.read().splitlines()
    except Exception as e:
        result["errors"].append(f"maps: {e}")
        return result

    # ----------------------
    # MEMORY REGIONS
    # ----------------------
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr = parts[0]
        perms = parts[1]

        if "r" not in perms:
            continue

        start_s, end_s = addr.split("-")
        start, end = int(start_s, 16), int(end_s, 16)
        size = end - start
        if size <= 0:
            continue

        region = read_region(pid, start, size, max_read)
        if not region:
            continue

        # run yara
        try:
            matches = rules.match(data=region)
        except:
            continue

        if not matches:
            continue

        region_entry = {
            "address": addr,
            "perms": perms,
            "entropy": entropy(region),
            "matches": []
        }

        for m in matches:
            for s in m.strings:
                sid = s.identifier
                for inst in s.instances:
                    off = inst.offset

                    snip_bytes, snip_va = extract_snippet(
                        region,
                        start,
                        off,
                        len(inst.matched_data)
                    )

                    hex_snip = hex_dump(snip_va, snip_bytes)

                    # disasm
                    dis_lines = []
                    try:
                        for ins in dis.disasm(snip_bytes, snip_va):
                            dis_lines.append(
                                f"        0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            )
                    except:
                        pass

                    region_entry["matches"].append({
                        "rule": m.rule,
                        "string": sid,
                        "offset": hex(start + off),
                        "snippet_va": hex(snip_va),
                        "snippet_hex_dump": hex_snip,
                        "disasm": "\n".join(dis_lines)
                    })

        result["regions"].append(region_entry)

    # ----------------------
    # FD SCAN
    # ----------------------
    if not no_fd_scan:
        fd_dir = f"/proc/{pid}/fd"
        if os.path.isdir(fd_dir):
            for fd in os.listdir(fd_dir):
                fd_path = os.path.join(fd_dir, fd)
                try:
                    target = os.readlink(fd_path)
                except:
                    continue

                if target.startswith(("pipe:", "socket:")):
                    continue

                try:
                    with open(fd_path, "rb") as f:
                        data = f.read(max_read)
                except:
                    continue

                try:
                    fd_y = rules.match(data=data)
                except:
                    continue

                if fd_y:
                    result["fd_matches"].append({
                        "fd": fd,
                        "target": target,
                        "rules": [x.rule for x in fd_y]
                    })

    return result

# ======================================================================
# PHASE 1 — YARA PID SCAN
# ======================================================================

def scan_pid(rules, pid, spid, ppid):
    if pid in (spid, ppid):
        return pid, None
    try:
        m = rules.match(pid=pid)
        return pid, (m if m else None)
    except:
        return pid, None

def phase1(rules, threads):
    print(Fore.CYAN + "\n[*] Phase 1 — threaded PID scan")
    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Total processes: {len(pids)}")

    matches = {}

    spid = os.getpid()
    ppid = os.getppid()

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futs = {exe.submit(scan_pid, rules, pid, spid, ppid): pid for pid in pids}

        for fut in as_completed(futs):
            pid, m = fut.result()
            if m:
                matches[pid] = m

                try:
                    pr = psutil.Process(pid)
                    name = pr.name()
                    exe_path = pr.exe()
                    cmd = " ".join(pr.cmdline())
                    sh = sha256(exe_path)
                except:
                    name = exe_path = cmd = "<unknown>"
                    sh = None

                rule_names = [x.rule for x in m]

                print(Fore.GREEN +
                      f"[+] PID {pid} MATCH | {name} | {exe_path}\n"
                      f"    CMD: {cmd}\n"
                      f"    SHA256: {sh}\n"
                      f"    Rules: {rule_names}\n")

    print(Fore.CYAN + f"[*] Phase 1 complete — {len(matches)} matches.\n")
    return matches

# ======================================================================
# MAIN
# ======================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-read", type=int, default=5*1024*1024)
    ap.add_argument("--no-fd-scan", action="store_true")
    args = ap.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.r}")
    rules = yara.compile(filepath=args.r)

    # -----------------------
    # PHASE 1
    # -----------------------
    matched = phase1(rules, args.threads)
    if not matched:
        print(Fore.YELLOW + "[*] No matches — exiting.")
        return

    # -----------------------
    # PHASE 2
    # -----------------------
    print(Fore.CYAN + f"[*] Phase 2 — deep scan of {len(matched)} processes...\n")

    tasks = [(pid, args.r, args.max_read, args.no_fd_scan)
             for pid in matched]

    deep_results = {}

    with ProcessPoolExecutor(max_workers=args.workers) as exe:
        futs = {exe.submit(deep_worker, t): t[0] for t in tasks}

        for fut in as_completed(futs):
            pid = futs[fut]
            res = fut.result()
            deep_results[pid] = res

            print(Fore.GREEN + f"\n[+] Deep scan complete for PID {pid}\n")

            # PRINT PHASE-2 DETAILS
            for region in res["regions"]:
                print(Fore.CYAN + f"  REGION {region['address']} perms={region['perms']} "
                                  f"entropy={region['entropy']:.3f}")

                for m in region["matches"]:
                    print(Fore.GREEN + f"    Rule={m['rule']} String={m['string']} "
                                       f"Offset={m['offset']}")
                    print("    Snippet Hex Dump:")
                    print(m["snippet_hex_dump"])
                    print("    Disassembly:")
                    print(m["disasm"])
                    print()

            if res["indicators"]:
                print(Fore.MAGENTA + "  Injection Indicators:")
                for i in res["indicators"]:
                    print("    •", i)

            if res["fd_matches"]:
                print(Fore.YELLOW + "  FD matches:")
                for fd in res["fd_matches"]:
                    print(f"    FD={fd['fd']} → {fd['target']} | Rules={fd['rules']}")

    print(Fore.CYAN + "\n[*] All deep scans completed.\n")
    print(Fore.GREEN + "[*] DONE.\n")


if __name__ == "__main__":
    main()