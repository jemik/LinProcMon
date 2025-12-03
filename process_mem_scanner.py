#!/usr/bin/env python3
# ======================================================================
# process_mem_scanner_v5.6 — FIXED + RESTORED MEMORY OUTPUT
#
# PHASE 1  (threaded):
#     - YARA native PID scan (rules.match(pid=<pid>))
#     - Self-PID excluded
#
# PHASE 2:
#     - /proc/<pid>/maps memory region scanning
#     - YARA region matches
#     - FULL hex dump + disassembly
#     - JSON report (all matches included)
# ======================================================================

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import math
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init as colorama_init
from capstone import *
colorama_init(autoreset=True)

SELF_PID = os.getpid()

# ======================================================================
# Utility
# ======================================================================

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

    # 64-bit
    if ei_class == 2:
        if e_machine == 0x3E: return "x86_64"
        if e_machine == 0xB7: return "arm64"
    # 32-bit
    else:
        if e_machine == 0x03: return "x86"
        if e_machine == 0x28: return "arm"

    return "x86_64"

def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":     return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":   return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":     return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

def hex_dump_highlight(data, base, match_off, match_len, ctx=256):
    half = ctx // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)
    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump @ 0x{snippet_base:x}:")
    lines = []

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        hex_parts = []
        ascii_parts = []
        off = snippet_base + i

        for j, b in enumerate(line):
            gi = start + i + j
            inside = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."

            if inside:
                hx = Fore.RED + hx + Style.RESET_ALL
                ch = Fore.RED + ch + Style.RESET_ALL

            hex_parts.append(hx)
            ascii_parts.append(ch)

        line_str = f"0x{off:016x}  {' '.join(hex_parts):<48}  {''.join(ascii_parts)}"
        print("        " + line_str)
        lines.append(line_str)

    return lines


# ======================================================================
# Indicators
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"

    try:
        for line in open(maps_path):
            parts = line.split()
            if len(parts) < 2:
                continue
            addr, perms = parts[0], parts[1]
            inode = parts[4] if len(parts) >= 5 else "0"
            path  = parts[5] if len(parts) >= 6 else ""

            if "r" in perms and "w" in perms and "x" in perms:
                indicators.append(f"RWX mapping: {addr} {perms}")
            if "x" in perms and inode == "0" and path in ("", "0"):
                indicators.append(f"Anonymous executable memory @ {addr}")
            if "memfd:" in path:
                indicators.append(f"memfd executable: {addr}")
    except:
        pass

    return indicators


# ======================================================================
# Memory reading
# ======================================================================

def read_region(pid, start, size, max_bytes):
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as f:
            f.seek(start)
            return f.read(min(size, max_bytes))
    except Exception:
        return None


# ======================================================================
# Deep scanning
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, json_slot):
    maps_path = f"/proc/{pid}/maps"
    arch = detect_arch(psutil.Process(pid).exe())
    dis = get_disassembler(arch)

    try:
        maps = open(maps_path).read().splitlines()
    except:
        print("  [!] Could not read maps")
        return

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

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

        entropy = shannon_entropy(region)
        print(Fore.GREEN + f"\n  [+] Region match at {addr_range} perms={perms}")
        print(f"      Entropy: {entropy:.3f}")

        region_json = {
            "addr_range": addr_range,
            "perms": perms,
            "entropy": entropy,
            "matches": []
        }

        for m in matches:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            m_entry = {"rule": m.rule, "strings": []}

            for s in m.strings:
                ident = s.identifier
                for inst in s.instances:

                    off  = inst.offset
                    data = inst.matched_data
                    mlen = len(data)
                    abs_off = start + off

                    print(Fore.CYAN + f"\n    String {ident}: offset=0x{abs_off:x} len={mlen}")

                    # Hex dump
                    dump_lines = hex_dump_highlight(region, start, off, mlen)

                    # Disassembly fragment
                    ctx_start = max(0, off - 64)
                    ctx_end   = min(len(region), off + mlen + 64)
                    code = region[ctx_start:ctx_end]

                    print("\n    Disassembly:")
                    dis_lines = []
                    try:
                        for ins in dis.disasm(code, start + ctx_start):
                            high = (start + off) <= ins.address < (start + off + mlen)
                            prefix = ">>" if high else "  "
                            color = Fore.RED if high else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print("      " + color + line)
                            dis_lines.append(line)
                    except:
                        print("      <failed disassembly>")
                        dis_lines.append("<failed>")

                    # Save JSON entry
                    m_entry["strings"].append({
                        "identifier": ident,
                        "absolute_offset": abs_off,
                        "length": mlen,
                        "hex_dump": dump_lines,
                        "disassembly": dis_lines
                    })

            region_json["matches"].append(m_entry)

        json_slot.append(region_json)


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="YARA Memory Scanner v5.6 (Corrected)")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-fd-scan", action="store_true")
    parser.add_argument("--max-read", type=int, default=5*1024*1024)
    parser.add_argument("--json-report", default="report.json")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # ----------------------------------------------------
    # PHASE 1 — threaded YARA PID scan
    # ----------------------------------------------------
    print(Fore.CYAN + "\n[*] Phase 1 — YARA native PID scan (threaded)")
    pids = [p.pid for p in psutil.process_iter() if p.pid != SELF_PID]
    matched = {}

    def scan_one(pid):
        try:
            return pid, rules.match(pid=pid)
        except:
            return pid, []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
            if res:
                matched[pid] = res

                proc = psutil.Process(pid)
                exe = proc.exe()
                cmd = " ".join(proc.cmdline())
                name = proc.name()
                sha = compute_sha256(exe)

                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name: {name} | EXE: {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {[m.rule for m in res]}"
                )

    print(f"\n[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # ----------------------------------------------------
    # PHASE 2 — deep forensic scan
    # ----------------------------------------------------
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "matched_pids": {}
    }

    for pid, matches in matched.items():
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        proc_report = {
            "pid": pid,
            "process_name": "",
            "exe": "",
            "cmd": "",
            "sha256": "",
            "injection_indicators": [],
            "regions": []
        }

        # Metadata
        proc = psutil.Process(pid)
        exe = proc.exe()
        cmd = " ".join(proc.cmdline())
        sha = compute_sha256(exe)
        name = proc.name()

        proc_report["process_name"] = name
        proc_report["exe"] = exe
        proc_report["cmd"] = cmd
        proc_report["sha256"] = sha

        print(Fore.YELLOW + "Process Info:")
        print(f"  PID    : {pid}")
        print(f"  Name   : {name}")
        print(f"  EXE    : {exe}")
        print(f"  CMD    : {cmd}")
        print(f"  SHA256 : {sha}")

        # Indicators
        indicators = detect_injection_indicators(pid)
        proc_report["injection_indicators"] = indicators

        print(Fore.YELLOW + "\nInjection Indicators:")
        if indicators:
            for i in indicators:
                print(Fore.RED + "  [!] " + i)
        else:
            print("  <none>")

        # Deep scan
        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, proc_report["regions"])

        print(Fore.CYAN + "\n====================================================\n")
        report["matched_pids"][str(pid)] = proc_report

    # ----------------------------------------------------
    # JSON report
    # ----------------------------------------------------
    with open(args.json_report, "w") as f:
        json.dump(report, f, indent=2)

    print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()