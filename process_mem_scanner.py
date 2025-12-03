#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 (fixed)

This version restores ALL working deep-scan output from v5.1:
- Region matches
- Entropy
- Hex dumps
- Disassembly
- Correct YARA string offsets
- JSON reporting
- Own-PID filter
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import json
import math
from datetime import datetime

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
    freq = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


def compute_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


def detect_arch(path):
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x40)
    except:
        return "x86_64"
    if len(hdr) < 20: return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]
    if ei_class == 2:
        if e_machine == 0x3E: return "x86_64"
        if e_machine == 0xB7: return "arm64"
    else:
        if e_machine == 0x03: return "x86"
        if e_machine == 0x28: return "arm"
    return "x86_64"


def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86": return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64": return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm": return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


def hex_dump_highlight(data, base, match_off, match_len, ctx=256):
    half = ctx // 2
    start = max(0, match_off - half)
    end   = min(len(data), match_off + match_len + half)

    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump @ 0x{snippet_base:x}:")
    for i in range(0, len(snippet), 16):
        chunk = snippet[i:i+16]
        hex_line = []
        ascii_line = []

        for j,b in enumerate(chunk):
            global_idx = start + i + j
            highlight = (match_off <= global_idx < match_off + match_len)

            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."

            if highlight:
                hx = Fore.RED + hx + Style.RESET_ALL
                ch = Fore.RED + ch + Style.RESET_ALL

            hex_line.append(hx)
            ascii_line.append(ch)

        print(f"        0x{snippet_base + i:016x}  {' '.join(hex_line):<48}  {''.join(ascii_line)}")


# ======================================================================
# Memory scanning helpers
# ======================================================================

def read_region(pid, start, size, max_read):
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as f:
            f.seek(start)
            return f.read(min(size, max_read))
    except:
        return None


# ======================================================================
# Deep scan — FULLY RESTORED FROM v5.1
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, report_obj):

    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except:
        return

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    proc_report_regions = []

    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr_range, perms = parts[0], parts[1]
        if "r" not in perms:
            continue

        start_s, end_s = addr_range.split("-")
        start = int(start_s, 16)
        end   = int(end_s, 16)
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

        # OUTPUT RESTORED
        print(Fore.GREEN + f"\n  [+] Region match at {addr_range} perms={perms}")
        ent = shannon_entropy(region)
        print(f"      Entropy: {ent:.3f}")

        reg_entry = {
            "range": addr_range,
            "perms": perms,
            "entropy": ent,
            "matches": []
        }

        for m in matches:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            m_entry = {"rule": m.rule, "strings": []}

            for s in m.strings:
                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(Fore.CYAN +
                          f"\n    String {s.identifier}: offset=0x{abs_off:x} len={mlen}")

                    hex_dump_highlight(region, start, off, mlen)

                    # Disassembly
                    exe = psutil.Process(pid).exe()
                    arch = detect_arch(exe)
                    md = get_disassembler(arch)

                    ctx_start = max(0, off - 64)
                    ctx_end = min(len(region), off + mlen + 64)
                    code = region[ctx_start:ctx_end]

                    print("\n    Disassembly:")
                    disasm_lines = []
                    try:
                        for ins in md.disasm(code, start + ctx_start):
                            hi = (start + off <= ins.address < start + off + mlen)
                            prefix = ">>" if hi else "  "
                            c = Fore.RED if hi else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print(c + "      " + line)
                            disasm_lines.append(line)
                    except:
                        print("      <failed disassembly>")
                        disasm_lines.append("<failed>")

                    # Dump region
                    if dump_dir:
                        outdir = os.path.join(dump_dir, f"pid_{pid}")
                        os.makedirs(outdir, exist_ok=True)
                        p = os.path.join(outdir, f"{addr_range.replace('-', '_')}.bin")
                        with open(p, "wb") as f:
                            f.write(region)
                        print(Fore.GREEN + f"    Dumped region → {p}")

                    # Add to JSON
                    m_entry["strings"].append({
                        "identifier": s.identifier,
                        "offset": abs_off,
                        "length": mlen,
                        "disassembly": disasm_lines
                    })

            reg_entry["matches"].append(m_entry)

        proc_report_regions.append(reg_entry)

    report_obj["regions"] = proc_report_regions



# ======================================================================
# Main scanning
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Hybrid YARA Memory Scanner v5.6 (fixed)")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--max-read", type=int, default=512*1024*1024)  # FULL READ
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-fd-scan", action="store_true")
    parser.add_argument("--json-report", default="report.json")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    pids = [p.pid for p in psutil.process_iter()]
    if SELF_PID in pids:
        pids.remove(SELF_PID)

    print(Fore.CYAN + "\n[*] Phase 1 — YARA native PID scan (threaded)")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    matched = {}

    def do_scan(pid):
        try:
            r = rules.match(pid=pid)
            return pid, r
        except:
            return pid, []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(do_scan, pid): pid for pid in pids}
        for f in as_completed(futs):
            pid, res = f.result()
            if res:
                proc = psutil.Process(pid)
                exe = proc.exe()
                cmd = " ".join(proc.cmdline())
                sha = compute_sha256(exe)

                print(Fore.GREEN +
                      f"[+] Match in PID {pid} | Name: {proc.name()} | EXE: {exe}\n"
                      f"    CMD: {cmd}\n"
                      f"    SHA256: {sha}\n"
                      f"    Rules: {[m.rule for m in res]}\n")
                matched[pid] = res

    print(Fore.CYAN + f"\n[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # JSON output
    report = {"timestamp": datetime.utcnow().isoformat(), "processes": []}

    # ----------------------------------------------------
    # PHASE 2
    # ----------------------------------------------------
    for pid in matched:
        proc = psutil.Process(pid)
        exe = proc.exe()
        cmd = " ".join(proc.cmdline())
        sha = compute_sha256(exe)

        print(Fore.CYAN + f"\n==================== PID {pid} ====================")
        print(Fore.YELLOW + "Process Info:")
        print(f"  PID    : {pid}")
        print(f"  Name   : {proc.name()}")
        print(f"  EXE    : {exe}")
        print(f"  CMD    : {cmd}")
        print(f"  SHA256 : {sha}")

        proc_node = {
            "pid": pid,
            "name": proc.name(),
            "exe": exe,
            "cmd": cmd,
            "sha256": sha,
            "regions": []
        }

        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, proc_node)
        report["processes"].append(proc_node)

        print(Fore.CYAN + "\n====================================================\n")

    with open(args.json_report, "w") as f:
        json.dump(report, f, indent=2)

    print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
    print(Fore.GREEN + "[*] DONE.\n")


if __name__ == "__main__":
    main()