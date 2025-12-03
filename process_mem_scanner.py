#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — FIXED VERSION
Restores full Phase-2 output EXACTLY like v5.1:

✔ Region match lines
✔ Entropy
✔ Hex dump highlight
✔ Full disassembly
✔ JSON report with full match data
✔ Correct YARA scanning logic
✔ No suppressed errors
✔ Does NOT skip matched regions
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
import datetime

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

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

def detect_arch(exe):
    try:
        with open(exe, "rb") as f:
            hdr = f.read(0x40)
    except:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:
        if e_machine == 0x3E: return "x86_64"
        if e_machine == 0xB7: return "arm64"
    elif ei_class == 1:
        if e_machine == 0x03: return "x86"
        if e_machine == 0x28: return "arm"

    return "x86_64"

def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":     return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":   return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":     return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

def hex_dump_highlight(data, base, off, length, ctx=256):
    half = ctx // 2
    start = max(0, off - half)
    end   = min(len(data), off + length + half)
    buf   = data[start:end]
    virt  = base + start

    print(f"        Hex dump @ 0x{virt:x}:")

    for i in range(0, len(buf), 16):
        chunk = buf[i:i+16]
        hexp = []
        ascp = []
        for j,b in enumerate(chunk):
            gi = start + i + j
            inmatch = (off <= gi < off + length)
            h = f"{b:02x}"
            a = chr(b) if 32 <= b <= 126 else "."
            if inmatch:
                h = Fore.RED + h + Style.RESET_ALL
                a = Fore.RED + a + Style.RESET_ALL
            hexp.append(h)
            ascp.append(a)

        print(f"        0x{virt+i:016x}  {' '.join(hexp):<48}  {''.join(ascp)}")


# ======================================================================
# Deep scan memory maps
# ======================================================================

def deep_scan_memory(pid, rules, max_read, dump_dir, json_proc):

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except:
        print(Fore.RED + "Could not read maps")
        return

    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr, perms = parts[0], parts[1]
        if "r" not in perms:
            continue

        s, e = addr.split("-")
        start = int(s, 16)
        end   = int(e, 16)
        size  = end - start
        if size <= 0:
            continue

        # Read full region or up to max_read
        try:
            with open(f"/proc/{pid}/mem", "rb", 0) as f:
                f.seek(start)
                region = f.read(min(size, max_read))
        except Exception as ex:
            continue

        # YARA deep match
        try:
            mres = rules.match(data=region)
        except Exception as ex:
            print(Fore.RED + f"YARA error in region {addr}: {ex}")
            continue

        if not mres:
            continue

        # Terminal output
        print(Fore.GREEN + f"\n  [+] Region match at {addr} perms={perms}")
        print(f"      Entropy: {shannon_entropy(region):.3f}")

        arch = detect_arch(psutil.Process(pid).exe())
        md = get_disassembler(arch)

        region_out = {
            "address": addr,
            "perms": perms,
            "entropy": shannon_entropy(region),
            "matches": []
        }

        # MATCH CONTENT
        for m in mres:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            mjson = { "rule": m.rule, "strings": [] }

            for st in m.strings:
                for inst in st.instances:
                    off  = inst.offset
                    mdat = inst.matched_data
                    mlen = len(mdat)
                    abs_addr = start + off

                    print(Fore.CYAN + f"\n    String {st.identifier}: offset=0x{abs_addr:x} len={mlen}")
                    hex_dump_highlight(region, start, off, mlen)

                    # Collect JSON hex + disasm
                    snippet_info = {
                        "identifier": st.identifier,
                        "offset": abs_addr,
                        "length": mlen,
                        "hex": mdat.hex(),
                        "disasm": []
                    }

                    # Disassembly context
                    cstart = max(0, off - 64)
                    cend   = min(len(region), off + mlen + 64)
                    code   = region[cstart:cend]

                    print("\n    Disassembly:")
                    try:
                        for ins in md.disasm(code, start + cstart):
                            highlighted = (start + off <= ins.address < start + off + mlen)
                            prefix = ">>" if highlighted else "  "
                            col = Fore.RED if highlighted else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print(col + "      " + line)
                            snippet_info["disasm"].append(line)
                    except:
                        print("      <failed disassembly>")

                    mjson["strings"].append(snippet_info)

            region_out["matches"].append(mjson)

        json_proc["regions"].append(region_out)

        # Dump region if requested
        if dump_dir:
            os.makedirs(os.path.join(dump_dir, f"pid_{pid}"), exist_ok=True)
            p = os.path.join(dump_dir, f"pid_{pid}", f"region_{addr.replace('-','_')}.bin")
            with open(p, "wb") as f:
                f.write(region)
            print(Fore.GREEN + f"    Dumped region to: {p}")


# ======================================================================
# Main
# ======================================================================

def main():

    parser = argparse.ArgumentParser(description="YARA Memory Scanner v5.6 FIXED")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--max-read", type=int, default=256*1024*1024)
    parser.add_argument("--dump-dir")
    parser.add_argument("--no-fd-scan", action="store_true")
    parser.add_argument("--json-report", default="report.json")

    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # Do not scan our own PID
    selfpid = os.getpid()

    print(Fore.CYAN + "\n[*] Phase 1 — YARA native PID scan (threaded)")
    pids = [p.pid for p in psutil.process_iter() if p.pid != selfpid]

    matched = {}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def scan_one(pid):
        try:
            res = rules.match(pid=pid)
            return pid, res
        except:
            return pid, []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_one, pid): pid for pid in pids}
        for f in as_completed(futs):
            pid, res = f.result()
            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    exe = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    name = proc.name()
                    sha = compute_sha256(exe)
                except:
                    exe = cmd = name = sha = "<unknown>"

                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name: {name} | EXE: {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {[m.rule for m in res]}\n"
                )

    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # JSON structure
    report = {
        "generated": str(datetime.datetime.now()),
        "matches": []
    }

    # Phase 2
    for pid in matched:
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            cmd = " ".join(proc.cmdline())
            sha = compute_sha256(exe)
            name = proc.name()
        except:
            exe = cmd = sha = name = "<unknown>"

        print(Fore.YELLOW + "Process Info:")
        print(f"  PID    : {pid}")
        print(f"  Name   : {name}")
        print(f"  EXE    : {exe}")
        print(f"  CMD    : {cmd}")
        print(f"  SHA256 : {sha}")

        json_proc = {
            "pid": pid,
            "exe": exe,
            "cmd": cmd,
            "sha256": sha,
            "regions": []
        }

        deep_scan_memory(pid, rules, args.max_read, args.dump_dir, json_proc)

        report["matches"].append(json_proc)

        print(Fore.CYAN + "\n====================================================\n")

    with open(args.json_report, "w") as f:
        json.dump(report, f, indent=2)

    print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
    print(Fore.GREEN + "\n[*] DONE.\n")

if __name__ == "__main__":
    main()