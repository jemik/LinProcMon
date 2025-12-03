#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — FIXED VERSION + UX TWEAKS

- Phase 1:
    * YARA native PID scan (rules.match(pid=pid)) using threads
    * Progress bar: "Scanning processes | N/Total [++++-----]"
    * MATCHED lines printed on their own line (no overlap with progress bar)
    * MATCHED highlighted with red background

- Phase 2:
    * Enumerate readable regions from /proc/<pid>/maps
    * Re-scan each region with YARA to get offsets
    * Hex dump around matched bytes
    * Capstone disassembly
    * Full console output like v5.1
    * JSON report with full match data (regions, strings, disasm)

NOTE:
This is Linux-only (uses /proc, YARA pid=, etc.)
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

from colorama import Fore, Back, Style, init as colorama_init
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
    except Exception:
        return None

def detect_arch(exe):
    try:
        with open(exe, "rb") as f:
            hdr = f.read(0x40)
    except Exception:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:
        if e_machine == 0x3E:
            return "x86_64"
        if e_machine == 0xB7:
            return "arm64"
    elif ei_class == 1:
        if e_machine == 0x03:
            return "x86"
        if e_machine == 0x28:
            return "arm"

    return "x86_64"

def get_disassembler(arch):
    if arch == "x86_64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

def hex_dump_highlight(data, base, off, length, ctx=256):
    """
    Print a contextual hex dump with the matched bytes highlighted in red.
    """
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
        for j, b in enumerate(chunk):
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
    """
    Full Phase-2 deep scan:
      - /proc/<pid>/maps
      - Read memory from /proc/<pid>/mem
      - YARA match per region
      - Print region + entropy + hex dump + disasm
      - Append full info into json_proc["regions"]
    """

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception:
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
        except Exception:
            continue

        # YARA deep match
        try:
            mres = rules.match(data=region)
        except Exception as ex:
            print(Fore.RED + f"YARA error in region {addr}: {ex}")
            continue

        if not mres:
            continue

        # Terminal output (same style as your original v5.1)
        print(Fore.GREEN + f"\n  [+] Region match at {addr} perms={perms}")
        ent = shannon_entropy(region)
        print(f"      Entropy: {ent:.3f}")

        # Disassembler for this PID
        try:
            arch = detect_arch(psutil.Process(pid).exe())
        except Exception:
            arch = "x86_64"
        md = get_disassembler(arch)

        region_out = {
            "address": addr,
            "perms": perms,
            "entropy": ent,
            "matches": []
        }

        # MATCH CONTENT
        for m in mres:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            mjson = {
                "rule": m.rule,
                "meta": dict(getattr(m, "meta", {})),
                "strings": []
            }

            for st in m.strings:
                ident = st.identifier
                for inst in st.instances:
                    off  = inst.offset
                    mdat = inst.matched_data
                    mlen = len(mdat)
                    abs_addr = start + off

                    print(Fore.CYAN + f"\n    String {ident}: offset=0x{abs_addr:x} len={mlen}")
                    hex_dump_highlight(region, start, off, mlen)

                    snippet_info = {
                        "identifier": ident,
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
                    except Exception:
                        print("      <failed disassembly>")

                    mjson["strings"].append(snippet_info)

            region_out["matches"].append(mjson)

        json_proc["regions"].append(region_out)

        # Dump region if requested
        if dump_dir:
            try:
                outdir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(outdir, exist_ok=True)
                p = os.path.join(outdir, f"region_{addr.replace('-','_')}.bin")
                with open(p, "wb") as f:
                    f.write(region)
                print(Fore.GREEN + f"    Dumped region to: {p}")
            except Exception as e:
                print(Fore.RED + f"    Failed dumping region: {e}")


# ======================================================================
# Simple progress bar for Phase 1
# ======================================================================

def print_progress(done, total, width=70):
    if total <= 0:
        return
    ratio = done / total
    filled = int(width * ratio)
    bar = "[" + "+" * filled + "-" * (width - filled) + "]"
    # Carriage-return style progress (no newline)
    print(f"\rScanning processes | {done}/{total} {bar}", end="", flush=True)


# ======================================================================
# Main
# ======================================================================

def main():

    parser = argparse.ArgumentParser(description="YARA Memory Scanner v5.6 FIXED + UX")
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--threads", type=int, default=4, help="Phase 1 thread count")
    parser.add_argument("--max-read", type=int, default=256*1024*1024,
                        help="Max bytes to read per region")
    parser.add_argument("--dump-dir", help="Directory for region dumps")
    parser.add_argument("--no-fd-scan", action="store_true",  # kept for CLI compatibility
                        help="(placeholder, FD scan not implemented in this v5.6)")
    parser.add_argument("--json-report", default="report.json",
                        help="Path to JSON report output")

    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # Do not scan our own PID
    selfpid = os.getpid()

    print(Fore.CYAN + "\n[*] Enumerating processes...")
    all_procs = [p.pid for p in psutil.process_iter() if p.pid != selfpid]
    total = len(all_procs)
    print(f"[*] {total} processes found (excluding scanner)\n")

    # --------------------------------------------------------------
    # PHASE 1 — threaded native PID scanning + progress bar
    # --------------------------------------------------------------
    print(Fore.CYAN + "[*] Phase 1 — YARA native PID scan (threaded)")

    matched = {}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def scan_one(pid):
        try:
            res = rules.match(pid=pid)
            return pid, res
        except Exception:
            return pid, []

    done = 0
    if total > 0:
        print_progress(done, total)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_one, pid): pid for pid in all_procs}
        for f in as_completed(futs):
            pid, res = f.result()
            done += 1
            print_progress(done, total)

            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    exe = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    name = proc.name()
                    sha = compute_sha256(exe)
                except Exception:
                    exe = cmd = name = sha = "<unknown>"

                # Finish the progress bar line before printing match
                print()  # newline after progress bar

                # MATCHED line with red background; rest default color
                rules_str = [m.rule for m in res]
                print(
                    f"[+] {Back.RED}MATCHED{Style.RESET_ALL} "
                    f"PID {pid} | Name: {name} | EXE: {exe}"
                )
                print(f"    CMD: {cmd}")
                print(f"    SHA256: {sha}")
                print(f"    Rules: {rules_str}\n")

                # Re-print progress bar (optional; comment out if noisy)
                if done < total:
                    print_progress(done, total)

    # Make sure the progress bar line ends cleanly
    if total > 0:
        print()

    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # -----------------------------------------------------------------
    # JSON structure for report
    # -----------------------------------------------------------------
    report = {
        "generated": str(datetime.datetime.now()),
        "rule_file": args.rule,
        "matches": []
    }

    # -----------------------------------------------------------------
    # PHASE 2 — deep forensics per matched PID
    # -----------------------------------------------------------------
    for pid in matched:
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            cmd = " ".join(proc.cmdline())
            sha = compute_sha256(exe)
            name = proc.name()
        except Exception:
            exe = cmd = sha = name = "<unknown>"

        print(Fore.YELLOW + "Process Info:")
        print(f"  PID    : {pid}")
        print(f"  Name   : {name}")
        print(f"  EXE    : {exe}")
        print(f"  CMD    : {cmd}")
        print(f"  SHA256 : {sha}")

        json_proc = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmd": cmd,
            "sha256": sha,
            "regions": []
        }

        deep_scan_memory(pid, rules, args.max_read, args.dump_dir, json_proc)

        report["matches"].append(json_proc)

        print(Fore.CYAN + "\n====================================================\n")

    # -----------------------------------------------------------------
    # Write JSON report
    # -----------------------------------------------------------------
    try:
        with open(args.json_report, "w") as f:
            json.dump(report, f, indent=2)
        print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
    except Exception as e:
        print(Fore.RED + f"[*] Failed to write JSON report: {e}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()