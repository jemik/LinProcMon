#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — FIXED + FILE SCAN

Modes:

1) Process mode (default)
   - Phase 1: YARA native PID scan (rules.match(pid=pid)), threaded
   - Phase 2: For each matched PID:
       * Enumerate /proc/<pid>/maps
       * Read memory regions
       * Run YARA on each region
       * Print:
           - Region match line
           - Entropy
           - Hex dump with highlighted match
           - Capstone disassembly with highlighted instructions
       * Save full details into JSON (regions[*].matches[*].strings[*])

2) File/dir mode (enabled with --scan-path PATH)
   - If PATH is a file: scan that file
   - If PATH is a directory: recursively scan all files
   - For each file with a match:
       * Treat whole file like a single region
       * Output format mirrors Phase-2 region output:
           - "File match at <path>"
           - Entropy, hex dump, disasm, etc.
       * Stored in JSON under report["matches"] with type="file"

Common:
   - YARA meta is included in JSON for every rule match ("meta" field).
   - Progress bar for Phase 1 process scan.
   - Scanner avoids scanning itself.
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

from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, Back, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

# ======================================================================
# Utility
# ======================================================================

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def compute_sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def detect_arch(exe: str) -> str:
    """
    Very small ELF-based arch detector.
    Falls back to x86_64 if anything fails.
    """
    try:
        with open(exe, "rb") as f:
            hdr = f.read(0x40)
    except Exception:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64-bit
        if e_machine == 0x3E:
            return "x86_64"
        if e_machine == 0xB7:
            return "arm64"
    elif ei_class == 1:  # 32-bit
        if e_machine == 0x03:
            return "x86"
        if e_machine == 0x28:
            return "arm"

    return "x86_64"

def get_disassembler(arch: str):
    if arch == "x86_64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

def hex_dump_highlight(data: bytes, base: int, off: int, length: int, ctx: int = 256):
    """
    Print a hex dump with the matched range highlighted in red.
    base  = virtual base address
    off   = match offset inside data
    length= match length
    ctx   = total context bytes (around match)
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

def print_progress(current: int, total: int, width: int = 70):
    """
    Simple text progress bar for Phase 1 PID scan.
    """
    if total <= 0:
        total = 1
    ratio = current / total
    filled = int(ratio * width)
    bar = "+" * filled + "-" * (width - filled)
    msg = f"\rScanning processes | {current}/{total} [{bar}]"
    print(msg, end="", flush=True)

# ======================================================================
# Deep scan memory maps (Phase 2)
# ======================================================================

def deep_scan_memory(pid: int, rules, max_read: int, dump_dir: str, json_proc: dict):
    """
    For a matched PID:
      - Walk /proc/<pid>/maps
      - Read each readable region (up to max_read)
      - Run YARA on the region
      - Print region/entropy/hex dump/disasm exactly as in v5.1
      - Append full details into json_proc["regions"]
    """

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            maps = f.read().splitlines()
    except Exception:
        print(Fore.RED + "Could not read maps")
        return

    # Try to figure out arch once per PID
    try:
        exe = psutil.Process(pid).exe()
        arch = detect_arch(exe)
    except Exception:
        arch = "x86_64"
    md = get_disassembler(arch)

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

        # Read full region (or up to max_read)
        try:
            with open(f"/proc/{pid}/mem", "rb", 0) as f:
                f.seek(start)
                region = f.read(min(size, max_read))
        except Exception:
            continue

        if not region:
            continue

        # YARA deep match
        try:
            mres = rules.match(data=region)
        except Exception as ex:
            print(Fore.RED + f"YARA error in region {addr}: {ex}")
            continue

        if not mres:
            continue

        ent = shannon_entropy(region)

        # Terminal output
        print(Fore.GREEN + f"\n  [+] Region match at {addr} perms={perms}")
        print(f"      Entropy: {ent:.3f}")

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
                "meta": getattr(m, "meta", {}),
                "strings": []
            }

            for st in m.strings:
                for inst in st.instances:
                    off  = inst.offset
                    mdat = inst.matched_data
                    mlen = len(mdat)
                    abs_addr = start + off

                    print(
                        Fore.CYAN +
                        f"\n    String {st.identifier}: offset=0x{abs_addr:x} len={mlen}"
                    )
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
            except Exception as ex:
                print(Fore.RED + f"    Failed to dump region: {ex}")

# ======================================================================
# File / directory scan mode
# ======================================================================

def walk_files(root_path: str):
    """
    Yield full file paths.
    - If root_path is a file: yield it once.
    - If it's a directory: recursively yield all files.
    """
    if os.path.isfile(root_path):
        yield root_path
    elif os.path.isdir(root_path):
        for dirpath, _, filenames in os.walk(root_path):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                yield full
    else:
        return

def scan_files_mode(scan_path: str, rules, max_read: int, dump_dir: str, report: dict):
    """
    File/dir scan mode:
      - No process scanning
      - For each file:
          * Read up to max_read
          * Run YARA
          * If matches:
              - Print "File match" block with entropy/hex/disasm
              - Append into report["matches"] as type="file"
    """
    files = list(walk_files(scan_path))
    if not files:
        print(Fore.RED + f"[!] No files found for path: {scan_path}")
        return

    print(Fore.CYAN + f"[*] File/dir scan mode enabled. Files to scan: {len(files)}")

    for path in files:
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                data = f.read(min(size, max_read))
        except Exception as e:
            print(Fore.RED + f"[!] Failed to read {path}: {e}")
            continue

        if not data:
            continue

        try:
            mres = rules.match(data=data)
        except Exception as e:
            print(Fore.RED + f"[!] YARA error on {path}: {e}")
            continue

        if not mres:
            continue

        ent = shannon_entropy(data)

        print(Fore.YELLOW + f"\n[*] Scanning file: {path}")
        print(Fore.GREEN + f"  [+] File match at {path}")
        print(f"      Size: {len(data)} bytes")
        print(f"      Entropy: {ent:.3f}")

        arch = detect_arch(path)
        md = get_disassembler(arch)

        file_json = {
            "type": "file",
            "file": path,
            "sha256": compute_sha256(path),
            "size": len(data),
            "entropy": ent,
            "regions": []
        }

        # Treat whole file as a single "region" from 0..len(data)
        region_out = {
            "address": f"0x0-0x{len(data):x}",
            "perms": "r--",
            "entropy": ent,
            "matches": []
        }

        for m in mres:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            mjson = {
                "rule": m.rule,
                "meta": getattr(m, "meta", {}),
                "strings": []
            }

            for st in m.strings:
                for inst in st.instances:
                    off  = inst.offset
                    mdat = inst.matched_data
                    mlen = len(mdat)
                    abs_off = off

                    print(
                        Fore.CYAN +
                        f"\n    String {st.identifier}: offset=0x{abs_off:x} len={mlen}"
                    )
                    hex_dump_highlight(data, 0, off, mlen)

                    snippet_info = {
                        "identifier": st.identifier,
                        "offset": abs_off,
                        "length": mlen,
                        "hex": mdat.hex(),
                        "disasm": []
                    }

                    cstart = max(0, off - 64)
                    cend   = min(len(data), off + mlen + 64)
                    code   = data[cstart:cend]

                    print("\n    Disassembly:")
                    try:
                        for ins in md.disasm(code, cstart):
                            highlighted = (off <= ins.address < off + mlen)
                            prefix = ">>" if highlighted else "  "
                            col = Fore.RED if highlighted else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print(col + "      " + line)
                            snippet_info["disasm"].append(line)
                    except Exception:
                        print("      <failed disassembly>")

                    mjson["strings"].append(snippet_info)

            region_out["matches"].append(mjson)

        file_json["regions"].append(region_out)

        if dump_dir:
            try:
                os.makedirs(dump_dir, exist_ok=True)
                base_name = os.path.basename(path)
                out_path = os.path.join(dump_dir, f"{base_name}.bin")
                with open(out_path, "wb") as f:
                    f.write(data)
                print(Fore.GREEN + f"    Dumped file bytes to: {out_path}")
            except Exception as e:
                print(Fore.RED + f"    Failed to dump file: {e}")

        report["matches"].append(file_json)

# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="YARA Memory Scanner v5.6 FIXED + FILE SCAN")

    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--threads", type=int, default=4, help="Threads for PID scan")
    parser.add_argument("--max-read", type=int, default=256*1024*1024,
                        help="Max bytes to read per region/file")
    parser.add_argument("--dump-dir", help="Dump matched regions/files to this directory")
    parser.add_argument("--json-report", default="report.json",
                        help="JSON report output path")
    parser.add_argument("--scan-path",
                        help="If set, scan this file or directory (recursive) instead of processes")

    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # JSON report skeleton
    report = {
        "generated": str(datetime.datetime.now()),
        "matches": []
    }

    # ------------------------------------------------------------------
    # MODE 1: File/Dir scan (disables process scanning)
    # ------------------------------------------------------------------
    if args.scan_path:
        scan_files_mode(args.scan_path, rules, args.max_read, args.dump_dir, report)
        with open(args.json_report, "w") as f:
            json.dump(report, f, indent=2)
        print(Fore.GREEN + f"\n[*] JSON report written → {args.json_report}")
        print(Fore.GREEN + "\n[*] DONE.\n")
        return

    # ------------------------------------------------------------------
    # MODE 2: Process scan (original behavior)
    # ------------------------------------------------------------------

    selfpid = os.getpid()
    parentpid = os.getppid()

    print(Fore.CYAN + "\n[*] Enumerating processes...")
    pids = [p.pid for p in psutil.process_iter() if p.pid not in (selfpid, parentpid)]
    print(f"[*] {len(pids)} processes found (excluding scanner + parent)\n")

    print(Fore.CYAN + "[*] Phase 1 — YARA native PID scan (threaded)")

    matched = {}

    def scan_one(pid):
        try:
            res = rules.match(pid=pid)
            return pid, res
        except Exception:
            return pid, []

    total = len(pids)
    done = 0

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
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
                    exe = cmd = name = "<unknown>"
                    sha = "<unknown>"

                rules_str = [m.rule for m in res]

                # End progress line before printing match
                print()
                # MATCHED line colored red (full header line)
                print(
                    Fore.RED +
                    f"[+] MATCHED PID {pid} | Name: {name} | EXE: {exe}" +
                    Style.RESET_ALL
                )
                print(f"    CMD: {cmd}")
                print(f"    SHA256: {sha}")
                print(f"    Rules: {rules_str}\n")

        # Finish progress bar line
        print()

    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # Phase 2 — deep memory scan per matched PID
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
            "type": "process",
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