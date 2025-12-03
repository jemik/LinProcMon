#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — FIXED + ENHANCED

Base behavior (from your last known-good v5.6):

PHASE 1:
    - YARA native PID scan (rules.match(pid=pid))
    - Threaded
    - Skips own PID
    - Prints per-match:
        [+] Match in PID ... | Name | EXE
            CMD
            SHA256
            Rules

PHASE 2 (for each matched PID):
    - Enumerate readable regions from /proc/<pid>/maps
    - Read region bytes from /proc/<pid>/mem
    - Re-scan each region with YARA
    - For each match:
        * "Region match at <addr> perms=<perms>"
        * "Entropy: <value>"
        * Per rule:
            Rule: <name>
            String <id>: offset=0x... len=...
            Hex dump @ ...
            Disassembly: (highlighted around the match)
    - Optional dump of full region to disk

JSON REPORT:
    - For each matched PID:
        pid, exe, cmd, sha256
        regions[]:
            address, perms, entropy
            matches[]:
                rule, meta (YARA rule.meta),
                strings[]:
                    identifier, offset, length, hex, disasm[]

ENHANCEMENTS ADDED NOW:
    ✔ Progress bar in Phase 1 (threaded PID scan)
    ✔ FD scanning (optional, controlled by --no-fd-scan)
      - Prints FD matches to terminal
      - Adds "fds" section in JSON
    ✔ YARA rule meta added into JSON (per rule)

No changes to the deep output format you liked.
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
from colorama import Fore, Style, init as colorama_init
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
    Print hex dump with the matched range highlighted in red, identical to
    your v5.1/v5.6 behavior.
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

def deep_scan_memory(pid: int, rules, max_read: int, dump_dir: str, json_proc: dict):
    """
    Deep scan of /proc/<pid>/maps + /proc/<pid>/mem.
    Console behavior matches your previous working versions.
    JSON is enriched with full match content (including rule.meta).
    """
    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            maps = f.read().splitlines()
    except Exception as ex:
        print(Fore.RED + f"Could not read maps for PID {pid}: {ex}")
        return

    try:
        exe_path = psutil.Process(pid).exe()
    except Exception:
        exe_path = "<unknown>"

    arch = detect_arch(exe_path)
    md = get_disassembler(arch)

    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr = parts[0]
        perms = parts[1]

        # Only readable regions
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
            with open(f"/proc/{pid}/mem", "rb", 0) as memf:
                memf.seek(start)
                region = memf.read(min(size, max_read))
        except Exception:
            continue

        if not region:
            continue

        # YARA deep match on this region
        try:
            mres = rules.match(data=region)
        except Exception as ex:
            print(Fore.RED + f"YARA error in region {addr}: {ex}")
            continue

        if not mres:
            continue

        # Terminal output (region header)
        ent = shannon_entropy(region)
        print(Fore.GREEN + f"\n  [+] Region match at {addr} perms={perms}")
        print(f"      Entropy: {ent:.3f}")

        # JSON region entry
        region_out = {
            "address": addr,
            "perms": perms,
            "entropy": ent,
            "matches": []
        }

        # Per-rule output
        for m in mres:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            rule_meta = {}
            try:
                # m.meta is a dict-like object in yara-python 4.5.4
                rule_meta = dict(m.meta)
            except Exception:
                rule_meta = {}

            mjson = {
                "rule": m.rule,
                "meta": rule_meta,
                "strings": []
            }

            # Per string / per instance output
            for st in m.strings:
                ident = st.identifier
                for inst in st.instances:
                    off  = inst.offset
                    mdat = inst.matched_data
                    mlen = len(mdat)
                    abs_addr = start + off

                    print(
                        Fore.CYAN +
                        f"\n    String {ident}: offset=0x{abs_addr:x} len={mlen}"
                    )
                    hex_dump_highlight(region, start, off, mlen)

                    # JSON snippet info
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

        # Dump full region if requested
        if dump_dir:
            try:
                outdir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(outdir, exist_ok=True)
                p = os.path.join(outdir, f"region_{addr.replace('-','_')}.bin")
                with open(p, "wb") as f:
                    f.write(region)
                print(Fore.GREEN + f"    Dumped region to: {p}")
            except Exception as ex:
                print(Fore.RED + f"    Failed dumping region {addr}: {ex}")


# ======================================================================
# FD (memfd etc.) scan
# ======================================================================

def scan_fds(pid: int, rules, max_read: int, dump_dir: str, json_proc: dict):
    """
    Scan /proc/<pid>/fd for YARA matches.

    - Skips sockets / pipes
    - Prints matches to terminal
    - Adds 'fds' section into JSON report
    """
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

    fds_json = []

    for fd in os.listdir(fd_path):
        full = os.path.join(fd_path, fd)
        try:
            target = os.readlink(full)
        except Exception:
            continue

        if target.startswith("socket:") or target.startswith("pipe:"):
            continue

        try:
            with open(full, "rb") as f:
                data = f.read(max_read)
        except Exception:
            continue

        if not data:
            continue

        try:
            matches = rules.match(data=data)
        except Exception:
            continue

        if not matches:
            continue

        print(Fore.GREEN + f"  [+] FD match: {full} → {target}")
        rule_names = [m.rule for m in matches]
        print(Fore.MAGENTA + f"    Rules: {rule_names}")

        fd_entry = {
            "fd": fd,
            "target": target,
            "rules": rule_names,
            "rule_meta": []
        }

        # Add meta per rule to JSON
        for m in matches:
            try:
                meta = dict(m.meta)
            except Exception:
                meta = {}
            fd_entry["rule_meta"].append({
                "rule": m.rule,
                "meta": meta
            })

        # Optionally dump FD content
        if dump_dir:
            try:
                outdir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(outdir, exist_ok=True)
                p = os.path.join(outdir, f"fd_{fd}.bin")
                with open(p, "wb") as f:
                    f.write(data)
                print(Fore.GREEN + f"    Dumped FD: {p}")
                fd_entry["dump_path"] = p
            except Exception as ex:
                print(Fore.RED + f"    Failed dumping FD {fd}: {ex}")

        fds_json.append(fd_entry)

    if fds_json:
        json_proc["fds"] = fds_json


# ======================================================================
# Progress bar for Phase 1
# ======================================================================

def print_progress(done: int, total: int, width: int = 60):
    if total <= 0:
        return
    ratio = done / total
    ratio = 1.0 if ratio > 1.0 else ratio
    filled = int(width * ratio)
    bar = "+" * filled + "-" * (width - filled)
    sys.stdout.write(
        f"\rScanning processes | {done}/{total} [{bar}]"
    )
    sys.stdout.flush()
    if done == total:
        print()  # newline at the end


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="YARA Memory Scanner v5.6 FIXED+ENHANCED")
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--threads", type=int, default=4, help="Threads for Phase 1 PID scan")
    parser.add_argument("--max-read", type=int, default=256 * 1024 * 1024,
                        help="Max bytes to read per region/FD")
    parser.add_argument("--dump-dir", help="Dump directory for matched regions/FDs")
    parser.add_argument("--no-fd-scan", action="store_true",
                        help="Disable scanning /proc/<pid>/fd (faster)")
    parser.add_argument("--json-report", default="report.json",
                        help="Write JSON report to this file (default: report.json)")

    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    selfpid = os.getpid()
    parentpid = os.getppid()

    print(Fore.CYAN + "\n[*] Enumerating processes...")
    all_pids = []
    for p in psutil.process_iter():
        try:
            pid = p.pid
        except Exception:
            continue
        if pid in (selfpid, parentpid):
            continue
        all_pids.append(pid)

    total = len(all_pids)
    print(f"[*] {total} processes found (excluding scanner + parent)\n")

    # --------------------------------------------------------------
    # PHASE 1 — threaded native PID scanning with progress bar
    # --------------------------------------------------------------
    print(Fore.CYAN + "[*] Phase 1 — YARA native PID scan (threaded)")

    matched = {}

    def scan_one(pid):
        try:
            res = rules.match(pid=pid)
            return pid, res
        except Exception:
            return pid, []

    done = 0
    print_progress(done, total)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_one, pid): pid for pid in all_pids}
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
                    exe = cmd = name = sha = "<unknown>"

                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name: {name} | EXE: {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {[m.rule for m in res]}\n"
                )

    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # --------------------------------------------------------------
    # JSON base structure
    # --------------------------------------------------------------
    report = {
        "generated": str(datetime.datetime.now()),
        "rule_file": args.rule,
        "matches": []
    }

    # --------------------------------------------------------------
    # PHASE 2 — deep forensics per matched PID
    # --------------------------------------------------------------
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

        # Deep memory scanning with full region/entropy/hex/disasm output
        deep_scan_memory(pid, rules, args.max_read, args.dump_dir, json_proc)

        # FD scanning (optional) — also prints + JSON
        if not args.no_fd_scan:
            scan_fds(pid, rules, args.max_read, args.dump_dir, json_proc)
        else:
            print(Fore.YELLOW + "Skipping FD scan (--no-fd-scan enabled)")

        report["matches"].append(json_proc)

        print(Fore.CYAN + "\n====================================================\n")

    # --------------------------------------------------------------
    # Write JSON report
    # --------------------------------------------------------------
    try:
        with open(args.json_report, "w") as f:
            json.dump(report, f, indent=2)
        print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
    except Exception as ex:
        print(Fore.RED + f"[!] Failed writing JSON report: {ex}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()