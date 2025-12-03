#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — Hybrid Scanner (JSON + progress + FD)

PHASE 1:
    - YARA native process scan (rules.match(pid=pid)) in threads
    - Skips own PID and parent PID
    - Shows progress bar and per-PID match info

PHASE 2 (only for matched PIDs):
    - Enumerate readable regions from /proc/<pid>/maps
    - Re-scan each region with YARA to get offsets
    - Hex dump around matched bytes (256 bytes window)
    - Capstone disassembly
    - Injection indicator detection
    - memfd/file descriptor scanning (/proc/<pid>/fd)
    - (Optional) dump matched regions / fds

JSON REPORT:
    - Per-process:
        - PID, name, exe, cmdline, sha256
        - injection_indicators
        - regions:
            - address, perms, entropy
            - matches: rule, meta, string id, offsets, length
              hexdump (plain, no color), disassembly (plain)
            - dump_file (if any)
        - fds:
            - fd, target, rules, meta, dump_file
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import math
import datetime
import json

from colorama import Fore, Style, init as colorama_init
from capstone import *
from concurrent.futures import ThreadPoolExecutor, as_completed

colorama_init(autoreset=True)


# ======================================================================
# Utility
# ======================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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

    if ei_class == 2:
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
    if arch == "x86_64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":
        return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


def hex_dump_highlight(data, base, match_off, match_len, ctx=256):
    """
    Print colored hex dump and also return a plain list of strings for JSON.
    """
    half = ctx // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)

    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump @ 0x{snippet_base:x}:")
    plain_lines = []

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        hex_parts_colored = []
        ascii_parts_colored = []
        hex_parts_plain = []
        ascii_parts_plain = []

        for j, b in enumerate(line):
            gi = start + i + j
            in_range = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."
            if in_range:
                hx_c = Fore.RED + hx + Style.RESET_ALL
                ch_c = Fore.RED + ch + Style.RESET_ALL
            else:
                hx_c = hx
                ch_c = ch

            hex_parts_colored.append(hx_c)
            ascii_parts_colored.append(ch_c)
            hex_parts_plain.append(hx)
            ascii_parts_plain.append(ch)

        addr_str = f"        0x{snippet_base + i:016x}  "
        hex_str_plain = " ".join(hex_parts_plain)
        ascii_str_plain = "".join(ascii_parts_plain)
        hex_str_colored = " ".join(hex_parts_colored)
        ascii_str_colored = "".join(ascii_parts_colored)

        line_colored = f"{addr_str}{hex_str_colored:<48}  {ascii_str_colored}"
        line_plain = f"{addr_str}{hex_str_plain:<48}  {ascii_str_plain}"

        print(line_colored)
        plain_lines.append(line_plain)

    return plain_lines


# ======================================================================
# Indicators
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

    # RWX, memfd, anonymous exec
    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr, perms, _, _, inode = parts[:5]
                path = parts[5] if len(parts) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    indicators.append(f"RWX mapping: {addr} {perms}")
                if "x" in perms and inode == "0" and path in ("", "0"):
                    indicators.append(f"Anonymous exec region: {addr}")
                if "x" in perms and "memfd:" in path:
                    indicators.append(f"memfd executable: {addr} {path}")
    except Exception:
        pass

    # VmFlags (RW→RX)
    try:
        current = None
        with open(smaps_path, "r") as f:
            for line in f:
                if "-" in line and ":" not in line:
                    current = line.split()[0]
                if line.startswith("VmFlags:"):
                    fl = line.split(":")[1].strip().split()
                    if "ex" in fl and ("mr" in fl or "mw" in fl) and current:
                        indicators.append(f"VmFlags transition: {current}")
    except Exception:
        pass

    # deduplicate
    return list(dict.fromkeys(indicators))


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
# Deep Scan of Memory Regions
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, arch, disasm):
    """
    Deep scan memory maps for a given PID.

    Returns: list of region dicts for JSON report:
        [
          {
            "address": "...",
            "perms": "...",
            "entropy": float,
            "dump_file": optional str,
            "matches": [
               {
                 "rule": ...,
                 "meta": {...},
                 "string": ...,
                 "absolute_offset": "0x...",
                 "relative_offset": int,
                 "length": int,
                 "hexdump": [lines...],
                 "disassembly": [lines...]
               }, ...
            ]
          }, ...
        ]
    """
    maps_path = f"/proc/{pid}/maps"
    try:
        lines = open(maps_path).read().splitlines()
    except Exception:
        return []

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    regions_report = []

    md = disasm

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr_range, perms = parts[0], parts[1]

        # Only readable regions
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
        except Exception:
            continue

        if not matches:
            continue

        print(Fore.GREEN + f"\n  [+] Region match at {addr_range} perms={perms}")
        ent = shannon_entropy(region)
        print(f"      Entropy: {ent:.3f}")

        region_info = {
            "address": addr_range,
            "perms": perms,
            "entropy": ent,
            "dump_file": None,
            "matches": []
        }

        dumped = False

        for m in matches:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            # Safely stringify meta for JSON
            meta = {k: str(v) for k, v in m.meta.items()} if hasattr(m, "meta") else {}

            for s in m.strings:
                ident = s.identifier
                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(Fore.CYAN + f"\n    String {ident}: offset={hex(abs_off)} len={mlen}")
                    hexdump_plain = hex_dump_highlight(region, start, off, mlen)

                    # disassembly fragment around match
                    ctx_start = max(0, off - 64)
                    ctx_end = min(len(region), off + mlen + 64)
                    code = region[ctx_start:ctx_end]

                    print("\n    Disassembly:")
                    disasm_lines_plain = []
                    try:
                        for ins in md.disasm(code, start + ctx_start):
                            high = (start + off <= ins.address < start + off + mlen)
                            prefix = ">>" if high else "  "
                            line_plain = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            disasm_lines_plain.append(line_plain)
                            color = Fore.RED if high else ""
                            print(color + "      " + line_plain)
                    except Exception:
                        print("      <failed disassembly>")
                        disasm_lines_plain.append("<failed disassembly>")

                    # Dump region once if requested
                    if dump_dir and not dumped:
                        outdir = os.path.join(dump_dir, f"pid_{pid}")
                        os.makedirs(outdir, exist_ok=True)
                        path = os.path.join(outdir, f"region_{addr_range.replace('-', '_')}.bin")
                        try:
                            with open(path, "wb") as f:
                                f.write(region)
                            print(Fore.GREEN + f"    Dumped region to: {path}")
                            region_info["dump_file"] = path
                        except Exception as e:
                            print(Fore.RED + f"    [!] Failed to dump region: {e}")
                        dumped = True

                    match_entry = {
                        "rule": m.rule,
                        "meta": meta,
                        "string": ident,
                        "absolute_offset": hex(abs_off),
                        "relative_offset": off,
                        "length": mlen,
                        "hexdump": hexdump_plain,
                        "disassembly": disasm_lines_plain
                    }
                    region_info["matches"].append(match_entry)

        regions_report.append(region_info)

    return regions_report


# ======================================================================
# FD (memfd) scan
# ======================================================================

def scan_fds(pid, rules, dump_dir, max_read):
    """
    Scan /proc/<pid>/fd for YARA matches.

    Returns list of fd entries for JSON:
      [
        {
          "fd": "123",
          "target": "/memfd:whatever",
          "rules": [rule names],
          "meta": [ {meta dict per rule}, ... ],
          "dump_file": optional str
        }, ...
      ]
    """
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return []

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

    fd_report = []

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

        try:
            matches = rules.match(data=data)
        except Exception:
            continue

        if matches:
            print(Fore.GREEN + f"  [+] FD match: {full} → {target}")
            rule_names = [m.rule for m in matches]
            for m in matches:
                print(Fore.MAGENTA + f"    Rule: {m.rule}")

            fd_entry = {
                "fd": fd,
                "target": target,
                "rules": rule_names,
                "meta": [
                    {k: str(v) for k, v in m.meta.items()} if hasattr(m, "meta") else {}
                    for m in matches
                ],
                "dump_file": None
            }

            if dump_dir:
                out = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(out, exist_ok=True)
                p = os.path.join(out, f"fd_{fd}.bin")
                try:
                    with open(p, "wb") as f:
                        f.write(data)
                    print(Fore.GREEN + f"    Dumped FD: {p}")
                    fd_entry["dump_file"] = p
                except Exception as e:
                    print(Fore.RED + f"    [!] Failed dumping FD: {e}")

            fd_report.append(fd_entry)

    return fd_report


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid YARA Memory Scanner v5.6 (threaded + JSON)"
    )
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--dump-dir", help="Dump directory for matched regions/FDs")
    parser.add_argument("--max-read", type=int, default=5 * 1024 * 1024,
                        help="Max bytes to read per region/FD")
    parser.add_argument("--threads", type=int, default=4,
                        help="Number of threads for Phase 1 PID scan")
    parser.add_argument("--no-fd-scan", action="store_true",
                        help="Disable scanning /proc/<pid>/fd descriptors (faster)")
    parser.add_argument("--json-report", default="report.json",
                        help="JSON report output file (default: report.json)")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA rules: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    print("[*] Enumerating processes...")
    all_pids = [p.pid for p in psutil.process_iter()]
    self_pid = os.getpid()
    parent_pid = os.getppid()
    # Skip our own process + parent
    pids = [pid for pid in all_pids if pid not in (self_pid, parent_pid)]
    total = len(pids)
    print(f"[*] {total} processes found (excluding self + parent)\n")

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

    bar_len = 50
    done = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
            done += 1
            filled = int(bar_len * done / total) if total else bar_len
            bar = "+" * filled + "-" * (bar_len - filled)
            print(
                f"\rScanning processes | {done}/{total} [{bar}]",
                end="",
                flush=True
            )

            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    exe = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    name = proc.name()
                    sha = compute_sha256(exe)
                except Exception:
                    exe = "<unknown>"
                    cmd = "<unknown>"
                    name = "<unknown>"
                    sha = None

                rule_names = [m.rule for m in res]
                # break the progress line
                print()
                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name: {name} | EXE: {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {rule_names}\n"
                )

    print()  # finish progress line
    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # JSON report skeleton
    report = {
        "timestamp": now_iso(),
        "rule_file": args.rule,
        "matched_processes": []
    }

    # --------------------------------------------------------------
    # PHASE 2 — deep forensics per matched PID
    # --------------------------------------------------------------
    for pid, yara_matches in matched.items():
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        proc_entry = {
            "pid": pid,
            "name": "<unknown>",
            "exe": "<unknown>",
            "cmdline": "<unknown>",
            "sha256": None,
            "injection_indicators": [],
            "regions": [],
            "fds": []
        }

        # process metadata
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            cmd = " ".join(proc.cmdline())
            sha = compute_sha256(exe)

            print(Fore.YELLOW + "Process Info:")
            print(f"  PID    : {pid}")
            print(f"  Name   : {proc.name()}")
            print(f"  EXE    : {exe}")
            print(f"  CMD    : {cmd}")
            print(f"  SHA256 : {sha}")

            proc_entry["name"] = proc.name()
            proc_entry["exe"] = exe
            proc_entry["cmdline"] = cmd
            proc_entry["sha256"] = sha
        except Exception:
            print("  <metadata unavailable>")

        # injection indicators
        indicators = detect_injection_indicators(pid)
        proc_entry["injection_indicators"] = indicators

        print(Fore.YELLOW + "\nInjection Indicators:")
        if indicators:
            for i in indicators:
                print(Fore.RED + "  [!] " + i)
        else:
            print("  <none>")

        # Deep memory region scanning
        try:
            arch = detect_arch(proc_entry["exe"]) if proc_entry["exe"] != "<unknown>" else "x86_64"
        except Exception:
            arch = "x86_64"
        disasm = get_disassembler(arch)

        regions_report = deep_scan_memory(
            pid, rules, args.dump_dir, args.max_read, arch, disasm
        )
        proc_entry["regions"] = regions_report

        # FD scanning
        if not args.no_fd_scan:
            fd_report = scan_fds(pid, rules, args.dump_dir, args.max_read)
            proc_entry["fds"] = fd_report
        else:
            print(Fore.YELLOW + "Skipping FD scan (--no-fd-scan enabled)")

        report["matched_processes"].append(proc_entry)

        print(Fore.CYAN + f"\n====================================================\n")

    # --------------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------------
    if args.json_report:
        try:
            with open(args.json_report, "w") as jf:
                json.dump(report, jf, indent=2)
            print(Fore.CYAN + f"[*] JSON report written → {args.json_report}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON report: {e}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()