#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — Hybrid Scanner + JSON

PHASE 1:
    - YARA native process scan (rules.match(pid=pid)) in threads
    - Skips own PID and parent PID
    - Fast, safe, correct offsets from YARA CLI behavior

PHASE 2 (only for matched PIDs):
    - Enumerate readable regions from /proc/<pid>/maps
    - Re-scan each region with YARA to get offsets
    - Hex dump around matched bytes
    - Capstone disassembly
    - Injection indicator detection
    - Optional memfd file descriptor scanning
    - Optional region dumps

JSON REPORT:
    - For each matched PID:
        - PID, name, exe, cmdline, sha256
        - injection_indicators
        - regions:
            - address, perms, entropy, dump_file (if any)
            - matches:
                - rule, string_id, absolute_offset, relative_offset, length
                - hexdump (list of lines, same style as terminal)
                - disassembly (list of lines, same style as terminal)
        - fd_matches:
            - fd, target, rules, dump_file (if any)
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

colorama_init(autoreset=True)


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
    Original terminal output — KEEP EXACT BEHAVIOR.
    Prints 256 bytes (128 before + match + 128 after) with match in red.
    """
    half = ctx // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)

    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump @ 0x{snippet_base:x}:")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        hex_parts = []
        ascii_parts = []
        for j, b in enumerate(line):
            gi = start + i + j
            in_range = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."
            if in_range:
                hx = Fore.RED + hx + Style.RESET_ALL
                ch = Fore.RED + ch + Style.RESET_ALL
            hex_parts.append(hx)
            ascii_parts.append(ch)
        print(
            f"        0x{snippet_base + i:016x}  "
            f"{' '.join(hex_parts):<48}  {''.join(ascii_parts)}"
        )


def build_hexdump_lines(data, base, match_off, match_len, ctx=256):
    """
    JSON-safe version of hex dump: same style as terminal,
    but without color codes, and with matching bytes just enclosed in [].
    Returns list[str].
    """
    lines = []
    half = ctx // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)

    snippet = data[start:end]
    snippet_base = base + start

    header = f"Hex dump @ 0x{snippet_base:x}:"
    lines.append(header)

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        hex_parts = []
        ascii_parts = []
        for j, b in enumerate(line):
            gi = start + i + j
            in_range = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."
            if in_range:
                hx = f"[{hx}]"
            hex_parts.append(hx)
            ascii_parts.append(ch)
        lines.append(
            f"0x{snippet_base + i:016x}  "
            f"{' '.join(hex_parts):<48}  {''.join(ascii_parts)}"
        )

    return lines


def build_disasm_lines(region, start, off, mlen, arch):
    """
    JSON + terminal disassembly helper.
    Returns (terminal_print_lines, json_lines)
      - terminal_print_lines already includes prefix and address text
        but no color; we add color in caller
      - json_lines is identical but without color (same strings)
    """
    md = get_disassembler(arch)
    ctx_start = max(0, off - 64)
    ctx_end = min(len(region), off + mlen + 64)
    code = region[ctx_start:ctx_end]

    json_lines = []
    term_lines = []

    try:
        for ins in md.disasm(code, start + ctx_start):
            high = (start + off <= ins.address < start + off + mlen)
            prefix = ">>" if high else "  "
            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
            json_lines.append(line)
            term_lines.append((line, high))
    except Exception:
        json_lines.append("<failed disassembly>")
        term_lines.append(("<failed disassembly>", False))

    return term_lines, json_lines


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
                if line.startswith("VmFlags:") and current:
                    fl = line.split(":")[1].strip().split()
                    if "ex" in fl and ("mr" in fl or "mw" in fl):
                        indicators.append(f"VmFlags transition: {current}")
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
# Deep Scan of Memory Regions (with JSON capture)
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, proc_report=None):
    """
    Original behavior:
      - Print region matches, entropy, strings, hex dump, disasm
      - Dump region to disk (if dump_dir) when matches occur

    New:
      - Also push structured info into proc_report["regions"]
    """
    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception:
        return

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    # Ensure report structure
    if proc_report is not None and "regions" not in proc_report:
        proc_report["regions"] = []

    # Detect arch once per PID (for disasm)
    try:
        exe_path = psutil.Process(pid).exe()
        arch = detect_arch(exe_path)
    except Exception:
        arch = "x86_64"

    for line in maps:
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

        entropy = shannon_entropy(region)

        print(Fore.GREEN + f"\n  [+] Region match at {addr_range} perms={perms}")
        print(f"      Entropy: {entropy:.3f}")

        # Region entry for JSON
        region_entry = {
            "address": addr_range,
            "perms": perms,
            "entropy": entropy,
            "matches": []
        }

        for m in matches:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            for s in m.strings:
                ident = s.identifier
                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(
                        Fore.CYAN +
                        f"\n    String {ident}: offset={hex(abs_off)} len={mlen}"
                    )

                    # Terminal hex dump
                    hex_dump_highlight(region, start, off, mlen)

                    # JSON hex dump lines
                    hexdump_lines = build_hexdump_lines(region, start, off, mlen)

                    # Disassembly
                    print("\n    Disassembly:")
                    term_disasm, json_disasm = build_disasm_lines(
                        region, start, off, mlen, arch
                    )
                    for line, high in term_disasm:
                        color = Fore.RED if high else ""
                        print(color + f"      {line}")

                    # JSON match entry
                    match_entry = {
                        "rule": m.rule,
                        "string_id": ident,
                        "absolute_offset": hex(abs_off),
                        "relative_offset": off,
                        "length": mlen,
                        "hexdump": hexdump_lines,
                        "disassembly": json_disasm
                    }
                    region_entry["matches"].append(match_entry)

        # Dump region (once per region with matches)
        if dump_dir:
            try:
                outdir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(outdir, exist_ok=True)
                path = os.path.join(outdir, f"region_{addr_range.replace('-', '_')}.bin")
                with open(path, "wb") as f:
                    f.write(region)
                print(Fore.GREEN + f"    Dumped region to: {path}")
                region_entry["dump_file"] = path
            except Exception:
                pass

        if proc_report is not None:
            proc_report["regions"].append(region_entry)


# ======================================================================
# FD (memfd) scan (with JSON capture)
# ======================================================================

def scan_fds(pid, rules, dump_dir, max_read, proc_report=None):
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

    if proc_report is not None and "fd_matches" not in proc_report:
        proc_report["fd_matches"] = []

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
            rule_names = []
            for m in matches:
                print(Fore.MAGENTA + f"    Rule: {m.rule}")
                rule_names.append(m.rule)

            fd_entry = {
                "fd": fd,
                "target": target,
                "rules": rule_names
            }

            if dump_dir:
                try:
                    out = os.path.join(dump_dir, f"pid_{pid}")
                    os.makedirs(out, exist_ok=True)
                    p = os.path.join(out, f"fd_{fd}.bin")
                    with open(p, "wb") as f:
                        f.write(data)
                    print(Fore.GREEN + f"    Dumped FD: {p}")
                    fd_entry["dump_file"] = p
                except Exception:
                    pass

            if proc_report is not None:
                proc_report["fd_matches"].append(fd_entry)


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid YARA Memory Scanner v5.6 (threaded + JSON)"
    )
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--dump-dir", help="Dump directory for matched regions/FDs")
    parser.add_argument(
        "--max-read",
        type=int,
        default=5 * 1024 * 1024,
        help="Max bytes to read per region/FD"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of threads for Phase 1 PID scan"
    )
    parser.add_argument(
        "--no-fd-scan",
        action="store_true",
        help="Disable scanning /proc/<pid>/fd descriptors (faster)"
    )
    parser.add_argument(
        "--json-report",
        help="Write JSON report with full details (regions, hexdump, disassembly)"
    )
    args = parser.parse_args()

    # JSON report root
    report = {
        "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "rule_file": args.rule,
        "processes": []
    }

    print(Fore.CYAN + f"[*] Loading YARA rules: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    self_pid = os.getpid()
    parent_pid = os.getppid()

    print("[*] Enumerating processes...")
    all_pids = [p.pid for p in psutil.process_iter()]
    # Skip self and parent
    pids = [pid for pid in all_pids if pid not in (self_pid, parent_pid)]
    print(f"[*] {len(pids)} processes found (excluding self and parent)\n")

    # --------------------------------------------------------------
    # PHASE 1 — threaded native PID scanning
    # --------------------------------------------------------------
    print(Fore.CYAN + "[*] Phase 1 — YARA native PID scan (threaded)")

    matched = {}

    def scan_one(pid):
        try:
            res = rules.match(pid=pid)
            return pid, res
        except Exception:
            return pid, []

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
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
                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name: {name} | EXE: {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {rule_names}"
                )

    print(f"\n[*] Phase 1 done. Matched {len(matched)} processes.\n")

    # --------------------------------------------------------------
    # PHASE 2 — deep forensics per matched PID
    # --------------------------------------------------------------
    for pid, yara_matches in matched.items():
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        proc_entry = {
            "pid": pid,
            "name": None,
            "exe": None,
            "cmdline": None,
            "sha256": None,
            "injection_indicators": [],
            "regions": [],
            "fd_matches": []
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

        # Deep memory region scanning (fills proc_entry["regions"])
        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, proc_entry)

        # FD scanning (fills proc_entry["fd_matches"])
        if not args.no_fd_scan:
            scan_fds(pid, rules, args.dump_dir, args.max_read, proc_entry)
        else:
            print(Fore.YELLOW + "Skipping FD scan (--no-fd-scan enabled)")

        print(Fore.CYAN + f"\n====================================================\n")

        report["processes"].append(proc_entry)

    # --------------------------------------------------------------
    # JSON report
    # --------------------------------------------------------------
    if args.json_report:
        try:
            with open(args.json_report, "w") as jf:
                json.dump(report, jf, indent=2)
            print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON report: {e}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()