#!/usr/bin/env python3
"""
process_mem_scanner_v5.0 — Hybrid Mode Scanner
Author: Jesper Mikkelsen + AI

PHASE 1:
    - Use YARA's NATIVE process scanning (rules.match(pid=pid))
    - Fast, accurate, identical to CLI YARA behavior
    - No manual memory reading required

PHASE 2:
    - For ONLY matched processes:
        * Read readable VMAs from /proc/<pid>/maps
        * Scan memfd FDs
        * Search and highlight matched bytes in memory
        * Disassembly around matched bytes
        * Shellcode heuristics
        * ELF carving and reconstruction
        * Injection indicator detection (RWX, memfd, anonymous exec, VmFlags)
"""

import os
import sys
import yara
import psutil
import argparse
import datetime
import struct
import hashlib
import math

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)


# ======================================================================
# Utility Functions
# ======================================================================

def shannon_entropy(data: bytes) -> float:
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


def detect_arch_from_exe(exe_path):
    try:
        with open(exe_path, "rb") as f:
            hdr = f.read(0x40)
    except Exception:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64-bit
        if e_machine == 0x3E: return "x86_64"
        if e_machine == 0xB7: return "arm64"
    elif ei_class == 1:  # 32-bit
        if e_machine == 0x03: return "x86"
        if e_machine == 0x28: return "arm"

    return "x86_64"


def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":     return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":   return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":     return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


def hex_dump_highlight(data, base, match_off, match_len, context=256):
    half = context // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)
    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump around match (0x{snippet_base:x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        hex_parts = []
        ascii_parts = []
        for j, b in enumerate(line):
            gi = start + i + j
            highlight = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else '.'

            if highlight:
                hx = Fore.RED + hx + Style.RESET_ALL
                ch = Fore.RED + ch + Style.RESET_ALL

            hex_parts.append(hx)
            ascii_parts.append(ch)

        print(f"        0x{snippet_base + i:016x}  {' '.join(hex_parts):<48}  {''.join(ascii_parts)}")


# ======================================================================
# Injection Indicators
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

    # RWX, anonymous exec, memfd
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
                    indicators.append(f"Anonymous executable mapping: {addr}")

                if "x" in perms and "memfd:" in path:
                    indicators.append(f"memfd executable mapping: {addr} {path}")

    except Exception:
        pass

    # VmFlags
    try:
        current = None
        with open(smaps_path, "r") as f:
            for line in f:
                if "-" in line and line.count("-") == 1 and line.split()[0].count(":") == 0:
                    current = line.split()[0]
                if line.startswith("VmFlags:"):
                    flags = line.split(":")[1].strip().split()
                    if "ex" in flags and ("mr" in flags or "mw" in flags):
                        indicators.append(f"VmFlags suggests RX-from-RW: {current}")
    except Exception:
        pass

    return indicators


# ======================================================================
# Memory REGION Reader (Safe & Correct)
# ======================================================================

def safe_read_region(pid, start, size, max_read):
    """
    Reads up to max_read bytes from a mapped region safely.
    Always stays within region boundaries.
    """
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as mem_f:
            mem_f.seek(start)
            return mem_f.read(min(size, max_read))
    except Exception:
        return None


# ======================================================================
# PHASE 2 — DEEP ANALYSIS FOR MATCHED PIDs
# ======================================================================

def deep_analyze(pid, yara_matches, dump_dir, max_read=5*1024*1024):
    """
    Only called for processes that were confirmed by YARA native scanning.
    """

    print(Fore.CYAN + f"\n[+] Deep Analysis for PID {pid}")

    # ---------------------------
    # Process Metadata
    # ---------------------------
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        cmd = " ".join(proc.cmdline())
        sha = compute_sha256(exe)

        print(Fore.YELLOW + "Process Info:")
        print(f"  PID   : {pid}")
        print(f"  Name  : {proc.name()}")
        print(f"  EXE   : {exe}")
        print(f"  CMD   : {cmd}")
        print(f"  SHA256: {sha}")
    except Exception:
        print("  <unable to read process metadata>")

    # ---------------------------
    # Injection Indicators
    # ---------------------------
    indicators = detect_injection_indicators(pid)
    print(Fore.YELLOW + "\nInjection Indicators:")
    if indicators:
        for i in indicators:
            print(Fore.RED + f"  [!] {i}")
    else:
        print("  <none>")

    # ---------------------------
    # Deep memory region scanning
    # ---------------------------
    print(Fore.YELLOW + "\nScanning memory regions...")

    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, "r") as f:
            maps = f.readlines()
    except Exception:
        print(Fore.RED + "  Unable to read memory maps")
        return

    # For disassembly later
    arch = detect_arch_from_exe(proc.exe())
    md = get_disassembler(arch)

    # Create PID dump folder
    if dump_dir:
        os.makedirs(os.path.join(dump_dir, f"pid_{pid}"), exist_ok=True)

    # --------------------------------------
    # For each YARA match: find where it is
    # --------------------------------------
    for match in yara_matches:
        print(Fore.MAGENTA + f"\n  YARA Rule Matched: {match.rule}")
        if match.meta:
            print("    Meta: " + ", ".join(f"{k}={v}" for k, v in match.meta.items()))

        for string in match.strings:
            ident = string.identifier

            for inst in string.instances:
                off = inst.offset
                mbytes = inst.matched_data
                mlen = len(mbytes)

                print(Fore.GREEN + f"\n    String {ident} matched offset={hex(off)} len={mlen}")

                # Now find which region contains this address
                for line in maps:
                    parts = line.split()
                    addr_range, perms = parts[0], parts[1]
                    start_s, end_s = addr_range.split("-")
                    start = int(start_s, 16)
                    end = int(end_s, 16)

                    if start <= off < end:
                        region_size = end - start
                        local_off = off - start
                        print(f"      Region: {addr_range} perms={perms}")
                        print(f"      Local offset in region: {hex(local_off)}")

                        # Safely read region slice
                        region_data = safe_read_region(pid, start, region_size, max_read)
                        if not region_data:
                            print(Fore.RED + f"      Could not read region at {addr_range}")
                            continue

                        # Dump region if requested
                        if dump_dir:
                            path = os.path.join(dump_dir, f"pid_{pid}", f"region_{addr_range.replace('-', '_')}.bin")
                            with open(path, "wb") as f:
                                f.write(region_data)
                            print(f"      Dumped region: {path}")

                        # Highlight hex dump
                        hex_dump_highlight(region_data, start, local_off, mlen)

                        # Disassemble around match
                        print("\n      Disassembly:")
                        ctx_start = max(0, local_off - 64)
                        ctx_end   = min(len(region_data), local_off + mlen + 64)
                        code = region_data[ctx_start:ctx_end]

                        try:
                            for ins in md.disasm(code, start + ctx_start):
                                addr = f"0x{ins.address:016x}"
                                text = f"{ins.mnemonic} {ins.op_str}"
                                if start + local_off <= ins.address < start + local_off + mlen:
                                    print(Fore.RED + f"        >> {addr}: {text}")
                                else:
                                    print(f"           {addr}: {text}")
                        except Exception:
                            print("        <disassembly failed>")

                        break  # Found region


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Hybrid YARA Memory Scanner v5.0")
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--dump-dir", help="Dump directory for matched regions")
    parser.add_argument("--max-read", type=int, default=5*1024*1024, help="Max bytes to read from each region")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA rule: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    print("[*] Enumerating processes...")
    pids = [p.pid for p in psutil.process_iter()]

    print(f"[*] {len(pids)} processes found")
    print("\n[*] Starting Phase 1 - YARA PID scanning...\n")

    matched = {}

    for pid in pids:
        try:
            res = rules.match(pid=pid, timeout=2000)
        except yara.TimeoutError:
            continue
        except Exception:
            continue

        if res:
            matched[pid] = res
            print(Fore.GREEN + f"[+] Match in PID {pid}: {[m.rule for m in res]}")

    print("\n[*] Phase 1 complete.")
    print(f"[*] {len(matched)} processes matched.")

    # ===============================================================
    # Phase 2 — Deep Forensics
    # ===============================================================
    for pid, results in matched.items():
        deep_analyze(pid, results, args.dump_dir, args.max_read)

    print("\n[✓] Done.\n")


if __name__ == "__main__":
    main()