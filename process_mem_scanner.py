#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — Hybrid Scanner (stable build)

PHASE 1:
    - Threaded YARA scan over all PIDs (rules.match(pid=pid))
    - Skips scanning its own process + parent
    - Prints full match info

PHASE 2:
    - Deep scan ONLY matched PIDs
    - Full region enumeration
    - YARA re-scan of region bytes
    - Hex dump with highlighted match bytes
    - Capstone disassembly
    - Injection indicator detection
    - Optional memfd FD scanning
    - Optional memory dumps
    - JSON report support (--json-report <file>)
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
    """
    Detect architecture from ELF header.
    """
    try:
        with open(exe_path, "rb") as f:
            hdr = f.read(0x40)
    except:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64 bit
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
    """
    Print hex dump with red highlighting of matched bytes.
    """
    half = ctx // 2
    start = max(0, match_off - half)
    end = min(len(data), match_off + match_len + half)

    snippet = data[start:end]
    snippet_base = base + start

    print(f"        Hex dump @ 0x{snippet_base:x}:")

    for i in range(0, len(snippet), 16):
        chunk = snippet[i:i+16]
        hex_parts = []
        ascii_parts = []
        for j, b in enumerate(chunk):
            gi = start + i + j
            in_range = match_off <= gi < match_off + match_len

            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."

            if in_range:
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

    # RWX, memfd, anonymous exec
    try:
        with open(maps_path, "r") as f:
            for line in f:
                p = line.split()
                if len(p) < 5:
                    continue
                addr, perms, _, _, inode = p[:5]
                path = p[5] if len(p) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    indicators.append(f"RWX mapping: {addr} {perms}")
                if "x" in perms and inode == "0" and path in ("", "0"):
                    indicators.append(f"Anonymous exec: {addr}")
                if "x" in perms and "memfd:" in path:
                    indicators.append(f"memfd exec: {addr} {path}")

    except:
        pass

    # VmFlags transitions rw->rx
    try:
        current = None
        with open(smaps_path, "r") as f:
            for line in f:
                if "-" in line and ":" not in line:
                    current = line.split()[0]
                if line.startswith("VmFlags:"):
                    fl = line.split(":")[1].strip().split()
                    if "ex" in fl and ("mr" in fl or "mw" in fl):
                        indicators.append(f"VmFlags transition: {current}")
    except:
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
    except:
        return None


# ======================================================================
# Deep Scan Core
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, json_out):
    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception:
        return

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    for line in maps:
        p = line.split()
        if len(p) < 2:
            continue

        addr_range, perms = p[0], p[1]
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

        print(Fore.GREEN + f"\n  [+] Region {addr_range} perms={perms}")
        ent = shannon_entropy(region)
        print(f"      Entropy: {ent:.3f}")

        region_entry = {
            "address": addr_range,
            "perms": perms,
            "entropy": ent,
            "matches": []
        }

        # Process matches
        for m in matches:
            rule = m.rule
            print(Fore.MAGENTA + f"    Rule: {rule}")

            for s in m.strings:
                string_id = s.identifier

                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(Fore.CYAN + f"\n    String {string_id}: offset={hex(abs_off)} len={mlen}")
                    hex_dump_highlight(region, start, off, mlen)

                    # disassembly fragment
                    arch = detect_arch(psutil.Process(pid).exe())
                    md = get_disassembler(arch)
                    ctx_start = max(0, off - 64)
                    ctx_end = min(len(region), off + mlen + 64)
                    code = region[ctx_start:ctx_end]

                    print("\n    Disassembly:")
                    disasm_lines = []
                    try:
                        for ins in md.disasm(code, start + ctx_start):
                            high = (start + off <= ins.address < start + off + mlen)
                            prefix = ">>" if high else "  "
                            color = Fore.RED if high else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print(color + "      " + line)
                            disasm_lines.append(line)
                    except:
                        print("      <failed disassembly>")

                    region_entry["matches"].append({
                        "rule": rule,
                        "string_id": string_id,
                        "absolute_offset": abs_off,
                        "length": mlen,
                        "hexdump_context": {
                            "base": start,
                            "offset": off
                        },
                        "disassembly": disasm_lines
                    })

        json_out["regions"].append(region_entry)

        # dump raw region
        if dump_dir:
            outdir = os.path.join(dump_dir, f"pid_{pid}")
            os.makedirs(outdir, exist_ok=True)
            path = os.path.join(outdir, f"region_{addr_range.replace('-', '_')}.bin")
            with open(path, "wb") as f:
                f.write(region)
            print(Fore.GREEN + f"    Dumped region: {path}")


# ======================================================================
# FD Scan
# ======================================================================

def scan_fds(pid, rules, dump_dir, max_read, json_out):
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

    for fd in os.listdir(fd_path):
        full = os.path.join(fd_path, fd)
        try:
            target = os.readlink(full)
        except:
            continue

        if target.startswith("socket:") or target.startswith("pipe:"):
            continue

        try:
            with open(full, "rb") as f:
                data = f.read(max_read)
        except:
            continue

        try:
            matches = rules.match(data=data)
        except:
            continue

        if matches:
            print(Fore.GREEN + f"  [+] FD {fd} match → {target}")
            entry = {"fd": fd, "target": target, "rules": []}

            for m in matches:
                print(Fore.MAGENTA + f"    Rule: {m.rule}")
                entry["rules"].append(m.rule)

            if dump_dir:
                outdir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(outdir, exist_ok=True)
                path = os.path.join(outdir, f"fd_{fd}.bin")
                with open(path, "wb") as f:
                    f.write(data)
                print(Fore.GREEN + f"    Dumped FD: {path}")
                entry["dump_file"] = path

            json_out["fd_matches"].append(entry)


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Hybrid YARA Memory Scanner v5.6")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--max-read", type=int, default=5*1024*1024)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-fd-scan", action="store_true")
    parser.add_argument("--json-report", help="Write full JSON report")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}\n")
    rules = yara.compile(filepath=args.rule)

    self_pid = os.getpid()
    parent_pid = os.getppid()

    # ------------------------------------------------------------------
    # PHASE 1 — threaded YARA PID scan
    # ------------------------------------------------------------------
    print(Fore.CYAN + "[*] Phase 1 — threaded PID scan")

    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Total processes: {len(pids)}")

    matched = {}

    def scan_one(pid):
        if pid in (self_pid, parent_pid):
            return pid, []
        try:
            res = rules.match(pid=pid)
            return pid, res
        except:
            return pid, []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    exe = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    name = proc.name()
                except:
                    exe = cmd = name = "<unknown>"

                rule_names = [m.rule for m in res]
                print(
                    Fore.GREEN +
                    f"[+] PID {pid} MATCH | {name} | {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {compute_sha256(exe)}\n"
                    f"    Rules: {rule_names}\n"
                )

    print(Fore.CYAN + f"[*] Phase 1 complete — {len(matched)} matches.\n")

    # ------------------------------------------------------------------
    # PHASE 2 — deep scanning
    # ------------------------------------------------------------------
    if not matched:
        print(Fore.YELLOW + "[*] No matches — exiting.")
        return

    print(Fore.CYAN + f"[*] Phase 2 — deep scan of {len(matched)} processes...\n")

    json_report = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "rule": args.rule,
        "matched": []
    }

    for pid, mlist in matched.items():
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        proc_entry = {"pid": pid, "regions": [], "fd_matches": []}

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
            proc_entry["cmd"] = cmd
            proc_entry["sha256"] = sha

        except:
            print("  <metadata unavailable>")

        indicators = detect_injection_indicators(pid)
        print(Fore.YELLOW + "\nInjection Indicators:")
        proc_entry["injection_indicators"] = indicators

        if indicators:
            for i in indicators:
                print(Fore.RED + f"  [!] {i}")
        else:
            print("  <none>")

        # deep memory scan
        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, proc_entry)

        # FD scan
        if not args.no_fd_scan:
            scan_fds(pid, rules, args.dump_dir, args.max_read, proc_entry)
        else:
            print(Fore.YELLOW + "Skipping FD scan (--no-fd-scan enabled)")

        print(Fore.CYAN + f"\n[+] Deep scan complete for PID {pid}\n")
        json_report["matched"].append(proc_entry)

    print(Fore.CYAN + "\n[*] All deep scans completed.\n")

    # ------------------------------------------------------------------
    # JSON REPORT
    # ------------------------------------------------------------------
    if args.json_report:
        try:
            with open(args.json_report, "w") as jf:
                json.dump(json_report, jf, indent=2)
            print(Fore.GREEN + f"[*] JSON report written → {args.json_report}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON: {e}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()