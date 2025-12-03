#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — Evolution of your working v5.1

What's added compared to v5.1:
-------------------------------------------------
✓ JSON report (--json-report FILE)
✓ Skip scanning self & parent process
✓ Output normalized (same as v5.1)
✓ ZERO changes to working matching logic
✓ ZERO changes to snippet extraction logic
✓ Identical disassembly & hex dump behavior
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import math
import json
import datetime

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)


# ======================================================================
# Utility
# ======================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()

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
        if e_machine == 0x3E: return "x86_64"
        if e_machine == 0xB7: return "arm64"
    else:
        if e_machine == 0x03: return "x86"
        if e_machine == 0x28: return "arm"

    return "x86_64"

def get_disassembler(arch):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":    return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":  return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":    return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


def hex_dump_highlight(data, base, match_off, match_len, ctx=256):
    """Printable hex dump with highlight on matched bytes."""
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


# ======================================================================
# Indicators
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

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
# PHASE 2 — Deep Memory Scan
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, report):
    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception:
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
        except Exception:
            continue
        if not matches:
            continue

        print(Fore.GREEN + f"\n  [+] Region match at {addr_range} perms={perms}")
        print(f"      Entropy: {shannon_entropy(region):.3f}")

        reg_entry = {
            "address": addr_range,
            "perms": perms,
            "entropy": shannon_entropy(region),
            "matches": []
        }

        for m in matches:
            for s in m.strings:
                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(Fore.CYAN + f"\n    String {s.identifier}: offset={hex(abs_off)} len={mlen}")
                    hex_dump_highlight(region, start, off, mlen)

                    # disassembly
                    arch = detect_arch(psutil.Process(pid).exe())
                    md = get_disassembler(arch)
                    ctx_start = max(0, off - 64)
                    ctx_end = min(len(region), off + mlen + 64)
                    code = region[ctx_start:ctx_end]

                    print("\n    Disassembly:")
                    dis_list = []
                    try:
                        for ins in md.disasm(code, start + ctx_start):
                            high = (start + off <= ins.address < start + off + mlen)
                            prefix = ">>" if high else "  "
                            color = Fore.RED if high else ""
                            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
                            print(color + "      " + line)
                            dis_list.append(line)
                    except:
                        print("      <failed disassembly>")

                    reg_entry["matches"].append({
                        "string": s.identifier,
                        "absolute_offset": hex(abs_off),
                        "length": mlen,
                        "disassembly": dis_list
                    })

        report["regions"].append(reg_entry)


# ======================================================================
# FD Scan
# ======================================================================

def scan_fds(pid, rules, dump_dir, max_read, report):
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

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
            for m in matches:
                print(Fore.MAGENTA + f"    Rule: {m.rule}")

            report["fd_matches"].append({
                "fd": fd,
                "target": target,
                "rules": [m.rule for m in matches]
            })


# ======================================================================
# MAIN
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="process_mem_scanner v5.6")
    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--json-report")
    parser.add_argument("--max-read", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--no-fd-scan", action="store_true")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    self_pid = os.getpid()
    parent_pid = os.getppid()

    print(Fore.CYAN + "\n[*] Phase 1 — threaded PID scan")
    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Total processes: {len(pids)}\n")

    matched = {}

    def scan_one(pid):
        if pid in (self_pid, parent_pid):
            return pid, []
        try:
            return pid, rules.match(pid=pid)
        except:
            return pid, []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan_one, pid): pid for pid in pids}
        for fut in as_completed(futures):
            pid, res = fut.result()
            if res:
                matched[pid] = res
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    sha = compute_sha256(exe)
                except Exception:
                    name = exe = cmd = sha = "<unknown>"

                print(
                    Fore.GREEN +
                    f"[+] PID {pid} MATCH | {name} | {exe}\n"
                    f"    CMD: {cmd}\n"
                    f"    SHA256: {sha}\n"
                    f"    Rules: {[m.rule for m in res]}\n"
                )

    print(Fore.CYAN + f"\n[*] Phase 1 complete — {len(matched)} matches.\n")

    # -------------------------------------------------------------
    # JSON OUTPUT PREP
    # -------------------------------------------------------------
    final_json = {
        "timestamp": now_iso(),
        "matched": []
    }

    # -------------------------------------------------------------
    # PHASE 2
    # -------------------------------------------------------------

    print(Fore.CYAN + f"[*] Phase 2 — deep scan of {len(matched)} processes...\n")

    for pid in matched:
        print(Fore.GREEN + f"\n[+] Deep scan START for PID {pid}")

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = proc.exe()
            cmd = " ".join(proc.cmdline())
            sha = compute_sha256(exe)
        except:
            name = exe = cmd = sha = "<unknown>"

        report = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmd": cmd,
            "sha256": sha,
            "injection_indicators": detect_injection_indicators(pid),
            "regions": [],
            "fd_matches": []
        }

        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, report)

        if not args.no_fd_scan:
            scan_fds(pid, rules, args.dump_dir, args.max_read, report)

        final_json["matched"].append(report)

        print(Fore.GREEN + f"[+] Deep scan complete for PID {pid}\n")

    print(Fore.CYAN + "\n[*] All deep scans completed.\n")

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(final_json, f, indent=2)
        print(Fore.GREEN + f"[+] JSON report written → {args.json_report}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()