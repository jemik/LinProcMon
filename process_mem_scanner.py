#!/usr/bin/env python3
"""
process_mem_scanner_v5.6-R
Clean rewritten version with normalized output.

FEATURES:
    • Phase-1 threaded YARA PID scan
    • Phase-2 multiprocess deep forensic scan
    • Hexdump + snippet (256 bytes)
    • Disassembly via Capstone
    • Injection indicator detection
    • Optional FD scanning
    • JSON report output
    • Self-excluding (does not scan its own process)
"""

import os
import sys
import psutil
import yara
import argparse
import json
import base64
import struct
import math
import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

# =====================================================================
# GLOBALS
# =====================================================================

SNIPPET_BEFORE = 128
SNIPPET_AFTER  = 128
SNIPPET_TOTAL  = SNIPPET_BEFORE + SNIPPET_AFTER


# =====================================================================
# UTIL
# =====================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs = {b: data.count(b) for b in set(data)}
    return -sum((c/len(data)) * math.log2(c/len(data)) for c in freqs.values())


def compute_sha256(path):
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


# =====================================================================
# ARCH DETECTION
# =====================================================================

def detect_arch(exe_path: str):
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
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":    return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":  return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":    return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)


# =====================================================================
# HEX DUMP
# =====================================================================

def format_hexdump(base_va, data: bytes, width=16):
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"0x{base_va + i:016x}  {hex_part:<48}  {asc_part}")
    return out


# =====================================================================
# SHELLCODE HIGHLIGHTING
# =====================================================================

def looks_like_shellcode(insn):
    m = insn.mnemonic.lower()
    o = insn.op_str.lower()

    if m == "push" and "0x3b" in o:
        return True
    if m == "movabs" and ("/bin/sh" in o or "68732f6e69622f" in o):
        return True
    if m in ("syscall", "int") and ("0x80" in o):
        return True
    if m == "cdq":
        return True
    if m == "xor" and ("rdx" in o or "esi" in o):
        return True
    if m in ("jmp", "call") and ("rsp" in o or "rax" in o):
        return True
    return False


# =====================================================================
# DISASSEMBLY
# =====================================================================

def disassemble_snippet(arch, data: bytes, base_va):
    md = get_disassembler(arch)
    md.detail = False
    out = []

    try:
        for insn in md.disasm(data, base_va):
            out.append({
                "addr": f"0x{insn.address:016x}",
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "highlight": looks_like_shellcode(insn)
            })
    except:
        pass

    return out


# =====================================================================
# SNIPPET EXTRACTION
# =====================================================================

def extract_snippet(region_bytes, region_start_va, match_offset, match_len):
    start = max(0, match_offset - SNIPPET_BEFORE)
    end   = min(len(region_bytes), match_offset + match_len + SNIPPET_AFTER)

    snip = region_bytes[start:end]
    snip_va = region_start_va + start

    return snip, snip_va


# =====================================================================
# INJECTION INDICATORS
# =====================================================================

def detect_injection(pid):
    indicators = []
    maps_path = f"/proc/{pid}/maps"

    try:
        with open(maps_path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue

                addr, perms = parts[0], parts[1]
                path = parts[5] if len(parts) >= 6 else ""

                if "rwx" in perms:
                    indicators.append(f"RWX region: {addr}")

                if "x" in perms and path.startswith("memfd:"):
                    indicators.append(f"memfd exec region: {addr} {path}")

                if "x" in perms and path == "":
                    indicators.append(f"Anonymous exec region: {addr}")

    except:
        pass

    return indicators


# =====================================================================
# READ MEMORY REGION
# =====================================================================

def read_region(pid, start, size, max_read):
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(mem_path, "rb") as f:
            if size > max_read:
                f.seek(start + (size - max_read))
                return f.read(max_read)
            else:
                f.seek(start)
                return f.read(size)
    except:
        return None


# =====================================================================
# DEEP SCAN WORKER (MULTIPROCESS)
# =====================================================================

def deep_worker(task):
    pid, rule_path, max_read, no_fd_scan = task

    out = {
        "pid": pid,
        "regions": [],
        "fd_matches": [],
        "injection_indicators": [],
        "errors": []
    }

    try:
        rules = yara.compile(filepath=rule_path)
    except Exception as e:
        out["errors"].append(f"yara_compile: {e}")
        return out

    try:
        exe_path = psutil.Process(pid).exe()
        arch = detect_arch(exe_path)
    except:
        arch = "x86_64"

    out["injection_indicators"] = detect_injection(pid)

    # Read maps
    try:
        with open(f"/proc/{pid}/maps") as f:
            maps = f.read().splitlines()
    except Exception as e:
        out["errors"].append(f"maps: {e}")
        return out

    # ---- Scan memory regions ----
    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue

        addr_range, perms = parts[0], parts[1]
        if "r" not in perms:
            continue

        start_s, end_s = addr_range.split("-")
        start, end = int(start_s, 16), int(end_s, 16)
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

        region_info = {
            "address": addr_range,
            "perms": perms,
            "entropy": shannon_entropy(region),
            "matches": []
        }

        # Group by string
        groups = {}

        for m in matches:
            for inst in m.strings:
                sid = inst.identifier
                groups.setdefault(sid, []).append((inst.offset, inst.matched_data))

        for sid, inst_list in groups.items():
            entry = {"string_id": sid, "instances": []}

            for off, data_bytes in inst_list:
                snip, snip_va = extract_snippet(region, start, off, len(data_bytes))

                hex_snip = " ".join(f"{b:02x}" for b in snip)
                b64_snip = base64.b64encode(snip).decode()

                entry["instances"].append({
                    "absolute_offset": f"0x{start+off:x}",
                    "relative_offset": off,
                    "length": len(data_bytes),
                    "snippet_va": f"0x{snip_va:x}",
                    "hex": hex_snip,
                    "b64": b64_snip,
                    "hexdump": format_hexdump(snip_va, snip),
                    "disassembly": disassemble_snippet(arch, snip, snip_va),
                })

            region_info["matches"].append(entry)

        out["regions"].append(region_info)

    # ---- FD scanning ----
    if not no_fd_scan:
        fd_dir = f"/proc/{pid}/fd"
        if os.path.isdir(fd_dir):
            for fd in os.listdir(fd_dir):
                full = os.path.join(fd_dir, fd)

                try:
                    target = os.readlink(full)
                except:
                    continue

                if target.startswith(("pipe:", "socket:")):
                    continue

                try:
                    with open(full, "rb") as f:
                        fd_bytes = f.read(max_read)
                except:
                    continue

                try:
                    fd_matches = rules.match(data=fd_bytes)
                except:
                    continue

                if fd_matches:
                    out["fd_matches"].append({
                        "fd": fd,
                        "target": target,
                        "rules": [m.rule for m in fd_matches]
                    })

    return out


# =====================================================================
# PHASE-1 — YARA PID SCAN
# =====================================================================

def scan_pid_threaded(rules, pid, self_pid, parent_pid):
    if pid in (self_pid, parent_pid):
        return pid, None
    try:
        m = rules.match(pid=pid)
        return pid, m if m else None
    except:
        return pid, None


def do_phase1(rules, threads, self_pid, parent_pid):
    pids = [p.pid for p in psutil.process_iter()]
    print(Fore.CYAN + f"[*] Found {len(pids)} processes\n")

    matches = {}

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futs = {exe.submit(scan_pid_threaded, rules, pid, self_pid, parent_pid): pid for pid in pids}

        for fut in as_completed(futs):
            pid, result = fut.result()
            if result:
                matches[pid] = result
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe_path = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    sha = compute_sha256(exe_path)
                except:
                    name = exe_path = cmd = "<unknown>"
                    sha = None

                print(
                    Fore.GREEN +
                    f"[+] Match PID {pid} | {name}\n"
                    f"    EXE={exe_path}\n"
                    f"    CMD={cmd}\n"
                    f"    SHA256={sha}\n"
                    f"    Rules={[m.rule for m in result]}\n"
                )

    print(Fore.CYAN + f"[*] Phase-1 complete — {len(matches)} matched\n")
    return matches


# =====================================================================
# PHASE-2 — MULTIPROCESS DEEP FORENSIC SCAN
# =====================================================================

def do_phase2(tasks, workers):
    results = {}
    print(Fore.CYAN + f"[*] Launching {workers} deep workers...\n")

    with ProcessPoolExecutor(max_workers=workers) as exe:
        futs = {exe.submit(deep_worker, t): t[0] for t in tasks}

        for fut in as_completed(futs):
            pid = futs[fut]
            try:
                results[pid] = fut.result()
                print(Fore.GREEN + f"[+] Deep scan complete: PID {pid}")
            except Exception as e:
                print(Fore.RED + f"[!] Worker crash for PID {pid}: {e}")

    print(Fore.CYAN + "\n[*] Phase-2 complete\n")
    return results


# =====================================================================
# MAIN
# =====================================================================

def main():
    ap = argparse.ArgumentParser(description="process_mem_scanner_v5.6-R")

    ap.add_argument("-r", "--rule", required=True)
    ap.add_argument("--threads", type=int, default=6)
    ap.add_argument("--deep-workers", type=int, default=4)
    ap.add_argument("--max-read", type=int, default=6 * 1024 * 1024)
    ap.add_argument("--no-fd-scan", action="store_true")
    ap.add_argument("--json-report")

    args = ap.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    self_pid = os.getpid()
    parent_pid = os.getppid()
    print(Fore.CYAN + f"[*] Scanner PID={self_pid}, parent={parent_pid}\n")

    # ----------------------------- Phase-1
    phase1 = do_phase1(rules, args.threads, self_pid, parent_pid)

    if not phase1:
        print(Fore.YELLOW + "[*] No YARA matches — exiting\n")
        return

    # ----------------------------- Phase-2 prep
    tasks = [(pid, args.rule, args.max_read, args.no_fd_scan) for pid in phase1]

    deep = do_phase2(tasks, args.deep_workers)

    # ----------------------------- JSON OUTPUT
    if args.json_report:
        print(Fore.CYAN + f"[*] Writing JSON → {args.json_report}")

        rep = {
            "timestamp": now_iso(),
            "rule_file": args.rule,
            "matched_pids": deep
        }

        try:
            with open(args.json_report, "w") as f:
                json.dump(rep, f, indent=2)
            print(Fore.GREEN + "[+] JSON saved\n")
        except Exception as e:
            print(Fore.RED + f"[!] JSON write error: {e}")

    print(Fore.GREEN + "\n[*] Scan complete.\n")


if __name__ == "__main__":
    main()