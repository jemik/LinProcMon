#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 (rewritten clean version)
Compatible with yara-python 4.5.4
- Threaded PID scanning (Phase 1)
- Multiprocess deep forensic scanning (Phase 2)
- Full disassembly, snippet extraction, entropy, hexdumps
- Optional FD scanning
- NO ELF carving
"""

import os
import sys
import yara
import psutil
import argparse
import hashlib
import base64
import struct
import json
import math
import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

SNIPPET_BEFORE = 128
SNIPPET_AFTER  = 128


# =====================================================================
# Utility helpers
# =====================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()


def compute_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(8192), b""):
                h.update(b)
        return h.hexdigest()
    except:
        return None


def shannon_entropy(b: bytes):
    if not b:
        return 0.0
    length = len(b)
    freqs = {}
    for x in b:
        freqs[x] = freqs.get(x, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in freqs.values())


# =====================================================================
# Architecture + Disassembly utilities
# =====================================================================

def detect_arch(path):
    """
    Return "x86_64" (default), "x86", "arm", "arm64".
    """
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x40)
    except:
        return "x86_64"

    if len(hdr) < 20:
        return "x86_64"

    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64-bit ELF
        if e_machine == 0x3E:
            return "x86_64"
        if e_machine == 0xB7:
            return "arm64"
    if ei_class == 1:
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


def is_shellcode_instruction(insn):
    m = insn.mnemonic.lower()
    op = insn.op_str.lower()

    if m == "push" and "0x3b" in op:
        return True
    if m == "movabs" and ("/bin/sh" in op or "68732f6e69622f" in op):
        return True
    if m in ("syscall", "int") and ("0x80" in op or "80" in op):
        return True
    if m == "cdq":
        return True
    if m == "xor" and ("rdx" in op or "esi" in op):
        return True
    if m in ("jmp", "call") and ("rax" in op or "rsp" in op):
        return True

    return False


def hex_dump(base, data, width=16):
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexp = " ".join(f"{b:02x}" for b in chunk)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    0x{base+i:016x}  {hexp:<48}  {asc}")
    return "\n".join(out)


def disassemble_snippet(arch, snippet: bytes, base_va: int):
    md = get_disassembler(arch)
    md.detail = False

    lines = []
    try:
        for insn in md.disasm(snippet, base_va):
            hi = is_shellcode_instruction(insn)
            mark = ">>" if hi else "  "
            lines.append(
                f"{mark} 0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}"
            )
    except Exception:
        pass
    return lines


# =====================================================================
# Memory access helpers
# =====================================================================

def read_region(pid, start, size, max_read):
    """
    Safe region reader: respects max_read limit and mmap IO rules.
    """
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as m:
            m.seek(start)
            return m.read(min(size, max_read))
    except Exception:
        return None


def extract_snippet(region, match_off, match_len, region_va_start):
    """
    Compute snippet bytes + snippet VA.
    """
    start = max(match_off - SNIPPET_BEFORE, 0)
    end   = min(match_off + match_len + SNIPPET_AFTER, len(region))

    snip = region[start:end]
    snip_va = region_va_start + start

    return snip, snip_va


# =====================================================================
# Phase 1 — YARA scan of PIDs
# =====================================================================

def scan_pid(rules, pid, selfpid, parentpid):
    if pid in (selfpid, parentpid):
        return pid, None

    try:
        m = rules.match(pid=pid)
        return pid, m if m else None
    except:
        return pid, None


def phase1(rules, threads):
    print(Fore.CYAN + "\n[*] Phase 1 — threaded PID scan")
    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Total processes: {len(pids)}")

    selfpid = os.getpid()
    parentpid = os.getppid()

    matches = {}

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(scan_pid, rules, pid, selfpid, parentpid): pid for pid in pids}

        for fut in as_completed(futs):
            pid, res = fut.result()
            if res:
                matches[pid] = res

                try:
                    proc = psutil.Process(pid)
                    print(Fore.GREEN +
                          f"[+] PID {pid} MATCH | {proc.name()} | {proc.exe()}\n"
                          f"    CMD: {' '.join(proc.cmdline())}\n"
                          f"    SHA256: {compute_sha256(proc.exe())}\n"
                          f"    Rules: {[m.rule for m in res]}\n")
                except:
                    print(Fore.GREEN +
                          f"[+] PID {pid} MATCH | (metadata unavailable)\n")

    print(Fore.CYAN + f"[*] Phase 1 complete — {len(matches)} matches.\n")
    return matches


# =====================================================================
# Phase 2 — Deep forensic scan worker
# =====================================================================

def deep_worker(job):
    """
    Runs in separate process
    job = (pid, rule_path, max_read, no_fd)
    """
    pid, rule_path, max_read, no_fd = job
    out = {
        "pid": pid,
        "regions": [],
        "fd_matches": [],
        "injection_indicators": [],
        "errors": []
    }

    # compile rules
    try:
        rules = yara.compile(filepath=rule_path)
    except Exception as e:
        out["errors"].append(f"rule_compile: {e}")
        return out

    # detect architecture
    try:
        exe = psutil.Process(pid).exe()
        arch = detect_arch(exe)
    except:
        arch = "x86_64"

    # injection indicators
    out["injection_indicators"] = detect_injection_indicators(pid)

    # read maps
    try:
        with open(f"/proc/{pid}/maps") as f:
            maps = f.read().splitlines()
    except Exception as e:
        out["errors"].append(f"maps: {e}")
        return out

    # scan memory
    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue
        addr, perms = parts[0], parts[1]
        if "r" not in perms:
            continue

        start_s, end_s = addr.split("-")
        start = int(start_s, 16)
        end   = int(end_s, 16)
        size  = end - start
        if size <= 0:
            continue

        region = read_region(pid, start, size, max_read)
        if not region:
            continue

        # apply yara
        try:
            mem = rules.match(data=region)
        except Exception:
            continue

        if not mem:
            continue

        reg_info = {
            "address": addr,
            "perms": perms,
            "entropy": shannon_entropy(region),
            "matches": []
        }

        # YARA-Python 4.5.4 MATCH FORMAT:
        # match.strings is list of tuples: (offset, identifier, data)
        for m in mem:
            rule_name = m.rule

            by_string = {}
            for (off, sid, data) in m.strings:
                by_string.setdefault(sid, []).append((off, data))

            for sid, inst_list in by_string.items():
                g = {
                    "string_id": sid,
                    "rule": rule_name,
                    "instances": []
                }
                for (off, data_bytes) in inst_list:
                    abs_off = start + off
                    snip, snip_va = extract_snippet(region, off, len(data_bytes), start)

                    hexd = hex_dump(snip_va, snip)
                    dis  = disassemble_snippet(arch, snip, snip_va)

                    g["instances"].append({
                        "absolute_offset": hex(abs_off),
                        "relative_offset": off,
                        "length": len(data_bytes),
                        "snippet_va": hex(snip_va),
                        "snippet_hex": " ".join(f"{b:02x}" for b in snip),
                        "snippet_b64": base64.b64encode(snip).decode(),
                        "hexdump": hexd,
                        "disassembly": dis
                    })

                reg_info["matches"].append(g)

        out["regions"].append(reg_info)

    # FD scan
    if not no_fd:
        fdpath = f"/proc/{pid}/fd"
        if os.path.isdir(fdpath):
            for fd in os.listdir(fdpath):
                full = os.path.join(fdpath, fd)
                try:
                    target = os.readlink(full)
                except:
                    continue

                if target.startswith(("pipe:", "socket:")):
                    continue

                try:
                    with open(full, "rb") as f:
                        data = f.read(max_read)
                except:
                    continue

                try:
                    fm = rules.match(data=data)
                except:
                    continue

                if fm:
                    out["fd_matches"].append({
                        "fd": fd,
                        "target": target,
                        "rules": [m.rule for m in fm]
                    })

    return out


# =====================================================================
# Injection indicator scan (maps + smaps)
# =====================================================================

def detect_injection_indicators(pid):
    out = []
    mpath = f"/proc/{pid}/maps"
    spath = f"/proc/{pid}/smaps"

    try:
        with open(mpath) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr, perms, _, _, inode = parts[:5]
                path = parts[5] if len(parts) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    out.append(f"RWX region: {addr}")
                if "x" in perms and inode == "0":
                    out.append(f"Anonymous exec: {addr} {path}")
                if "memfd:" in path and "x" in perms:
                    out.append(f"memfd exec: {addr} {path}")
    except:
        pass

    try:
        with open(spath) as f:
            cur = None
            for line in f:
                if "-" in line and ":" not in line:
                    cur = line.split()[0]
                if line.startswith("VmFlags:"):
                    flags = line.split(":")[1].strip().split()
                    if "ex" in flags and ("mw" in flags or "mr" in flags):
                        out.append(f"VmFlags RW→RX: {cur}")
    except:
        pass

    return out


# =====================================================================
# Main
# =====================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--rule", required=True)
    ap.add_argument("--max-read", type=int, default=5 * 1024 * 1024)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--no-fd-scan", action="store_true")
    ap.add_argument("--json", help="Write full JSON output")
    args = ap.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # Phase 1
    matches = phase1(rules, args.threads)
    if not matches:
        print(Fore.YELLOW + "[*] No PID matches. Exiting.")
        return

    # Phase 2
    jobs = [(pid, args.rule, args.max_read, args.no_fd_scan) for pid in matches.keys()]

    print(Fore.CYAN + f"[*] Phase 2 — deep scan of {len(jobs)} processes...\n")

    deep = {}

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(deep_worker, j): j[0] for j in jobs}

        for fut in as_completed(futs):
            pid = futs[fut]
            try:
                res = fut.result()
                deep[pid] = res
                print(Fore.GREEN + f"[+] Deep scan complete for PID {pid}")
            except Exception as e:
                print(Fore.RED + f"[!] Worker crash for PID {pid}: {e}")

    print(Fore.CYAN + "\n[*] All deep scans completed.\n")

    # JSON
    if args.json:
        print(Fore.CYAN + f"[*] Writing JSON → {args.json}")
        try:
            with open(args.json, "w") as f:
                json.dump(deep, f, indent=2)
            print(Fore.GREEN + "[+] JSON saved.")
        except Exception as e:
            print(Fore.RED + f"[!] JSON error: {e}")

    print(Fore.GREEN + "\n[*] DONE.\n")


if __name__ == "__main__":
    main()