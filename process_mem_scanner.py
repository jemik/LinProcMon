#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — PART 1/3
Forensic-grade hybrid YARA memory scanner
SNIPPET = 256 bytes (128 before + match + 128 after)
DISASM  = full snippet
"""

import os
import sys
import yara
import psutil
import argparse
import struct
import hashlib
import base64
import math
import json
import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from colorama import Fore, Style, init as colorama_init
from capstone import *

colorama_init(autoreset=True)

SNIPPET_BEFORE = 128
SNIPPET_AFTER  = 128
SNIPPET_TOTAL  = SNIPPET_BEFORE + SNIPPET_AFTER

# ======================================================================
# Utility functions
# ======================================================================

def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()

# ------------------------------
# Entropy (Shannon)
# ------------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freqs.values()]
    return -sum(p * math.log2(p) for p in probs)

# ------------------------------
# SHA256 of executable
# ------------------------------
def compute_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

# ======================================================================
# ARCHITECTURE DETECTION
# ======================================================================
def detect_arch(exe_path: str) -> str:
    """
    Detect architecture from ELF header.
    Default to x86_64 if uncertain.
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

    if ei_class == 2:  # 64-bit
        if e_machine == 0x3E:   # EM_X86_64
            return "x86_64"
        if e_machine == 0xB7:   # EM_AARCH64
            return "arm64"
    else:
        if e_machine == 0x03:   # EM_386
            return "x86"
        if e_machine == 0x28:   # EM_ARM
            return "arm"

    return "x86_64"

def get_disassembler(arch: str):
    if arch == "x86_64": return Cs(CS_ARCH_X86, CS_MODE_64)
    if arch == "x86":    return Cs(CS_ARCH_X86, CS_MODE_32)
    if arch == "arm64":  return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    if arch == "arm":    return Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return Cs(CS_ARCH_X86, CS_MODE_64)

# ======================================================================
# HEX DUMP FORMATTER
# ======================================================================
def format_hex_dump(base_addr: int, data: bytes, bytes_per_line=16) -> str:
    """
    Produces a multi-line hex dump with printable ASCII.
    Example:
        0x00007ffee651eba0  41 42 43 44 ...
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr = base_addr + i
        lines.append(f"        0x{addr:016x}  {hex_part:<48}  {asc_part}")
    return "\n".join(lines)

# ======================================================================
# SHELLCODE INSTRUCTION HIGHLIGHTER
# ======================================================================
def is_shellcode_instruction(insn):
    """
    Return True if instruction looks like shellcode.

    Examples:
        push 0x3b
        movabs rbx, '/bin/sh'
        syscall, int 0x80
        cdq / xor rdx,rdx / xor esi,esi
        call rax / jmp rsp
    """
    mnem = insn.mnemonic.lower()
    op = insn.op_str.lower()

    # Execve shellcode markers
    if mnem == "push" and "0x3b" in op:
        return True
    if mnem == "movabs" and ("/bin/sh" in insn.op_str or "68732f6e69622f" in insn.op_str):
        return True
    if mnem in ("syscall", "int") and ("0x80" in op or "80" in op):
        return True

    # Typical prep instructions
    if mnem == "cdq":
        return True
    if mnem == "xor" and ("rdx" in op or "esi" in op):
        return True

    # Indirect transfers
    if mnem in ("jmp", "call") and ("rax" in op or "rsp" in op):
        return True

    return False

# ======================================================================
# DISASSEMBLY OF SNIPPET
# ======================================================================
def disassemble_snippet(arch: str, snippet: bytes, base_va: int):
    """
    Disassemble entire snippet with Capstone.
    Each returned entry is:
        { "addr": int, "mnemonic": "...", "op_str": "...", "highlight": bool }
    """
    md = get_disassembler(arch)
    md.detail = False

    out = []
    try:
        for insn in md.disasm(snippet, base_va):
            out.append({
                "addr": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "highlight": is_shellcode_instruction(insn)
            })
    except Exception:
        pass

    return out

# ======================================================================
# SNIPPET EXTRACTION
# ======================================================================
def extract_snippet(region: bytes, match_offset: int, region_start_va: int, match_len: int):
    """
    Extract 128 bytes before + match + 128 bytes after.
    Also compute:
        snippet_bytes
        snippet_va
        hex dump
        base64
        disassembly (full snippet)
    """
    start = max(0, match_offset - SNIPPET_BEFORE)
    end   = min(len(region), match_offset + match_len + SNIPPET_AFTER)
    snippet = region[start:end]

    snippet_va = region_start_va + start

    # Prepare hex representation
    snippet_hex = " ".join(f"{b:02x}" for b in snippet)
    snippet_b64 = base64.b64encode(snippet).decode()

    return snippet, snippet_hex, snippet_b64, snippet_va

# ======================================================================
# DETECT MEMORY INJECTION PATTERNS
# ======================================================================
def detect_injection_indicators(pid: int):
    indicators = []
    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

    # RWX, anonymous exec, memfd exec
    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                addr, perms, _, _, inode = parts[:5]
                path = parts[5] if len(parts) >= 6 else ""

                if "r" in perms and "w" in perms and "x" in perms:
                    indicators.append(f"RWX region: {addr} {perms}")

                if "x" in perms and inode == "0" and path in ("", "0"):
                    indicators.append(f"Anonymous executable region: {addr}")

                if "x" in perms and "memfd:" in path:
                    indicators.append(f"memfd executable region: {addr} {path}")
    except Exception:
        pass

    # VmFlags → RX transitions
    try:
        current = None
        with open(smaps_path, "r") as f:
            for line in f:
                if "-" in line and ":" not in line:
                    current = line.split()[0]
                if line.startswith("VmFlags:"):
                    flags = line.split(":")[1].strip().split()
                    if "ex" in flags and ("mr" in flags or "mw" in flags):
                        indicators.append(f"VmFlags RW→RX: {current}")
    except Exception:
        pass

    return indicators

# ======================================================================
# PART 2 — DEEP SCAN WORKER + MATCH SERIALIZATION
# ======================================================================

import base64

def serialize_snippet(snippet_bytes):
    """Return both HEX and Base64 representations."""
    hex_str = " ".join(f"{b:02x}" for b in snippet_bytes)
    b64_str = base64.b64encode(snippet_bytes).decode()
    return hex_str, b64_str


def deep_worker(args):
    """
    Multiprocess deep scan worker.
    Inputs:
        pid, rule_path, dump_dir, max_read, no_fd_scan
    Returns:
        Dictionary with all forensic details for this PID
    """
    pid, rule_path, dump_dir, max_read, no_fd_scan = args

    result = {
        "pid": pid,
        "regions": [],
        "fd_matches": [],
        "injection_indicators": [],
        "errors": []
    }

    # Load YARA rules in this subprocess
    try:
        rules = yara.compile(filepath=rule_path)
    except Exception as e:
        result["errors"].append(f"rule_compile: {e}")
        return result

    # Identify architecture for disassembly
    try:
        exe_path = psutil.Process(pid).exe()
        arch = detect_arch(exe_path)
    except Exception:
        arch = "x86_64"
    dis = get_disassembler(arch)

    # Injection indicators
    result["injection_indicators"] = detect_injection_indicators(pid)

    # Read /proc/<pid>/maps
    try:
        with open(f"/proc/{pid}/maps") as f:
            maps = f.read().splitlines()
    except Exception as e:
        result["errors"].append(f"maps: {e}")
        return result

    # -----------------------
    # Scan each memory region
    # -----------------------
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

        region_bytes = read_region(pid, start, size, max_read)
        if not region_bytes:
            continue

        # Run YARA on this region
        try:
            mem_matches = rules.match(data=region_bytes)
        except Exception:
            continue
        if not mem_matches:
            continue

        region_info = {
            "address": addr_range,
            "perms": perms,
            "entropy": shannon_entropy(region_bytes),
            "matches": []
        }

        # Group matches by string identifier ("$opcode", "$string_1", etc.)
        grouped = {}  # {string_id: [instances]}
        for match in mem_matches:
            for s in match.strings:
                sid = s.identifier
                if sid not in grouped:
                    grouped[sid] = []
                grouped[sid].extend(s.instances)

        # Process grouped matches
        for sid, instances in grouped.items():
            grouped_entry = {
                "string_id": sid,
                "instances": []
            }

            for inst in instances:
                abs_off = start + inst.offset

                # Extract our 256B snippet (128 before + match + 128 after)
                snip_va, snip_bytes = extract_snippet(
                    region_bytes, start, inst.offset, len(inst.matched_data)
                )

                # Build hex dump text block
                hexdump_lines = build_hexdump(snip_bytes, base_addr=snip_va)

                # Disassemble entire snippet
                disasm_lines = build_disassembly(dis, snip_bytes, snip_va)

                # Serialize snippet for JSON
                hex_snip, b64_snip = serialize_snippet(snip_bytes)

                inst_entry = {
                    "absolute_offset": hex(abs_off),
                    "relative_offset": inst.offset,
                    "length": len(inst.matched_data),
                    "snippet_va": hex(snip_va),
                    "snippet_hex": hex_snip,
                    "snippet_b64": b64_snip,
                    "hexdump": hexdump_lines,
                    "disassembly": disasm_lines
                }
                grouped_entry["instances"].append(inst_entry)

            region_info["matches"].append(grouped_entry)

        # Dump entire region if requested
        if dump_dir:
            try:
                out_dir = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(out_dir, exist_ok=True)
                dump_file = os.path.join(out_dir, f"region_{addr_range.replace('-', '_')}.bin")
                with open(dump_file, "wb") as f:
                    f.write(region_bytes)
                region_info["dump_file"] = dump_file
            except Exception as e:
                result["errors"].append(f"dump: {e}")

        result["regions"].append(region_info)

    # -----------------------
    # FD Scanning (optional)
    # -----------------------
    if not no_fd_scan:
        fd_dir = f"/proc/{pid}/fd"
        if os.path.isdir(fd_dir):
            for fd in os.listdir(fd_dir):
                full_fd = os.path.join(fd_dir, fd)

                try:
                    target = os.readlink(full_fd)
                except Exception:
                    continue

                if target.startswith(("pipe:", "socket:")):
                    continue

                try:
                    with open(full_fd, "rb") as f:
                        fd_bytes = f.read(max_read)
                except Exception:
                    continue

                try:
                    fd_yara = rules.match(data=fd_bytes)
                except Exception:
                    continue

                if fd_yara:
                    entry = {
                        "fd": fd,
                        "target": target,
                        "rules": [m.rule for m in fd_yara]
                    }

                    if dump_dir:
                        try:
                            out_dir = os.path.join(dump_dir, f"pid_{pid}")
                            os.makedirs(out_dir, exist_ok=True)
                            dump_file = os.path.join(out_dir, f"fd_{fd}.bin")
                            with open(dump_file, "wb") as f:
                                f.write(fd_bytes)
                            entry["dump_file"] = dump_file
                        except Exception as e:
                            result["errors"].append(f"fd_dump: {e}")

                    result["fd_matches"].append(entry)

    return result

# ================================================================
#  PART 3/3 — SECTION 1
#  MAIN SCANNER LOGIC — PHASE 1 (YARA PID SCAN)
# ================================================================

def scan_pid_with_yara(rules, pid, self_pid, parent_pid):
    """
    ThreadPool helper for Phase 1.
    Returns (pid, matches_list OR None)
    """
    if pid == self_pid or pid == parent_pid:
        return pid, None

    try:
        matches = rules.match(pid=pid)
        if matches:
            return pid, matches
        return pid, None
    except Exception:
        return pid, None


def phase1_scan(rules, threads, self_pid, parent_pid):
    """
    Perform threaded YARA scanning across all PIDs.
    Returns dict: { pid: [matches] }
    """
    print(Fore.CYAN + "[*] Phase 1 — threaded YARA PID scan\n")

    pids = [p.pid for p in psutil.process_iter()]
    print(f"[*] Found {len(pids)} processes.")

    matched = {}

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {
            exe.submit(scan_pid_with_yara, rules, pid, self_pid, parent_pid): pid
            for pid in pids
        }

        for fut in as_completed(futures):
            pid, result = fut.result()

            if result:
                matched[pid] = result

                # Collect process metadata for printing
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe_path = proc.exe()
                    cmd = " ".join(proc.cmdline())
                    sha = compute_sha256(exe_path)
                except Exception:
                    name = exe_path = cmd = "<unknown>"
                    sha = None

                rule_names = [m.rule for m in result]

                print(
                    Fore.GREEN +
                    f"[+] Match in PID {pid} | Name={name} | EXE={exe_path}\n"
                    f"    CMD={cmd}\n"
                    f"    SHA256={sha}\n"
                    f"    Rules={rule_names}\n"
                )

    print(Fore.CYAN + f"\n[*] Phase 1 complete — {len(matched)} matched processes.\n")
    return matched


# ================================================================
#  TASK PREPARATION FOR PHASE 2 (Deep Worker Jobs)
# ================================================================

def prepare_phase2_tasks(matched, rule_path, dump_dir, max_read, no_fd_scan, self_pid, parent_pid):
    """
    Build the list of (pid, rule_path, dump_dir, max_read, no_fd_scan)
    for ProcessPool deep scanning.
    """
    tasks = []
    for pid in matched:
        if pid in (self_pid, parent_pid):
            continue
        tasks.append((pid, rule_path, dump_dir, max_read, no_fd_scan))
    return tasks


# ================================================================
#  MAIN()
# ================================================================

def main():
    parser = argparse.ArgumentParser(
        description="process_mem_scanner_v5.6 — full forensic YARA memory scanner"
    )

    parser.add_argument("-r", "--rule", required=True)
    parser.add_argument("--dump-dir")
    parser.add_argument("--max-read", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--threads", type=int, default=6)
    parser.add_argument("--deep-workers", type=int, default=4)
    parser.add_argument("--no-fd-scan", action="true_false",
                        help="Disable scanning /proc/PID/fd/*")
    parser.add_argument("--json-report", help="Write full forensic JSON output")

    args = parser.parse_args()

    # ------------------------------------------------------------
    # Load YARA rule
    # ------------------------------------------------------------
    print(Fore.CYAN + f"[*] Loading YARA rule: {args.rule}")
    rules = yara.compile(filepath=args.rule)

    # ------------------------------------------------------------
    # Self PIDs
    # ------------------------------------------------------------
    self_pid = os.getpid()
    parent_pid = os.getppid()
    print(Fore.CYAN + f"[*] Scanner PID={self_pid}, parent={parent_pid}\n")

    # ------------------------------------------------------------
    # Phase 1 scan
    # ------------------------------------------------------------
    matched = phase1_scan(
        rules,
        args.threads,
        self_pid,
        parent_pid
    )

    if not matched:
        print(Fore.YELLOW + "[*] No YARA PID matches found — exiting.\n")
        return

    # ------------------------------------------------------------
    # Build Phase 2 task list
    # ------------------------------------------------------------
    print(Fore.CYAN + "[*] Preparing Phase 2 deep scan tasks...\n")

    tasks = prepare_phase2_tasks(
        matched,
        args.rule,
        args.dump_dir,
        args.max_read,
        args.no_fd_scan,
        self_pid,
        parent_pid
    )

    print(Fore.CYAN + f"[*] {len(tasks)} processes scheduled for deep scanning.\n")

    # Hand off to Part 3/3 Section 2 next…
    run_phase2(tasks, args, matched)   # <---- implemented in SECTION 2

    # ======================================================================
    # JSON REPORT GENERATION
    # ======================================================================

    if args.json_report:
        print(Fore.CYAN + f"\n[*] Writing JSON report → {args.json_report}")

        json_report = {
            "timestamp": now_iso(),
            "scanner_pid": self_pid,
            "scanner_parent_pid": parent_pid,
            "rule_file": args.rule,
            "matched_pids": [],
        }

        for pid, deep in deep_results.items():
            proc_entry = {}

            # -------------------------
            # Process metadata
            # -------------------------
            try:
                proc = psutil.Process(pid)
                proc_entry["pid"] = pid
                proc_entry["name"] = proc.name()
                proc_entry["exe"] = proc.exe()
                proc_entry["cmdline"] = " ".join(proc.cmdline())
                proc_entry["sha256"] = compute_sha256(proc.exe())
            except Exception:
                proc_entry["pid"] = pid
                proc_entry["name"] = "<unknown>"
                proc_entry["exe"] = "<unknown>"
                proc_entry["cmdline"] = "<unknown>"
                proc_entry["sha256"] = None

            # -------------------------
            # Injection indicators
            # -------------------------
            proc_entry["injection_indicators"] = (
                deep.get("injection_indicators") or []
            )

            # -------------------------
            # FD matches
            # -------------------------
            proc_entry["fd_matches"] = deep.get("fd_matches") or []

            # -------------------------
            # Memory regions + matches
            # -------------------------
            final_regions = []
            for region in deep.get("regions", []):
                region_entry = {
                    "address": region["address"],
                    "perms": region["perms"],
                    "entropy": region["entropy"],
                    "dump_file": region.get("dump_file"),
                    "matches": [],
                }

                # matches grouped by string ID
                for string_id, match_list in region.get("matches", {}).items():
                    for inst in match_list:
                        region_entry["matches"].append({
                            "string": string_id,
                            "rule": inst["rule"],
                            "absolute_offset": inst["absolute_offset"],
                            "length": inst["length"],
                            "snippet_virtual_address": inst["snippet_va"],
                            "snippet_hex": inst["snippet_hex"],
                            "snippet_b64": inst["snippet_b64"],
                            "disassembly": inst["disassembly"],
                        })

                final_regions.append(region_entry)

            proc_entry["regions"] = final_regions
            json_report["matched_pids"].append(proc_entry)

        # -----------------------------
        # Write JSON to disk
        # -----------------------------
        try:
            with open(args.json_report, "w") as jf:
                json.dump(json_report, jf, indent=2)
            print(Fore.GREEN + f"[+] JSON report saved successfully")
        except Exception as e:
            print(Fore.RED + f"[!] Failed writing JSON: {e}")

    # ======================================================================
    # FINAL SUMMARY
    # ======================================================================

    print(Fore.CYAN + "\n===================== SUMMARY =====================")
    print(Fore.CYAN + f"Matched processes: {len(matches)}")
    print(Fore.CYAN + f"Deep-scanned: {len(deep_results)}")

    for pid in deep_results:
        print(Fore.GREEN + f"  • PID {pid}: deep scan complete")

    print(Fore.CYAN + "====================================================\n")

    print(Fore.GREEN + "[*] Scan complete.\n")


# ======================================================================
# ENTRYPOINT
# ======================================================================

if __name__ == "__main__":
    main()