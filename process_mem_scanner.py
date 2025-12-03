#!/usr/bin/env python3
"""
process_mem_scanner_v5.6 — Hybrid YARA Memory Scanner (JSON + progress + meta)

BASELINE:
  - This is built directly on top of your last working v5.1 code.
  - Phase 1: YARA native PID scan (rules.match(pid=pid)) — threaded, with progress bar.
  - Phase 2: For each matched PID:
        * Enumerate /proc/<pid>/maps
        * Read memory from /proc/<pid>/mem
        * Re-scan each region with YARA
        * Print:
              - region address / perms
              - entropy
              - rule name + META
              - string matches with:
                    String $id: offset=0x... len=...
                    Hex dump (256 bytes around match, match highlighted in RED)
                    Disassembly (Capstone) around match, match highlighted in RED
        * Optional FD scan (/proc/<pid>/fd), unless --no-fd-scan

ADDED IN v5.6:
  - Skip scanning our own process and parent PID in Phase 1.
  - Phase 1 progress bar: "Scanning processes | X/Y [++++----]".
  - Optional JSON report via --json-report:
        * Per-matched PID, store:
            - Process metadata (pid, name, exe, cmdline, sha256)
            - Injection indicators
            - Regions:
                - address, perms, entropy
                - For each YARA rule:
                      rule name
                      rule meta
                      For each string id:
                          instances with:
                              absolute_offset, relative_offset, length
                              hex_dump (list of lines, plain text)
                              disassembly (list of lines, plain text)
            - FD matches (fd, target, rules, optional dump file)
  - JSON report does NOT contain ANSI color codes — only plain text.

YARA:
  - Tested logic is compatible with yara-python 4.5.4:
        match.strings -> [StringMatch]
        StringMatch.identifier
        StringMatch.instances -> [StringMatchInstance]
        StringMatchInstance.offset
        StringMatchInstance.matched_data
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
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()


def shannon_entropy(data: bytes) -> float:
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


def hex_dump_highlight(data: bytes, base: int, match_off: int, match_len: int, ctx=256):
    """
    Print the same hex dump as v5.1, with match highlighted in RED.
    Also return a list of plain-text lines for JSON (no color).
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
        hex_parts_plain = []
        ascii_parts_colored = []
        ascii_parts_plain = []

        for j, b in enumerate(line):
            gi = start + i + j
            in_range = match_off <= gi < match_off + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."

            if in_range:
                hx_col = Fore.RED + hx + Style.RESET_ALL
                ch_col = Fore.RED + ch + Style.RESET_ALL
            else:
                hx_col = hx
                ch_col = ch

            hex_parts_colored.append(hx_col)
            ascii_parts_colored.append(ch_col)
            hex_parts_plain.append(hx)
            ascii_parts_plain.append(ch)

        colored_line = (
            f"        0x{snippet_base + i:016x}  "
            f"{' '.join(hex_parts_colored):<48}  {''.join(ascii_parts_colored)}"
        )
        plain_line = (
            f"0x{snippet_base + i:016x}  "
            f"{' '.join(hex_parts_plain):<48}  {''.join(ascii_parts_plain)}"
        )

        print(colored_line)
        plain_lines.append(plain_line)

    return plain_lines


def disasm_fragment(region: bytes,
                    base: int,
                    match_off: int,
                    match_len: int,
                    arch: str,
                    ctx: int = 128):
    """
    Disassemble a small fragment around the match (like v5.1).
    Print to console with RED highlight for instructions that fall
    inside the matched range.
    Also return a list of plain-text lines for JSON.
    """
    md = get_disassembler(arch)

    ctx_start = max(0, match_off - ctx)
    ctx_end = min(len(region), match_off + match_len + ctx)
    code = region[ctx_start:ctx_end]

    print("\n    Disassembly:")
    plain_lines = []

    try:
        for ins in md.disasm(code, base + ctx_start):
            high = (base + match_off <= ins.address < base + match_off + match_len)
            prefix = ">>" if high else "  "
            line = f"{prefix} 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}"
            plain_lines.append(line)

            color = Fore.RED if high else ""
            print(color + f"      {line}")
    except Exception:
        msg = "      <failed disassembly>"
        print(msg)
        plain_lines.append("<failed disassembly>")

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
# Deep Scan of Memory Regions
# ======================================================================

def deep_scan_memory(pid, rules, dump_dir, max_read, json_proc_entry=None):
    """
    Phase 2: exact same console behavior as v5.1, PLUS
    populate json_proc_entry["regions"] with all region/match details.
    """
    maps_path = f"/proc/{pid}/maps"
    try:
        maps = open(maps_path).read().splitlines()
    except Exception:
        return

    print(Fore.YELLOW + "\n[*] Deep scanning memory maps...")

    arch = "x86_64"
    try:
        exe_path = psutil.Process(pid).exe()
        arch = detect_arch(exe_path)
    except Exception:
        pass

    if json_proc_entry is not None and "regions" not in json_proc_entry:
        json_proc_entry["regions"] = []

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

        region_entry = {
            "address": addr_range,
            "perms": perms,
            "entropy": entropy,
            "matches": []
        }

        for m in matches:
            print(Fore.MAGENTA + f"    Rule: {m.rule}")
            # Print META and store it as well
            if m.meta:
                meta_str = ", ".join(f"{k}='{v}'" for k, v in m.meta.items())
                print(f"      Meta: {meta_str}")
            else:
                meta_str = ""
                print("      Meta: <none>")

            rule_entry = {
                "rule": m.rule,
                "meta": m.meta,
                "strings": []
            }

            for s in m.strings:
                ident = s.identifier
                string_entry = {
                    "identifier": ident,
                    "instances": []
                }

                for inst in s.instances:
                    off = inst.offset
                    mlen = len(inst.matched_data)
                    abs_off = start + off

                    print(Fore.CYAN + f"\n    String {ident}: offset={hex(abs_off)} len={mlen}")

                    # Hex dump (console + JSON)
                    hex_lines = hex_dump_highlight(region, start, off, mlen)

                    # Disassembly (console + JSON)
                    disasm_lines = disasm_fragment(region, start, off, mlen, arch)

                    inst_entry = {
                        "absolute_offset": hex(abs_off),
                        "relative_offset": off,
                        "length": mlen,
                        "hex_dump": hex_lines,
                        "disassembly": disasm_lines,
                    }
                    string_entry["instances"].append(inst_entry)

                    # Dump entire region once if requested
                    if dump_dir:
                        outdir = os.path.join(dump_dir, f"pid_{pid}")
                        os.makedirs(outdir, exist_ok=True)
                        path = os.path.join(outdir, f"region_{addr_range.replace('-', '_')}.bin")
                        if "dump_file" not in region_entry:
                            try:
                                with open(path, "wb") as f:
                                    f.write(region)
                                region_entry["dump_file"] = path
                                print(Fore.GREEN + f"    Dumped region to: {path}")
                            except Exception:
                                pass

                rule_entry["strings"].append(string_entry)

            region_entry["matches"].append(rule_entry)

        if json_proc_entry is not None:
            json_proc_entry["regions"].append(region_entry)


# ======================================================================
# FD (memfd) scan
# ======================================================================

def scan_fds(pid, rules, dump_dir, max_read, json_proc_entry=None):
    fd_path = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_path):
        return

    print(Fore.YELLOW + "\n[*] Scanning file descriptors...")

    if json_proc_entry is not None and "fd_matches" not in json_proc_entry:
        json_proc_entry["fd_matches"] = []

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

            entry = {
                "fd": fd,
                "target": target,
                "rules": rule_names
            }

            if dump_dir:
                out = os.path.join(dump_dir, f"pid_{pid}")
                os.makedirs(out, exist_ok=True)
                p = os.path.join(out, f"fd_{fd}.bin")
                try:
                    with open(p, "wb") as f:
                        f.write(data)
                    print(Fore.GREEN + f"    Dumped FD: {p}")
                    entry["dump_file"] = p
                except Exception:
                    pass

            if json_proc_entry is not None:
                json_proc_entry["fd_matches"].append(entry)


# ======================================================================
# Progress bar for Phase 1
# ======================================================================

def print_progress(current, total, bar_width=50):
    ratio = current / total if total else 1.0
    filled = int(bar_width * ratio)
    bar = "+" * filled + "-" * (bar_width - filled)
    line = f"\rScanning processes | {current}/{total} [{bar}]"
    # Print without newline; flush to update in-place
    sys.stdout.write(line)
    sys.stdout.flush()
    if current == total:
        print()  # final newline


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid YARA Memory Scanner v5.6 (threaded + JSON)"
    )
    parser.add_argument("-r", "--rule", required=True, help="YARA rule file")
    parser.add_argument("--dump-dir", help="Dump directory for matched regions/FDs")
    parser.add_argument("--max-read", type=int, default=5*1024*1024,
                        help="Max bytes to read per region/FD")
    parser.add_argument("--threads", type=int, default=4,
                        help="Number of threads for Phase 1 PID scan")
    parser.add_argument("--no-fd-scan", action="store_true",
                        help="Disable scanning /proc/<pid>/fd descriptors (faster)")
    parser.add_argument("--json-report",
                        help="Write full forensic JSON output to this file")
    args = parser.parse_args()

    print(Fore.CYAN + f"[*] Loading YARA: {args.rule}\n")
    rules = yara.compile(filepath=args.rule)

    self_pid = os.getpid()
    parent_pid = os.getppid()

    print("[*] Enumerating processes...")
    pids = [p.pid for p in psutil.process_iter()]
    # Skip our own process and parent to avoid self matches
    pids = [pid for pid in pids if pid not in (self_pid, parent_pid)]
    total = len(pids)
    print(f"[*] {total} processes found\n")

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

    done = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_one, pid): pid for pid in pids}
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
                    f"    Rules: {rule_names}\n"
                )

    print(f"[*] Phase 1 done. Matched {len(matched)} processes.\n")

    if not matched:
        if args.json_report:
            # Still write an empty report for completeness
            report = {
                "generated_at": now_iso(),
                "rule_file": args.rule,
                "matched_processes": []
            }
            try:
                with open(args.json_report, "w") as jf:
                    json.dump(report, jf, indent=2)
                print(Fore.CYAN + f"[*] JSON report written → {args.json_report}")
            except Exception as e:
                print(Fore.RED + f"[!] Failed to write JSON report: {e}")
        print("[*] DONE (no matches).")
        return

    # --------------------------------------------------------------
    # PHASE 2 — deep forensics per matched PID
    # --------------------------------------------------------------
    json_results = {}

    for pid, yara_matches in matched.items():
        print(Fore.CYAN + f"\n==================== PID {pid} ====================")

        proc_entry = {
            "pid": pid,
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
            proc_entry["name"] = "<unknown>"
            proc_entry["exe"] = "<unknown>"
            proc_entry["cmdline"] = "<unknown>"
            proc_entry["sha256"] = None

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
        deep_scan_memory(pid, rules, args.dump_dir, args.max_read, json_proc_entry=proc_entry)

        # FD scanning (optional)
        if not args.no_fd_scan:
            scan_fds(pid, rules, args.dump_dir, args.max_read, json_proc_entry=proc_entry)
        else:
            print(Fore.YELLOW + "Skipping FD scan (--no-fd-scan enabled)")

        print(Fore.CYAN + f"\n====================================================\n")

        json_results[pid] = proc_entry

    # --------------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------------
    if args.json_report:
        report = {
            "generated_at": now_iso(),
            "rule_file": args.rule,
            "matched_processes": list(json_results.values())
        }
        try:
            with open(args.json_report, "w") as jf:
                json.dump(report, jf, indent=2)
            print(Fore.CYAN + f"[*] JSON report written → {args.json_report}")
        except Exception as e:
            print(Fore.RED + f"[!] Failed to write JSON report: {e}")

    print("[*] DONE.")


if __name__ == "__main__":
    main()