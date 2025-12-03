#!/usr/bin/env python3
"""
process_mem_scanner.py

Linux process memory scanner using YARA.
Features:
- Scans all readable memory regions from /proc/<pid>/mem
- Prints PID, PPID, path, cmdline, SHA256
- Shows parent and children
- Shows YARA matches with offset and 256 bytes around match
- Highlights matched bytes in RED
- Skips scanning itself (and its parent)
"""

import argparse
import os
import sys
import time
import datetime
import hashlib

import psutil
import yara
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------

def compute_sha256(path):
    """Return SHA256 of file or None."""
    if not path or not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def get_process_info(proc: psutil.Process):
    """Return info about process as dict."""
    info = {
        "pid": None,
        "ppid": None,
        "exe": None,
        "cmdline": None,
        "name": None,
        "sha256": None,
    }
    try:
        info["pid"] = proc.pid
        info["ppid"] = proc.ppid()
        info["exe"] = proc.exe()
        info["cmdline"] = " ".join(proc.cmdline())
        info["name"] = proc.name()
        info["sha256"] = compute_sha256(info["exe"])
    except Exception:
        pass
    return info


def print_process_info(title, info, indent=""):
    print(f"{indent}{title}:")
    if not info:
        print(f"{indent}  <unavailable>")
        return

    print(f"{indent}  PID   : {info.get('pid')}")
    print(f"{indent}  Name  : {info.get('name')}")
    print(f"{indent}  PPID  : {info.get('ppid')}")
    print(f"{indent}  EXE   : {info.get('exe')}")
    print(f"{indent}  CMD   : {info.get('cmdline')}")
    print(f"{indent}  SHA256: {info.get('sha256')}")


def hex_dump_with_highlight(data: bytes, base_addr: int, match_offset: int,
                            match_len: int, context_bytes: int = 256):
    """
    Dump hex around matched bytes (256 bytes) with red highlighting.
    """
    half = context_bytes // 2
    start = max(0, match_offset - half)
    end = min(len(data), match_offset + match_len + half)

    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"      Hex dump (0x{snippet_base:016x} - 0x{snippet_base + len(snippet):016x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i + 16]
        addr = snippet_base + i

        hex_parts = []
        ascii_parts = []

        for j, b in enumerate(line):
            global_index = start + i + j
            in_match = match_offset <= global_index < match_offset + match_len

            h = f"{b:02x}"
            c = chr(b) if 32 <= b <= 126 else "."

            if in_match:
                h = Fore.RED + h + Style.RESET_ALL
                c = Fore.RED + c + Style.RESET_ALL

            hex_parts.append(h)
            ascii_parts.append(c)

        hex_str = " ".join(hex_parts)
        ascii_str = "".join(ascii_parts)

        print(f"        0x{addr:016x}  {hex_str:<48}  {ascii_str}")


# ----------------------------------------------------------------------
# Memory Scanning
# ----------------------------------------------------------------------

def scan_process(pid: int, rules, max_region_size: int):
    """Scan memory regions for a single PID. Returns match tuples."""
    results = []

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return []

    try:
        maps_f = open(maps_path, "r")
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        return []

    with maps_f, mem_f:
        for line in maps_f:
            parts = line.split()
            if len(parts) < 2:
                continue

            addr_range = parts[0]
            perms = parts[1]

            if "r" not in perms:
                continue

            start_s, end_s = addr_range.split("-")
            region_start = int(start_s, 16)
            region_end = int(end_s, 16)
            region_size = region_end - region_start

            if region_size <= 0:
                continue

            read_size = min(region_size, max_region_size)

            try:
                mem_f.seek(region_start)
                region_data = mem_f.read(read_size)
            except Exception:
                continue

            if not region_data:
                continue

            try:
                rule_matches = rules.match(data=region_data)
            except Exception:
                continue

            if not rule_matches:
                continue

            pinfo = get_process_info(proc)

            for m in rule_matches:
                results.append((m, pinfo, region_start, region_data))

    return results


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan Linux processes with YARA and show memory offsets + context."
    )
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule file")
    parser.add_argument("--max-region-size", type=int, default=50 * 1024 * 1024,
                        help="Max bytes per memory region (default 50MB)")
    args = parser.parse_args()

    # Load YARA rules
    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to compile YARA: {e}")
        sys.exit(1)

    print(f"[*] Loaded YARA rules from {args.rule}")
    print("[*] Scanning processes...\n")

    current_pid = os.getpid()
    parent_pid = os.getppid()

    for proc in psutil.process_iter(attrs=["pid"]):
        pid = proc.info["pid"]

        # Skip own scanner and parent shell
        if pid == current_pid or pid == parent_pid:
            continue

        try:
            matches = scan_process(pid, rules, args.max_region_size)
        except Exception:
            continue

        if not matches:
            continue

        # Build process structure
        try:
            p = psutil.Process(pid)
        except Exception:
            continue

        proc_info = get_process_info(p)

        # Parent
        parent_info = None
        try:
            parent = p.parent()
            if parent:
                parent_info = get_process_info(parent)
        except Exception:
            pass

        # Children
        children_info = []
        try:
            for ch in p.children(recursive=False):
                children_info.append(get_process_info(ch))
        except Exception:
            pass

        timestamp = datetime.datetime.now().isoformat(timespec="seconds")
        print(Fore.CYAN + f"[{timestamp}] Match in process PID {pid}")
        print_process_info("Process", proc_info)
        print_process_info("Parent", parent_info)
        print()

        if children_info:
            print("Children:")
            for ci in children_info:
                print_process_info(f"  Child PID {ci['pid']}", ci, indent="  ")
            print()
        else:
            print("Children: <none>\n")

        # Handle each match
        for m, pinfo, region_base, region_data in matches:
            print(Fore.MAGENTA + f"  YARA Rule Matched: {m.rule} (namespace={m.namespace})")

            if m.meta:
                meta_str = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"    Meta: {meta_str}")

            # Correct handling of StringMatch objects
            for s in m.strings:
                off = s.offset
                ident = s.identifier
                data = s.data

                va = region_base + off
                print(Fore.GREEN + f"    String: {ident} Offset: 0x{va:016x} len={len(data)}")

                hex_dump_with_highlight(
                    data=region_data,
                    base_addr=region_base,
                    match_offset=off,
                    match_len=len(data),
                    context_bytes=256,
                )

            print("-" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")