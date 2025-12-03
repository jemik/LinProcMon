#!/usr/bin/env python3
"""
process_mem_scanner.py

Linux process memory scanner using YARA with full support for yara-python >= 4.3
(including 4.5.x).

Features:
- Scans all readable memory regions in /proc/<pid>/mem
- Skips scanning its own PID (and its parent)
- Displays PID, PPID, exe path, cmdline, SHA256
- Displays parent and children
- Shows YARA matches with offset and 256 bytes of hex context
- Highlights matched bytes in RED
"""

import argparse
import os
import sys
import datetime
import hashlib
import psutil
import yara
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


# -------------------------------------------------------------
# Utility
# -------------------------------------------------------------

def compute_sha256(path):
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


def get_process_info(proc):
    info = {
        "pid": None,
        "ppid": None,
        "name": None,
        "exe": None,
        "cmdline": None,
        "sha256": None,
    }
    try:
        info["pid"] = proc.pid
        info["ppid"] = proc.ppid()
        info["name"] = proc.name()
        info["exe"] = proc.exe()
        info["cmdline"] = " ".join(proc.cmdline())
        info["sha256"] = compute_sha256(info["exe"])
    except Exception:
        pass
    return info


def print_process_info(title, info, indent=""):
    print(f"{indent}{title}:")
    if not info:
        print(f"{indent}  <unavailable>")
        return
    print(f"{indent}  PID   : {info['pid']}")
    print(f"{indent}  Name  : {info['name']}")
    print(f"{indent}  PPID  : {info['ppid']}")
    print(f"{indent}  EXE   : {info['exe']}")
    print(f"{indent}  CMD   : {info['cmdline']}")
    print(f"{indent}  SHA256: {info['sha256']}")


def hex_dump_with_highlight(data, base_addr, match_offset, match_len, context=256):
    half = context // 2
    start = max(0, match_offset - half)
    end = min(len(data), match_offset + match_len + half)
    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"      Hex dump (0x{snippet_base:016x} - 0x{snippet_base + len(snippet):016x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        addr = snippet_base + i

        hex_parts = []
        ascii_parts = []

        for j, b in enumerate(line):
            gi = start + i + j  # index in region data
            in_match = match_offset <= gi < (match_offset + match_len)

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


# -------------------------------------------------------------
# Memory scanning
# -------------------------------------------------------------

def scan_process(pid, rules, max_region):
    """
    Returns list of (match_object, proc_info, region_base, region_data)
    """
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

            # Only read readable regions
            if "r" not in perms:
                continue

            start_s, end_s = addr_range.split("-")
            region_start = int(start_s, 16)
            region_end = int(end_s, 16)
            region_size = region_end - region_start

            if region_size <= 0:
                continue

            read_size = min(region_size, max_region)

            try:
                mem_f.seek(region_start)
                region_data = mem_f.read(read_size)
            except Exception:
                continue

            if not region_data:
                continue

            try:
                matches = rules.match(data=region_data)
            except Exception:
                continue

            if not matches:
                continue

            proc_info = get_process_info(proc)

            for m in matches:
                results.append((m, proc_info, region_start, region_data))

    return results


# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Scan live processes with YARA.")
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule")
    parser.add_argument("--max-region-size", type=int, default=50*1024*1024,
                        help="Max bytes per memory region (default=50MB)")
    args = parser.parse_args()

    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to load YARA rule: {e}")
        sys.exit(1)

    print(f"[*] Using YARA rule: {args.rule}\n")
    print("[*] Scanning processes...\n")

    current_pid = os.getpid()
    parent_pid = os.getppid()

    for proc in psutil.process_iter(attrs=["pid"]):
        pid = proc.info["pid"]

        # Avoid self false positives
        if pid == current_pid or pid == parent_pid:
            continue

        try:
            matches = scan_process(pid, rules, args.max_region_size)
        except Exception:
            continue

        if not matches:
            continue

        # Process info
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue

        proc_info = get_process_info(p)

        # Parent info
        parent_info = None
        try:
            par = p.parent()
            if par:
                parent_info = get_process_info(par)
        except Exception:
            pass

        # Children info
        children = []
        try:
            for ch in p.children(recursive=False):
                children.append(get_process_info(ch))
        except Exception:
            pass

        # Header
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        print(Fore.CYAN + f"[{ts}] Match in process PID {pid}")
        print_process_info("Process", proc_info)
        print_process_info("Parent", parent_info)
        print()
        if children:
            print("Children:")
            for ci in children:
                print_process_info(f"  Child PID {ci['pid']}", ci, indent="  ")
            print()
        else:
            print("Children: <none>\n")

        # Each YARA rule match
        for m, pinfo, region_base, region_data in matches:
            print(Fore.MAGENTA + f"  YARA Rule Matched: {m.rule} (namespace={m.namespace})")

            if m.meta:
                meta_str = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"    Meta: {meta_str}")

            # YARA 4.5.4 correct iteration:
            for s in m.strings:
                ident = s.identifier

                for match in s.matches:
                    off = match.offset
                    data = match.data
                    length = match.length

                    va = region_base + off
                    print(Fore.GREEN + f"    String: {ident} Offset=0x{va:016x} len={length}")

                    hex_dump_with_highlight(
                        region_data,
                        region_base,
                        match_offset=off,
                        match_len=length,
                        context=256
                    )

            print("-" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")