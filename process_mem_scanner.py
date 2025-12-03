#!/usr/bin/env python3
"""
process_mem_scanner.py
Linux live process memory scanner using YARA.
Fully compatible with yara-python 4.5.4.

Features:
- Scans all readable memory regions via /proc/<pid>/mem
- Correct YARA 4.5.4 match handling (StringMatchInstance.matched_data)
- Shows PID, PPID, EXE, CMDLINE, SHA256
- Prints parent and children
- Prints YARA rule metadata
- Dumps 256 bytes around matched bytes, highlighted in RED
- Skips scanning its own PID and its parent PID
"""

import argparse
import os
import sys
import hashlib
import datetime
import psutil
import yara
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ---------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------

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


def get_proc_info(proc):
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


def print_proc_info(title, info, indent=""):
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


# ---------------------------------------------------------------------
# Hex dump with match highlighting
# ---------------------------------------------------------------------

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
            gi = start + i + j
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


# ---------------------------------------------------------------------
# Scan a process memory
# ---------------------------------------------------------------------

def scan_pid_memory(pid, rules, max_region):
    """
    Returns list of (YARAMatchObject, proc_info, region_base, region_data)
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

            perms = parts[1]
            if "r" not in perms:
                continue

            start_s, end_s = parts[0].split("-")
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

            pinfo = get_proc_info(proc)
            for m in matches:
                results.append((m, pinfo, region_start, region_data))

    return results


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Live Linux YARA process memory scanner (yara-python 4.5.4)")
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule file")
    parser.add_argument("--max-region-size", type=int, default=50*1024*1024,
                        help="Max bytes read per region")
    args = parser.parse_args()

    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to compile YARA rule: {e}")
        sys.exit(1)

    print(f"[*] Loaded YARA rule: {args.rule}")
    print("[*] Scanning processes...\n")

    own_pid = os.getpid()
    parent_pid = os.getppid()

    for proc in psutil.process_iter(attrs=["pid"]):
        pid = proc.info["pid"]

        if pid == own_pid or pid == parent_pid:
            continue

        try:
            results = scan_pid_memory(pid, rules, args.max_region_size)
        except Exception:
            continue

        if not results:
            continue

        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue

        proc_info = get_proc_info(p)

        parent_info = None
        try:
            parent = p.parent()
            if parent:
                parent_info = get_proc_info(parent)
        except Exception:
            pass

        children = []
        try:
            for c in p.children(recursive=False):
                children.append(get_proc_info(c))
        except Exception:
            pass

        ts = datetime.datetime.now().isoformat(timespec="seconds")
        print(Fore.CYAN + f"[{ts}] Match in process PID {pid}")
        print_proc_info("Process", proc_info)
        print_proc_info("Parent", parent_info)
        print()

        if children:
            print("Children:")
            for ci in children:
                print_proc_info(f"  Child PID {ci['pid']}", ci, indent="  ")
            print()
        else:
            print("Children: <none>\n")

        # Correct YARA 4.5.4 match model
        for m, pinfo, region_base, region_data in results:
            print(Fore.MAGENTA + f"  YARA Rule Matched: {m.rule}")

            if m.meta:
                meta = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"    Meta: {meta}")

            for s in m.strings:
                ident = s.identifier

                for inst in s.instances:
                    off = inst.offset
                    data = inst.matched_data
                    length = len(data)

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