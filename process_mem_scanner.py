#!/usr/bin/env python3
"""
Process memory scanner with YARA.

- Scans all processes on a Linux system using YARA.
- On match, prints:
  * PID, PPID, exe path, cmdline, SHA256 of exe
  * Parent process info
  * Children process info
  * Match offsets and 256-byte hex dump around match, with the match highlighted in red.
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

# Initialize colorama (also works on Windows terminals, but we mainly target Linux)
colorama_init(autoreset=True)


def compute_sha256(path):
    """Compute SHA256 of a file, or return None on error."""
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
    """Return a dict with basic process info."""
    info = {
        "pid": proc.pid,
        "ppid": None,
        "exe": None,
        "cmdline": None,
        "sha256": None,
        "name": None,
    }
    try:
        info["ppid"] = proc.ppid()
    except Exception:
        pass
    try:
        info["exe"] = proc.exe()
    except Exception:
        pass
    try:
        info["cmdline"] = " ".join(proc.cmdline())
    except Exception:
        info["cmdline"] = None
    try:
        info["name"] = proc.name()
    except Exception:
        pass

    info["sha256"] = compute_sha256(info["exe"])
    return info


def print_process_info(title, info, indent=""):
    """Pretty-print process info with optional indent."""
    if info is None:
        print(f"{indent}{title}: <unavailable>")
        return

    print(f"{indent}{title}:")
    print(f"{indent}  PID   : {info.get('pid')}")
    print(f"{indent}  Name  : {info.get('name')}")
    print(f"{indent}  PPID  : {info.get('ppid')}")
    print(f"{indent}  EXE   : {info.get('exe')}")
    print(f"{indent}  CMD   : {info.get('cmdline')}")
    print(f"{indent}  SHA256: {info.get('sha256')}")


def hex_dump_with_highlight(data: bytes, base_addr: int, match_offset: int, match_len: int, context_bytes: int = 256):
    """
    Hex dump a window around a match, highlighting matched bytes in red.

    data        : the memory region bytes
    base_addr   : virtual address of data[0]
    match_offset: offset inside data where match starts
    match_len   : length of match
    context_bytes: total bytes to show (centered around match where possible)
    """
    half_ctx = context_bytes // 2
    start = max(0, match_offset - half_ctx)
    end = min(len(data), match_offset + match_len + half_ctx)

    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"    Hex dump around match (0x{snippet_base:016x} - 0x{snippet_base + len(snippet):016x}):")

    # Print 16 bytes per line
    bytes_per_line = 16
    for i in range(0, len(snippet), bytes_per_line):
        line = snippet[i : i + bytes_per_line]
        addr = snippet_base + i
        hex_parts = []
        ascii_parts = []

        for j, b in enumerate(line):
            global_index = start + i + j  # index in data
            in_match = match_offset <= global_index < (match_offset + match_len)

            byte_hex = f"{b:02x}"
            if 32 <= b <= 126:
                byte_chr = chr(b)
            else:
                byte_chr = "."

            if in_match:
                hex_parts.append(Fore.RED + byte_hex + Style.RESET_ALL)
                ascii_parts.append(Fore.RED + byte_chr + Style.RESET_ALL)
            else:
                hex_parts.append(byte_hex)
                ascii_parts.append(byte_chr)

        # Align hex area
        hex_str = " ".join(hex_parts)
        ascii_str = "".join(ascii_parts)
        print(f"      0x{addr:016x}  {hex_str:<48}  {ascii_str}")


def scan_process(pid: int, rules, max_region_size: int):
    """
    Scan a single process memory using /proc/<pid>/maps and /proc/<pid>/mem.

    Returns list of (match, proc_info, region_base, region_data) for each match found.
    """
    matches_found = []

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return []

    try:
        maps_f = open(maps_path, "r")
    except Exception:
        return []

    try:
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        maps_f.close()
        return []

    with maps_f, mem_f:
        for line in maps_f:
            # Example line:
            # 00400000-0040b000 r-xp 00000000 fd:01 123456 /usr/bin/cat
            parts = line.split()
            if len(parts) < 2:
                continue

            addr_range = parts[0]
            perms = parts[1]

            # Only scan readable regions
            if "r" not in perms:
                continue

            start_s, end_s = addr_range.split("-")
            region_start = int(start_s, 16)
            region_end = int(end_s, 16)
            region_size = region_end - region_start

            if region_size <= 0:
                continue

            # Limit region size to avoid massive reads
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
            except yara.TimeoutError:
                print(f"[!] YARA timeout on PID {pid}, region 0x{region_start:x}-0x{region_end:x}")
                continue
            except Exception as e:
                # Some regions might cause issues
                # print(f"[!] YARA error on PID {pid}, region 0x{region_start:x}-0x{region_end:x}: {e}")
                continue

            if not rule_matches:
                continue

            proc_info = get_process_info(proc)

            for m in rule_matches:
                # Store each match with its region context
                matches_found.append(
                    (m, proc_info, region_start, region_data)
                )

    return matches_found


def main():
    parser = argparse.ArgumentParser(
        description="Scan all processes with YARA and dump match context."
    )
    parser.add_argument(
        "-r",
        "--rule",
        required=True,
        help="Path to YARA rule file (.yar / .yara)",
    )
    parser.add_argument(
        "--max-region-size",
        type=int,
        default=50 * 1024 * 1024,  # 50 MB per region
        help="Maximum bytes to read per memory region (default: 50MB).",
    )

    args = parser.parse_args()

    if os.geteuid() != 0:
        print(
            Fore.YELLOW
            + "[!] Warning: Not running as root. Many processes' memory cannot be read."
        )

    # Compile YARA rules
    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to compile YARA rules: {e}")
        sys.exit(1)

    print(f"[*] Using YARA rules from: {args.rule}")
    print("[*] Scanning all processes...\n")

    for proc in psutil.process_iter(attrs=["pid"]):
        pid = proc.info["pid"]
        try:
            matches = scan_process(pid, rules, args.max_region_size)
        except Exception:
            continue

        if not matches:
            continue

        # For each process that had matches, gather more info & print once
        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue

        # Process tree info
        proc_info = get_process_info(p)
        parent_info = None
        try:
            parent = p.parent()
            if parent:
                parent_info = get_process_info(parent)
        except Exception:
            parent_info = None

        children_infos = []
        try:
            for child in p.children(recursive=False):
                children_infos.append(get_process_info(child))
        except Exception:
            pass

        timestamp = datetime.datetime.now().isoformat(timespec="seconds")
        print(Fore.CYAN + f"\n[{timestamp}] Match in process PID {pid}")
        print_process_info("Process", proc_info)
        print_process_info("Parent", parent_info, indent="")

        if children_infos:
            print("Children:")
            for ci in children_infos:
                print_process_info(f"  Child PID {ci.get('pid')}", ci, indent="  ")
        else:
            print("Children: <none>")

        # Print per-rule / per-string matches
        for m, pinfo, region_base, region_data in matches:
            print(
                Fore.MAGENTA
                + f"\n  YARA Rule Matched: {m.rule} (namespace={m.namespace})"
            )
            if m.tags:
                print(f"    Tags: {', '.join(m.tags)}")
            if m.meta:
                meta_str = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"    Meta: {meta_str}")

            # m.strings is a list of (offset, identifier, data)
            for (off, ident, data) in m.strings:
                va = region_base + off
                print(
                    Fore.GREEN
                    + f"    String: {ident}  Offset: 0x{va:016x} (region+0x{off:x}, len={len(data)})"
                )

                # Dump hex around this match with match highlighted
                hex_dump_with_highlight(
                    data=region_data,
                    base_addr=region_base,
                    match_offset=off,
                    match_len=len(data),
                    context_bytes=256,
                )

        print("\n" + "-" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")