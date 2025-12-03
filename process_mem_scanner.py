#!/usr/bin/env python3
"""
process_mem_scanner_v2.py
Advanced Linux live process memory + FD scanner using YARA (with progress output).

- Compatible with yara-python 4.5.4 (uses StringMatchInstance.matched_data)
- Scans /proc/<pid>/maps and /proc/<pid>/fd/*
- Shows per-process progress: [idx/total] PID (name)
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
# Utils
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
# Hex dump around match
# ---------------------------------------------------------------------

def hex_dump_with_highlight(data, base_addr, match_offset, match_len, context=256):
    half = context // 2
    start = max(0, match_offset - half)
    end = min(len(data), match_offset + match_len + half)
    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"        Hex dump (0x{snippet_base:016x} - 0x{snippet_base + len(snippet):016x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        addr = snippet_base + i

        hex_parts = []
        ascii_parts = []

        for j, b in enumerate(line):
            gi = start + i + j
            in_match = (match_offset <= gi < match_offset + match_len)

            h = f"{b:02x}"
            c = chr(b) if 32 <= b <= 126 else '.'

            if in_match:
                h = Fore.RED + h + Style.RESET_ALL
                c = Fore.RED + c + Style.RESET_ALL

            hex_parts.append(h)
            ascii_parts.append(c)

        print(f"        0x{addr:016x}  {' '.join(hex_parts):<48}  {''.join(ascii_parts)}")


# ---------------------------------------------------------------------
# Scan process memory
# ---------------------------------------------------------------------

def scan_pid_maps(pid, rules, max_region):
    results = []

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        proc = psutil.Process(pid)
        maps_f = open(maps_path, "r")
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        return results

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

            if matches:
                results.append((matches, region_start, region_data, get_proc_info(proc)))

    return results


# ---------------------------------------------------------------------
# Scan FD-backed objects
# ---------------------------------------------------------------------

def scan_pid_fds(pid, rules, max_size):
    results = []

    fd_dir = f"/proc/{pid}/fd"
    if not os.path.isdir(fd_dir):
        return results

    try:
        fds = os.listdir(fd_dir)
    except Exception:
        return results

    for fd in fds:
        fd_path = os.path.join(fd_dir, fd)

        try:
            target = os.readlink(fd_path)
        except Exception:
            continue

        # Ignore sockets and pipes
        if target.startswith("socket:") or target.startswith("pipe:"):
            continue

        try:
            with open(fd_path, "rb", 0) as f:
                data = f.read(max_size)
        except Exception:
            continue

        if not data:
            continue

        try:
            matches = rules.match(data=data)
        except Exception:
            continue

        if matches:
            results.append((matches, fd_path, target, data))

    return results


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Advanced Linux YARA Memory + FD Scanner v2 (with progress)")
    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule file")
    parser.add_argument("--max-region-size", type=int, default=50*1024*1024,
                        help="Max bytes per region/FD (default 50MB)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose progress (print every scanned PID)")
    args = parser.parse_args()

    try:
        rules = yara.compile(filepath=args.rule)
    except Exception as e:
        print(Fore.RED + f"[!] Could not compile YARA rule: {e}")
        sys.exit(1)

    print(f"[*] Loaded YARA rule: {args.rule}")
    print("[*] Enumerating processes...")

    # Pre-collect processes for progress display
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        procs.append(p)
    total = len(procs)

    print(f"[*] Found {total} processes")
    print("[*] Starting scan...\n")

    own_pid = os.getpid()
    parent_pid = os.getppid()

    for idx, proc in enumerate(procs, start=1):
        pid = proc.info["pid"]
        name = proc.info.get("name", "?")

        if pid == own_pid or pid == parent_pid:
            continue

        # Progress line
        if args.verbose:
            print(Fore.BLUE + f"[*] [{idx}/{total}] Scanning PID {pid} ({name})", flush=True)
        else:
            # Lighter progress: update every 10 processes
            if idx % 10 == 0:
                print(Fore.BLUE + f"[*] Scanning {idx}/{total} (current PID {pid}, {name})", flush=True)

        # SCAN MEMORY MAPS
        try:
            map_results = scan_pid_maps(pid, rules, args.max_region_size)
        except Exception:
            map_results = []

        # SCAN FDs
        try:
            fd_results = scan_pid_fds(pid, rules, args.max_region_size)
        except Exception:
            fd_results = []

        if not map_results and not fd_results:
            continue

        # Build baseline process info
        try:
            p = psutil.Process(pid)
            info = get_proc_info(p)
        except Exception:
            continue

        ts = datetime.datetime.now().isoformat(timespec="seconds")
        print(Fore.CYAN + f"\n[{ts}] MATCHES FOUND in PID {pid}")
        print_proc_info("Process", info)

        # Parent
        try:
            parent = p.parent()
            if parent:
                print_proc_info("Parent", get_proc_info(parent))
            else:
                print("Parent: <none>")
        except Exception:
            print("Parent: <unknown>")

        # Children
        try:
            children = p.children()
            if children:
                print("\nChildren:")
                for ch in children:
                    print_proc_info(f"  Child PID {ch.pid}", get_proc_info(ch), indent="  ")
        except Exception:
            pass

        print()

        # MEMORY MATCHES
        for matches, region_base, region_data, pinfo in map_results:
            for m in matches:
                print(Fore.MAGENTA + f"  YARA Rule Match (Memory): {m.rule}")

                if m.meta:
                    print("    Meta: " + ", ".join(f"{k}={v!r}" for k, v in m.meta.items()))

                for s in m.strings:
                    ident = s.identifier
                    for inst in getattr(s, "instances", []):
                        off = inst.offset
                        mdata = inst.matched_data
                        length = len(mdata)

                        va = region_base + off
                        print(Fore.GREEN + f"    String: {ident} Offset=0x{va:016x} len={length}")

                        hex_dump_with_highlight(
                            region_data, region_base, off, length, 256
                        )

                print("-" * 80)

        # FD MATCHES
        if fd_results:
            print(Fore.YELLOW + f"\n[*] FD-based Matches for PID {pid}")
            for matches, fd_path, target, data in fd_results:
                print(Fore.YELLOW + f"  FD: {fd_path} -> {target}")

                for m in matches:
                    print(Fore.MAGENTA + f"    YARA Match (FD): {m.rule}")
                    if m.meta:
                        print("      Meta: " + ", ".join(f"{k}={v!r}" for k, v in m.meta.items()))

                    for s in m.strings:
                        ident = s.identifier
                        for inst in getattr(s, "instances", []):
                            off = inst.offset
                            mdata = inst.matched_data
                            length = len(mdata)

                            print(Fore.GREEN + f"      String: {ident} Offset={off} len={length}")

                            hex_dump_with_highlight(
                                data, 0, off, length, 256
                            )

                    print("-" * 80)

    print("\n[*] Scan complete.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")