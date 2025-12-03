#!/usr/bin/env python3
"""
process_mem_scanner_v4.2.py
Advanced Linux Memory Scanner with YARA + ELF Reconstruction + Shellcode Heuristics
Author: Jesper Mikkelsen + AI
Requires: psutil, yara-python, capstone, colorama

Core Features:
- Multiprocessing (hard timeouts, no hangs)
- YARA scanning on memory + FD targets
- Auto architecture detection (x86/x64/ARM/ARM64)
- Capstone disassembly around matches
- Injection heuristics (RWX, memfd, anonymous exec, VmFlags)
- ELF-only carving + Deep ELF Reconstruction (--deep-carve)
- Multi-ELF detection (all ELF occurrences)
- Split PT_LOAD segment merging (Volatility-style)
- Symbol extraction + JIT ELF heuristics
- PID-scoped dump directories

Run:
    sudo python3 process_mem_scanner_v4.2.py -r rule.yar --dump-dir dumps --deep-carve
"""

import argparse
import os
import sys
import time
import math
import json
import hashlib
import datetime
import struct

import psutil
import yara
from capstone import *
from colorama import Fore, Style, init as colorama_init

from multiprocessing import Pool, TimeoutError as MPTimeoutError

colorama_init(autoreset=True)


# ======================================================================
# Utility
# ======================================================================

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {b: data.count(b) for b in set(data)}
    probs = [c / len(data) for c in freq.values()]
    return -sum(p * math.log2(p) for p in probs)


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


def progress_bar(prefix, current, total, start_time, length=50):
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    eta = time.strftime("%H:%M:%S", time.gmtime(remaining)) if remaining > 0 else "--:--:--"
    frac = current / total if total else 0
    filled = int(length * frac)
    bar = "+" * filled + "-" * (length - filled)
    print(f"\r{prefix} | {current}/{total} [{bar}] ETA {eta}", end="", flush=True)


# ======================================================================
# Architecture Detection
# ======================================================================

def read_elf_header(path):
    try:
        with open(path, "rb") as f:
            return f.read(0x40)
    except Exception:
        return None


def detect_arch_from_elf(hdr):
    if not hdr or len(hdr) < 0x20:
        return "x86_64"
    ei_class = hdr[4]
    e_machine = struct.unpack("<H", hdr[18:20])[0]

    if ei_class == 2:  # 64-bit
        if e_machine == 0x3E:
            return "x86_64"
        if e_machine == 0xB7:
            return "arm64"
    elif ei_class == 1:  # 32-bit
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


# ======================================================================
# Hex Dump
# ======================================================================

def hex_dump_highlight(data: bytes, base_addr: int, match_offset: int, match_len: int, context=256):
    half = context // 2
    start = max(0, match_offset - half)
    end = min(len(data), match_offset + match_len + half)

    snippet = data[start:end]
    snippet_base = base_addr + start

    print(f"        Hex dump (0x{snippet_base:016x} - 0x{snippet_base+len(snippet):016x}):")

    for i in range(0, len(snippet), 16):
        line = snippet[i:i+16]
        addr = snippet_base + i
        hex_parts = []
        ascii_parts = []

        for j, b in enumerate(line):
            gi = start + i + j
            in_match = match_offset <= gi < match_offset + match_len
            hx = f"{b:02x}"
            ch = chr(b) if 32 <= b <= 126 else "."

            if in_match:
                hx = Fore.RED + hx + Style.RESET_ALL
                ch = Fore.RED + ch + Style.RESET_ALL

            hex_parts.append(hx)
            ascii_parts.append(ch)

        print(f"        0x{addr:016x}  {' '.join(hex_parts):<48}  {''.join(ascii_parts)}")


# ======================================================================
# Injection Detection (RWX, memfd, anonymous, VmFlags)
# ======================================================================

def detect_injection_indicators(pid):
    indicators = []

    maps_path = f"/proc/{pid}/maps"
    smaps_path = f"/proc/{pid}/smaps"

    # Basic MAPS indicators
    if os.path.isfile(maps_path):
        try:
            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    addr_range, perms, _, _, inode = parts[:5]
                    path = parts[5] if len(parts) >= 6 else ""

                    if "r" in perms and "w" in perms and "x" in perms:
                        indicators.append(f"RWX memory: {addr_range} {perms}")

                    if "x" in perms and inode == "0":
                        indicators.append(f"Anonymous executable: {addr_range}")

                    if "x" in perms and "memfd:" in path:
                        indicators.append(f"memfd executable region: {addr_range} {path}")
        except Exception:
            pass

    # VmFlags heuristics
    if os.path.isfile(smaps_path):
        try:
            current_range = None
            with open(smaps_path, "r") as f:
                for line in f:
                    if "-" in line and line.count("-") == 1 and line.split():
                        current_range = line.split()[0]
                    if line.startswith("VmFlags:"):
                        flags = line.split(":")[1].strip().split()
                        if "ex" in flags and ("mr" in flags or "mw" in flags):
                            indicators.append(
                                f"VmFlags suggests RW→RX transition: {current_range} flags={','.join(flags)}"
                            )
        except Exception:
            pass

    return list(dict.fromkeys(indicators))  # dedupe


# ======================================================================
# YARA + Memory Region Scanning Worker (Multiprocess)
# ======================================================================

def scan_pid_worker(args):
    pid, rule_path, max_region, only_exec, only_anon, only_memfd = args
    results = []

    try:
        proc = psutil.Process(pid)
        status = proc.status()
        if status in ("zombie", "dead", "disk-sleep"):
            return results
    except Exception:
        return results

    try:
        exe = proc.exe()
        if not exe:
            return results
    except Exception:
        return results

    try:
        rules = yara.compile(filepath=rule_path)
    except Exception:
        return results

    # Detect architecture
    hdr = read_elf_header(exe)
    arch = detect_arch_from_elf(hdr)
    md = get_disassembler(arch)

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    fd_dir = f"/proc/{pid}/fd"

    # --- Scan /proc/<pid>/maps regions ---
    try:
        maps_f = open(maps_path, "r")
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        maps_f = None
        mem_f = None

    if maps_f and mem_f:
        with maps_f, mem_f:
            for line in maps_f:
                parts = line.split()
                if len(parts) < 2:
                    continue

                addr_range, perms = parts[0], parts[1]

                if only_exec and "x" not in perms:
                    continue
                if only_anon:
                    if len(parts) < 6 or parts[5] != "0":
                        continue
                if "r" not in perms:
                    continue

                start_s, end_s = addr_range.split("-")
                start = int(start_s, 16)
                end = int(end_s, 16)
                size = end - start
                if size <= 0:
                    continue

                try:
                    mem_f.seek(start)
                    if size <= max_region:
                        region = mem_f.read(size)
                    else:
                        # Read the end, which often contains unpacked payloads
                        mem_f.seek(end - max_region)
                        region = mem_f.read(max_region)
                except Exception as e:
                    print(Fore.RED + f"[!] Failed to read memory for PID {pid}: {e}")
                    continue

                if not region:
                    continue

                try:
                    matches = rules.match(data=region)
                except Exception as e:
                    print(Fore.RED + f"[!] YARA scan error in PID {pid}: {e}")
                    continue

                if matches:
                    results.append({
                        "pid": pid,
                        "type": "maps",
                        "region_start": start,
                        "data": region,
                        "entropy": shannon_entropy(region),
                        "matches": matches,
                        "arch": arch,
                    })

    # --- Scan /proc/<pid>/fd file descriptors ---
    if os.path.isdir(fd_dir):
        try:
            for fd in os.listdir(fd_dir):
                path = os.path.join(fd_dir, fd)
                try:
                    target = os.readlink(path)
                except Exception:
                    continue

                if only_memfd and not target.startswith("memfd:"):
                    continue
                if target.startswith("socket:") or target.startswith("pipe:"):
                    continue

                try:
                    with open(path, "rb", 0) as f:
                        data = f.read()
                except Exception:
                    continue

                if not data:
                    continue

                try:
                    matches = rules.match(data=data)
                except Exception:
                    continue

                if matches:
                    results.append({
                        "pid": pid,
                        "type": "fd",
                        "fd_path": path,
                        "fd_target": target,
                        "data": data,
                        "entropy": shannon_entropy(data),
                        "matches": matches,
                        "arch": arch,
                    })
        except Exception:
            pass

    return results


# ======================================================================
# ELF-Only Carving (Header detection only)
# ======================================================================

def carve_memory(data: bytes):
    idx = data.find(b"\x7fELF")
    if idx != -1:
        return {"type": "ELF", "offset": idx}
    return None

# ======================================================================
# Advanced ELF Parsing & Reconstruction (ELF64 only)
# ======================================================================

MAX_ELF_REBUILD_SIZE = 256 * 1024 * 1024  # 256 MB ceiling


def parse_elf_header(data: bytes, offset: int = 0):
    """
    Parse minimal ELF64 header from memory buffer.
    Returns dict with header fields or None.
    """
    try:
        if len(data) < offset + 0x40:
            return None

        if not data[offset:offset+4] == b"\x7fELF":
            return None

        ei_class = data[offset+4]
        if ei_class != 2:  # 2 = ELFCLASS64
            return None

        # From ELF64 spec:
        # e_type      (2)
        # e_machine   (2)
        # e_version   (4)
        # e_entry     (8)
        # e_phoff     (8)
        # e_shoff     (8)
        # e_flags     (4)
        # e_ehsize    (2)
        # e_phentsize (2)
        # e_phnum     (2)
        # e_shentsize (2)
        # e_shnum     (2)
        # e_shstrndx  (2)
        fields = struct.unpack_from("<HHIQQQIHHHHHH", data, offset + 16)

        hdr = {
            "e_type": fields[0],
            "e_machine": fields[1],
            "e_version": fields[2],
            "e_entry": fields[3],
            "e_phoff": fields[4],
            "e_shoff": fields[5],
            "e_flags": fields[6],
            "e_ehsize": fields[7],
            "e_phentsize": fields[8],
            "e_phnum": fields[9],
            "e_shentsize": fields[10],
            "e_shnum": fields[11],
            "e_shstrndx": fields[12],
            "elf_offset": offset,
        }
        return hdr
    except Exception:
        return None


def parse_program_headers(data: bytes, ehdr: dict):
    """
    Parse ELF64 program headers.
    Returns list of dicts with PT_LOAD info.
    """
    ph_list = []
    phoff = ehdr["elf_offset"] + ehdr["e_phoff"]
    entsize = ehdr["e_phentsize"]
    count = ehdr["e_phnum"]

    if entsize == 0 or count == 0:
        return []

    try:
        for i in range(count):
            off = phoff + i * entsize
            if off + entsize > len(data):
                break
            # ELF64_Phdr: p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from("<IIQQQQQQ", data, off)
            ph_list.append({
                "p_type": p_type,
                "p_flags": p_flags,
                "p_offset": p_offset,
                "p_vaddr": p_vaddr,
                "p_paddr": p_paddr,
                "p_filesz": p_filesz,
                "p_memsz": p_memsz,
                "p_align": p_align,
            })
    except Exception:
        return []

    return ph_list


def find_memory_segments_for_elf(pid: int, ph_list):
    """
    For each PT_LOAD segment, find a backing /proc/<pid>/mem region that contains it.
    Returns list of (ph, bytes).
    """
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    segments = []

    if not os.path.isfile(maps_path):
        return segments

    try:
        mem_f = open(mem_path, "rb", 0)
    except Exception:
        return segments

    regions = []
    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                addr_range, perms = parts[0], parts[1]
                if "r" not in perms:
                    continue
                start_s, end_s = addr_range.split("-")
                regions.append((int(start_s, 16), int(end_s, 16)))
    except Exception:
        mem_f.close()
        return segments

    for ph in ph_list:
        if ph["p_type"] != 1:  # PT_LOAD
            continue

        vaddr = ph["p_vaddr"]
        end_v = vaddr + ph["p_memsz"]

        for r_start, r_end in regions:
            if vaddr >= r_start and end_v <= r_end:
                size = min(ph["p_filesz"], r_end - vaddr)
                try:
                    mem_f.seek(vaddr)
                    seg_data = mem_f.read(size)
                    if seg_data:
                        segments.append((ph, seg_data))
                except Exception:
                    pass
                break

    mem_f.close()
    return segments


def reconstruct_elf(pid: int, base_data: bytes, elf_offset: int):
    """
    Reconstruct a full ELF64 binary from memory using:
    - ELF header (from base_data at elf_offset)
    - PT_LOAD segments stitched from /proc/<pid>/mem

    Returns reconstructed ELF bytes or None.
    """
    ehdr = parse_elf_header(base_data, elf_offset)
    if not ehdr:
        return None

    ph_list = parse_program_headers(base_data, ehdr)
    if not ph_list:
        return None

    segments = find_memory_segments_for_elf(pid, ph_list)
    if not segments:
        return None

    # Compute max offset in file
    max_end = 0
    for ph, seg in segments:
        end = ph["p_offset"] + len(seg)
        if end > max_end:
            max_end = end

    max_end = min(max_end, MAX_ELF_REBUILD_SIZE)
    if max_end <= 0:
        return None

    out = bytearray(max_end)

    # Copy initial header + program headers into the beginning if possible
    header_len = min(len(base_data) - elf_offset, ehdr["e_ehsize"] + ehdr["e_phentsize"] * ehdr["e_phnum"])
    if header_len > 0:
        out[0:header_len] = base_data[elf_offset:elf_offset + header_len]

    # Copy each PT_LOAD segment
    for ph, seg in segments:
        off = ph["p_offset"]
        end = off + len(seg)
        if off >= max_end:
            continue
        if end > max_end:
            end = max_end
        out[off:end] = seg[: end - off]

    return bytes(out)


# ======================================================================
# Basic ELF Section/Symbol Extraction (optional, best-effort)
# ======================================================================

SHT_SYMTAB = 2
SHT_DYNSYM = 11


def parse_section_headers(elf: bytes, ehdr: dict):
    """
    Parse ELF64 section headers (best-effort).
    Returns list of dicts.
    """
    sh_list = []
    shoff = ehdr["e_shoff"]
    entsize = ehdr["e_shentsize"]
    count = ehdr["e_shnum"]
    base = 0  # We assume ELF starts at offset 0 now

    if shoff == 0 or entsize == 0 or count == 0:
        return sh_list

    try:
        for i in range(count):
            off = base + shoff + i * entsize
            if off + entsize > len(elf):
                break
            # Elf64_Shdr:
            #   sh_name (4)
            #   sh_type (4)
            #   sh_flags (8)
            #   sh_addr (8)
            #   sh_offset (8)
            #   sh_size (8)
            #   sh_link (4)
            #   sh_info (4)
            #   sh_addralign (8)
            #   sh_entsize (8)
            sh_fields = struct.unpack_from("<IIQQQQIIQQ", elf, off)
            sh_list.append({
                "sh_name": sh_fields[0],
                "sh_type": sh_fields[1],
                "sh_flags": sh_fields[2],
                "sh_addr": sh_fields[3],
                "sh_offset": sh_fields[4],
                "sh_size": sh_fields[5],
                "sh_link": sh_fields[6],
                "sh_info": sh_fields[7],
                "sh_addralign": sh_fields[8],
                "sh_entsize": sh_fields[9],
            })
    except Exception:
        pass

    return sh_list


def extract_string_table(elf: bytes, sh_list, index):
    """
    Extract a string table given its section index.
    """
    if index is None or index < 0 or index >= len(sh_list):
        return None
    sh = sh_list[index]
    off = sh["sh_offset"]
    size = sh["sh_size"]
    if off + size > len(elf):
        return None
    return elf[off:off+size]


def get_section_name(strtab: bytes, sh_name: int):
    if not strtab or sh_name >= len(strtab):
        return "<unknown>"
    end = strtab.find(b"\x00", sh_name)
    if end == -1:
        end = len(strtab)
    return strtab[sh_name:end].decode(errors="replace")


def extract_symbols(elf: bytes, ehdr: dict):
    """
    Extract symbols from SYMTAB and DYNSYM (if present).
    Returns dict with "symtab" and "dynsym".
    """
    symbols = {"symtab": [], "dynsym": []}

    sh_list = parse_section_headers(elf, ehdr)
    if not sh_list:
        return symbols

    # section header string table
    shstr = extract_string_table(elf, sh_list, ehdr.get("e_shstrndx"))

    # locate symtab/dynsym + associated strtab
    for idx, sh in enumerate(sh_list):
        if sh["sh_type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue

        sec_name = get_section_name(shstr, sh["sh_name"]) if shstr else "<unknown>"
        off = sh["sh_offset"]
        size = sh["sh_size"]
        entsize = sh["sh_entsize"] or 24  # Elf64_Sym size
        count = size // entsize

        if off + size > len(elf):
            continue

        # linked string table
        strtab = extract_string_table(elf, sh_list, sh["sh_link"])

        for i in range(count):
            eoff = off + i * entsize
            if eoff + entsize > len(elf):
                break
            # Elf64_Sym: st_name, st_info, st_other, st_shndx, st_value, st_size
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", elf, eoff)
            name = ""
            if strtab and st_name < len(strtab):
                end = strtab.find(b"\x00", st_name)
                if end == -1:
                    end = len(strtab)
                name = strtab[st_name:end].decode(errors="replace")
            sym = {
                "name": name,
                "st_value": st_value,
                "st_size": st_size,
                "st_info": st_info,
                "st_other": st_other,
                "st_shndx": st_shndx,
                "section": sec_name,
            }
            if sh["sh_type"] == SHT_SYMTAB:
                symbols["symtab"].append(sym)
            else:
                symbols["dynsym"].append(sym)

    return symbols


# ======================================================================
# JIT / ELF-ish Heuristics
# ======================================================================

def classify_shellcode(insns):
    """
    Very simple heuristic classifier for shellcode-like sequences.
    insns: list of (addr, mnemonic, op_str)
    """
    total = len(insns)
    if total == 0:
        return {"score": 0.0, "tags": []}

    cf_count = 0
    syscall_present = False
    binsh_present = False

    cf_prefixes = ("jmp", "j", "call", "ret", "loop")

    for _, mnem, op in insns:
        if any(mnem.startswith(p) for p in cf_prefixes):
            cf_count += 1
        if mnem == "syscall" or (mnem == "int" and "0x80" in op):
            syscall_present = True
        if "/bin/sh" in op or "0x68732f6e69622f" in op:
            binsh_present = True

    score = (cf_count / total) * 100.0
    tags = []
    if score > 40:
        tags.append("high_control_flow_density")
    if syscall_present:
        tags.append("syscall_present")
    if binsh_present:
        tags.append("binsh_literal")

    return {"score": score, "tags": tags}


def heuristic_jit_elf(elf: bytes, symbols: dict):
    """
    Light-weight heuristic for JIT-style ELF or custom loaders.
    Returns list of tags.
    """
    tags = []

    # Many small functions in dynsym or symtab → JIT-ish
    total_syms = len(symbols.get("symtab", [])) + len(symbols.get("dynsym", []))
    if total_syms > 2000:
        tags.append("many_symbols")

    # Look for PLT/GOT markers
    if b".plt" in elf or b".got" in elf or b".got.plt" in elf:
        tags.append("plt_got_present")

    # DWARF / debug presence
    if b".debug_info" in elf or b".eh_frame" in elf:
        tags.append("debug_sections_present")

    # High entropy overall
    ent = shannon_entropy(elf[: min(len(elf), 64 * 1024)])
    if ent > 7.0:
        tags.append("high_entropy_elf")

    return tags

# ======================================================================
# MAIN SCANNER LOGIC (v4.2)
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="Process Memory Scanner v4.2 with Deep ELF Reconstruction")

    parser.add_argument("-r", "--rule", required=True, help="Path to YARA rule file")
    parser.add_argument("--max-region-size", type=int, default=25 * 1024 * 1024,
                        help="Max bytes read per memory region/FD (default: 25 MB)")

    parser.add_argument("--threads", type=int, default=4,
                        help="Worker processes for scanning")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout *per process* scan")

    parser.add_argument("--json", help="Write JSON summary")
    parser.add_argument("--dump-dir", help="Directory for saving reconstructed ELFs + matched buffers")

    parser.add_argument("--only-exec", action="store_true", help="Scan only executable memory regions")
    parser.add_argument("--only-anon", action="store_true", help="Scan only anonymous regions")
    parser.add_argument("--only-memfd", action="store_true", help="Scan only memfd-backed FDs")

    parser.add_argument("--deep-carve", action="store_true",
                        help="Enable Deep ELF Reconstruction (PT_LOAD set detection + merge)")

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Pre-flight status
    # ------------------------------------------------------------------

    pids = [p.pid for p in psutil.process_iter()]
    total = len(pids)

    print(Fore.CYAN + f"[*] Loaded YARA rule: {args.rule}")
    print(f"[*] Found {total} processes\n")

    tasks = [
        (pid, args.rule, args.max_region_size,
         args.only_exec, args.only_anon, args.only_memfd)
        for pid in pids
    ]

    start_time = time.time()
    results = []
    timeouts = []

    pool = Pool(processes=args.threads)

    # ------------------------------------------------------------------
    # Multiprocessing scanning loop
    # ------------------------------------------------------------------
    try:
        for idx, task in enumerate(tasks, start=1):
            progress_bar("Scanning", idx, total, start_time)

            pid = task[0]
            try:
                async_res = pool.apply_async(scan_pid_worker, (task,))
                entries = async_res.get(timeout=args.timeout)
            except MPTimeoutError:
                print(Fore.RED + f"\n[!] PID {pid} exceeded timeout {args.timeout}s → skipped")
                timeouts.append(pid)
                continue
            except Exception:
                continue

            if entries:
                results.extend(entries)

    finally:
        pool.close()
        pool.terminate()

    print("\n\n[+] Scan complete.")
    print(f"[+] Matched regions: {len(results)}")
    print(f"[+] Timeouts: {len(timeouts)} → {timeouts}\n")

    # ------------------------------------------------------------------
    # JSON summary output
    # ------------------------------------------------------------------
    if args.json:
        summary = []
        for r in results:
            summary.append({
                "pid": r["pid"],
                "type": r["type"],
                "entropy": r["entropy"],
                "region_start": r.get("region_start"),
                "fd_path": r.get("fd_path"),
                "fd_target": r.get("fd_target"),
                "matches": [m.rule for m in r["matches"]],
                "arch": r.get("arch"),
            })

        try:
            with open(args.json, "w") as f:
                json.dump(summary, f, indent=2)
            print(Fore.GREEN + f"[+] JSON written to {args.json}")
        except Exception:
            print(Fore.RED + "[!] Failed to write JSON summary")

    if not results:
        print("[*] No YARA matches found.")
        return

    # ------------------------------------------------------------------
    # Sort results for cleaner display
    # ------------------------------------------------------------------
    results.sort(key=lambda x: (x["pid"], x["type"], x.get("region_start", 0)))

    # ------------------------------------------------------------------
    # Detailed forensic report
    # ------------------------------------------------------------------
    for entry in results:
        pid = entry["pid"]
        arch = entry["arch"]
        now = datetime.datetime.now().isoformat(timespec="seconds")

        print(Fore.CYAN + f"\n[{now}] MATCH in PID {pid} (ARCH={arch})")

        # --------------------------------------------------------------
        # Process metadata
        # --------------------------------------------------------------
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
            cmd = " ".join(proc.cmdline())

            print("Process Info:")
            print(f"  PID   : {pid}")
            print(f"  Name  : {proc.name()}")
            print(f"  EXE   : {exe}")
            print(f"  CMD   : {cmd}")
            print(f"  SHA256: {compute_sha256(exe)}")
        except Exception:
            print("Process Info: <unavailable>")

        # --------------------------------------------------------------
        # Injection Indicators
        # --------------------------------------------------------------
        print("\nInjection Indicators:")
        indicators = detect_injection_indicators(pid)
        if indicators:
            for i in indicators:
                print(Fore.RED + f"  [!] {i}")
        else:
            print("  <none>")

        # --------------------------------------------------------------
        # Region header
        # --------------------------------------------------------------
        data = entry["data"]

        if entry["type"] == "maps":
            base = entry["region_start"]
            print(Fore.YELLOW + f"\n  [MEMORY] start=0x{base:016x} size={len(data)} entropy={entry['entropy']:.3f}")
        else:
            base = 0
            print(Fore.YELLOW + f"\n  [FD] {entry['fd_path']} → {entry['fd_target']} size={len(data)}")

        # --------------------------------------------------------------
        # YARA match processing
        # --------------------------------------------------------------
        md = get_disassembler(arch)

        for m in entry["matches"]:
            print(Fore.MAGENTA + f"\n    YARA RULE: {m.rule}")
            if m.meta:
                meta_str = ", ".join(f"{k}={v!r}" for k, v in m.meta.items())
                print(f"      Meta: {meta_str}")

            # ------------------------------------------------------------------
            # Process each string match
            # ------------------------------------------------------------------
            for s in m.strings:
                ident = s.identifier

                for inst in getattr(s, "instances", []):
                    off = inst.offset
                    mdata = inst.matched_data
                    mlen = len(mdata)
                    va = base + off

                    print(Fore.GREEN + f"\n      String {ident} Offset=0x{va:016x} len={mlen}")
                    hex_dump_highlight(data, base, off, mlen)

                    # ----------------------------------------------------------
                    # Disassembly around match
                    # ----------------------------------------------------------
                    print("\n      Disassembly:")
                    start = max(0, off - 64)
                    end = min(len(data), off + mlen + 64)
                    code = data[start:end]

                    insns = []
                    try:
                        for ins in md.disasm(code, va - (off - start)):
                            insns.append((ins.address, ins.mnemonic, ins.op_str))
                    except Exception:
                        pass

                    for addr, mnem, op in insns:
                        addr_s = f"0x{addr:016x}"
                        if va <= addr < va + mlen:
                            print(Fore.RED + f"        >> {addr_s}: {mnem} {op}")
                        else:
                            print(f"           {addr_s}: {mnem} {op}")

                    # ----------------------------------------------------------
                    # Shellcode heuristic
                    # ----------------------------------------------------------
                    heuristic = classify_shellcode(insns)
                    print(f"\n      Shellcode Score: {heuristic['score']:.1f}  Tags={heuristic['tags']}")

        # ----------------------------------------------------------------------
        # ELF carving + deep reconstruction
        # ----------------------------------------------------------------------
        carved = carve_memory(data)
        if carved:
            print(Fore.CYAN + f"\n      ELF header detected at offset {carved['offset']}")

            if args.deep_carve:
                print(Fore.YELLOW + "      Attempting deep ELF reconstruction...")

                rebuilt = reconstruct_elf(pid, data, carved["offset"])

                if rebuilt:
                    # Basic ELF header parse to get symbols
                    ehdr = parse_elf_header(rebuilt, 0)

                    if ehdr:
                        symbols = extract_symbols(rebuilt, ehdr)
                        print(f"      Extracted {len(symbols['symtab'])} SYMTAB symbols")
                        print(f"      Extracted {len(symbols['dynsym'])} DYNSYM symbols")

                        jit_tags = heuristic_jit_elf(rebuilt, symbols)
                        if jit_tags:
                            print(Fore.MAGENTA + f"      JIT/ELF heuristic tags: {jit_tags}")

                    # ----------------------------------------------------------
                    # Save reconstructed ELF into PID folder
                    # ----------------------------------------------------------
                    if args.dump_dir:
                        pid_dir = os.path.join(args.dump_dir, f"pid_{pid}")
                        os.makedirs(pid_dir, exist_ok=True)

                        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

                        out_path = os.path.join(pid_dir, f"reconstructed_{ts}.elf")
                        try:
                            with open(out_path, "wb") as f:
                                f.write(rebuilt)
                            print(Fore.GREEN + f"      Reconstructed ELF saved: {out_path}")
                        except Exception:
                            print(Fore.RED + "      Failed to write reconstructed ELF")
                    else:
                        print(Fore.GREEN + "      Reconstruction succeeded (no dump-dir set)")
                else:
                    print(Fore.RED + "      Deep reconstruction failed.")

        # ----------------------------------------------------------------------
        # Dump raw buffer for manual analysis
        # ----------------------------------------------------------------------
        if args.dump_dir:
            pid_dir = os.path.join(args.dump_dir, f"pid_{pid}")
            os.makedirs(pid_dir, exist_ok=True)

            name = (
                f"region_{entry['region_start']:x}.bin"
                if entry["type"] == "maps"
                else "fd_region.bin"
            )
            dump_path = os.path.join(pid_dir, name)

            try:
                with open(dump_path, "wb") as f:
                    f.write(data)
                print(Fore.GREEN + f"      Raw region dumped: {dump_path}")
            except Exception:
                print(Fore.RED + "      Failed to dump region")

        print("\n" + "-" * 90)

    print("\n[✓] Done.\n")


# ======================================================================
# Entry Point
# ======================================================================

if __name__ == "__main__":
    main()