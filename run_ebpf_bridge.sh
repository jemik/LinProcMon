#!/bin/bash
# eBPF Integration Bridge - Sends events to realtime_memdump_tool

set -e

SOCKET_PATH="/tmp/linprocmon_ebpf.sock"

# Check if eBPF monitor is compiled
if [ ! -f ebpf_standalone ]; then
    echo "[!] eBPF monitor not compiled. Run ./compile_ebpf.sh first"
    exit 1
fi

# Check if socket exists (memory dumper is listening)
if [ ! -S "$SOCKET_PATH" ]; then
    echo "[!] Memory dumper not listening on $SOCKET_PATH"
    echo "[!] Start realtime_memdump_tool with --ebpf flag first:"
    echo "    sudo ./realtime_memdump_tool --ebpf --sandbox ./malware"
    exit 1
fi

# Run eBPF monitor with socket output
echo "[+] Starting eBPF monitor in bridge mode..."
echo "[+] Sending events to $SOCKET_PATH"
exec sudo ./ebpf_standalone --socket "$SOCKET_PATH" "$@"
