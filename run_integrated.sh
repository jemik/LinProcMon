#!/bin/bash
# Integrated eBPF + Memory Dumping
# Runs both tools together and correlates events

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root"
    exit 1
fi

if [ $# -lt 1 ]; then
    echo "Usage: sudo $0 <binary_to_monitor> [additional_args]"
    echo ""
    echo "Examples:"
    echo "  sudo $0 ./malware"
    echo "  sudo $0 ./suspicious_script --full_dump"
    exit 1
fi

BINARY="$1"
shift
EXTRA_ARGS="$@"

# Create unique session ID
SESSION_ID="ebpf_$$"
EBPF_LOG="/tmp/${SESSION_ID}_ebpf.log"
DUMPER_LOG="/tmp/${SESSION_ID}_dumper.log"

echo "======================================"
echo " Integrated eBPF + Memory Monitoring"
echo "======================================"
echo ""
echo "Target: $BINARY"
echo "eBPF Log: $EBPF_LOG"
echo "Dumper Log: $DUMPER_LOG"
echo ""

# Start eBPF monitor in background
echo "[1/3] Starting eBPF syscall monitor..."
./ebpf_standalone > "$EBPF_LOG" 2>&1 &
EBPF_PID=$!
sleep 1

if ! kill -0 $EBPF_PID 2>/dev/null; then
    echo "[!] eBPF monitor failed to start"
    cat "$EBPF_LOG"
    exit 1
fi

echo "      [✓] eBPF monitor running (PID $EBPF_PID)"

# Start memory dumper with sandbox mode
echo "[2/3] Starting memory dumper in sandbox mode..."
./realtime_memdump_tool --sandbox "$BINARY" --full_dump --sandbox-rescan 1 $EXTRA_ARGS > "$DUMPER_LOG" 2>&1 &
DUMPER_PID=$!

echo "      [✓] Memory dumper running (PID $DUMPER_PID)"
echo ""
echo "[3/3] Monitoring (press Ctrl-C to stop)..."
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "[*] Stopping monitors..."
    kill $EBPF_PID 2>/dev/null || true
    kill $DUMPER_PID 2>/dev/null || true
    wait $EBPF_PID 2>/dev/null || true
    wait $DUMPER_PID 2>/dev/null || true
    
    echo ""
    echo "======================================"
    echo " Analysis Complete"
    echo "======================================"
    echo ""
    echo "eBPF Events Captured:"
    echo "  mmap(PROT_EXEC):     $(grep -c 'mmap(PROT_EXEC)' "$EBPF_LOG" 2>/dev/null || echo 0)"
    echo "  mprotect(PROT_EXEC): $(grep -c 'mprotect(PROT_EXEC)' "$EBPF_LOG" 2>/dev/null || echo 0)"
    echo "  memfd_create():      $(grep -c 'memfd_create()' "$EBPF_LOG" 2>/dev/null || echo 0)"
    echo "  execve():            $(grep -c 'execve()' "$EBPF_LOG" 2>/dev/null || echo 0)"
    echo ""
    echo "Memory Dumps:"
    SANDBOX_DIR=$(grep "Sandbox directory:" "$DUMPER_LOG" | awk '{print $NF}' | head -1)
    if [ -n "$SANDBOX_DIR" ] && [ -d "$SANDBOX_DIR" ]; then
        echo "  Location: $SANDBOX_DIR"
        echo "  Dumps: $(find "$SANDBOX_DIR" -name "*.bin" 2>/dev/null | wc -l)"
        echo ""
        echo "To scan with YARA:"
        echo "  cd $SANDBOX_DIR/memory_dumps"
        echo "  python3 ../../test_loaders/yara_scan_sandbox.py"
    fi
    echo ""
    echo "Full logs:"
    echo "  eBPF:   $EBPF_LOG"
    echo "  Dumper: $DUMPER_LOG"
    echo ""
}

trap cleanup EXIT INT TERM

# Tail both logs in real-time
tail -f "$EBPF_LOG" "$DUMPER_LOG" &
TAIL_PID=$!

# Wait for memory dumper to finish
wait $DUMPER_PID

# Kill tail
kill $TAIL_PID 2>/dev/null || true
