#!/bin/bash
# Integrated eBPF + Memory Dumping
# Runs both tools together and correlates events
# Broken version

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
PIPE_PATH="/tmp/${SESSION_ID}_pipe"

echo "======================================"
echo " Integrated eBPF + Memory Monitoring"
echo "======================================"
echo ""
echo "Target: $BINARY"
echo "eBPF Log: $EBPF_LOG"
echo "IPC Pipe: $PIPE_PATH"
echo ""

# Create named pipe for IPC
echo "[0/3] Creating IPC pipe..."
mkfifo "$PIPE_PATH"
echo "      [✓] Named pipe created: $PIPE_PATH"

# Start eBPF monitor in background
echo "[1/3] Starting eBPF syscall monitor..."
./ebpf_standalone --pipe "$PIPE_PATH" > "$EBPF_LOG" 2>&1 &
EBPF_PID=$!

# Wait for eBPF to fully attach (check log for ready message)
echo "      [*] Waiting for eBPF to attach..."
for i in {1..30}; do
    if grep -q "Press Ctrl-C to stop" "$EBPF_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! kill -0 $EBPF_PID 2>/dev/null; then
    echo "[!] eBPF monitor failed to start"
    cat "$EBPF_LOG"
    exit 1
fi

if ! grep -q "Press Ctrl-C to stop" "$EBPF_LOG" 2>/dev/null; then
    echo "[!] eBPF monitor did not attach within 3 seconds"
    cat "$EBPF_LOG"
    kill $EBPF_PID 2>/dev/null
    exit 1
fi

echo "      [✓] eBPF monitor running (PID $EBPF_PID)"

# Start memory dumper with sandbox mode
echo "[2/3] Starting memory dumper in sandbox mode..."
./realtime_memdump_tool --ebpf-pipe "$PIPE_PATH" --full_dump --sandbox-rescan 1 --sandbox-timeout 1  $EXTRA_ARGS --sandbox "$BINARY" &
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
    
    # Clean up pipe
    rm -f "$PIPE_PATH"
    
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
    # Find most recent sandbox directory
    SANDBOX_DIR=$(ls -td sandbox_* 2>/dev/null | head -1)
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
    echo ""
}

trap cleanup EXIT INT TERM

# Tail eBPF log in real-time (memory dumper outputs directly)
tail -f "$EBPF_LOG" &
TAIL_PID=$!

# Wait for memory dumper to finish
wait $DUMPER_PID

# Kill tail
kill $TAIL_PID 2>/dev/null || true
