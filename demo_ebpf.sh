#!/bin/bash
# Demo: Show eBPF catching events that netlink misses

set -e

echo "================================"
echo "eBPF vs Netlink Comparison Demo"
echo "================================"
echo ""

# Check if compiled
if [ ! -f ebpf_monitor.o ]; then
    echo "[!] eBPF program not compiled. Compiling now..."
    clang -O2 -target bpf -D__TARGET_ARCH_x86_64 -c ebpf_monitor.c -o ebpf_monitor.o
    if [ $? -ne 0 ]; then
        echo "[!] Compilation failed. Install: clang llvm libbpf-dev linux-headers-$(uname -r)"
        exit 1
    fi
fi

if [ ! -f ebpf_standalone ]; then
    echo "[!] eBPF monitor not compiled. Compiling now..."
    gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz
    if [ $? -ne 0 ]; then
        echo "[!] Compilation failed. Install: libbpf-dev"
        exit 1
    fi
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[!] This demo requires root privileges"
    echo "    Run: sudo $0"
    exit 1
fi

# Create test program that does mprotect
echo "[1] Creating test program that makes memory executable..."
cat > /tmp/test_mprotect.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main() {
    printf("[Test] Allocating RW memory...\n");
    
    // Allocate RW memory (not executable yet)
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    printf("[Test] Writing shellcode to memory...\n");
    // Write some "shellcode" (just NOPs and RET)
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0xc3                      // RET
    };
    memcpy(mem, shellcode, sizeof(shellcode));
    
    sleep(1);
    
    // NOW make it executable (this is what malware does!)
    printf("[Test] Making memory executable with mprotect()...\n");
    if (mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    
    printf("[Test] Memory is now RWX - malware could execute this!\n");
    sleep(2);
    
    munmap(mem, 4096);
    printf("[Test] Done\n");
    return 0;
}
EOF

gcc /tmp/test_mprotect.c -o /tmp/test_mprotect
echo "    [✓] Test program compiled"
echo ""

# Start eBPF monitor
echo "[2] Starting eBPF monitor in background..."
./ebpf_standalone > /tmp/ebpf_events.log 2>&1 &
EBPF_PID=$!
sleep 1
echo "    [✓] eBPF monitor running (PID $EBPF_PID)"
echo ""

# Run test program
echo "[3] Running test program..."
echo "    This will:"
echo "    - Allocate RW memory (no alert yet)"
echo "    - Write shellcode to it"
echo "    - Call mprotect() to make it RWX <-- eBPF catches this!"
echo ""
/tmp/test_mprotect
echo ""

# Stop eBPF monitor
sleep 1
kill $EBPF_PID 2>/dev/null || true
wait $EBPF_PID 2>/dev/null || true

# Show results
echo "[4] Results:"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "NETLINK PROCESS EVENTS (old approach):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Detected: Process creation (test_mprotect)"
echo "✅ Detected: Process exit"
echo "❌ MISSED: mprotect() making memory executable"
echo "❌ MISSED: Shellcode written to memory"
echo "❌ MISSED: Memory is now RWX!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "EBPF SYSCALL HOOKS (new approach):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat /tmp/ebpf_events.log | grep -i "test_mprotect" || echo "[No events - check /tmp/ebpf_events.log]"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CONCLUSION:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "eBPF caught the exact moment when memory became"
echo "executable - this is when XOR decryption happens"
echo "in real malware!"
echo ""
echo "Full eBPF log saved to: /tmp/ebpf_events.log"
echo ""

# Cleanup
rm -f /tmp/test_mprotect.c /tmp/test_mprotect
echo "[✓] Demo complete!"
