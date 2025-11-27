#!/bin/bash
# Quick compile script for eBPF monitoring

set -e

echo "LinProcMon eBPF Quick Compile"
echo "=============================="
echo ""

# Check dependencies
echo "[1] Checking dependencies..."
MISSING=""

if ! command -v clang &> /dev/null; then
    MISSING="$MISSING clang"
fi

if ! command -v llvm-objdump &> /dev/null; then
    MISSING="$MISSING llvm"
fi

if ! pkg-config --exists libbpf 2>/dev/null && [ ! -f /usr/include/bpf/libbpf.h ] && [ ! -f /usr/include/bpf/bpf.h ]; then
    MISSING="$MISSING libbpf-dev"
fi

if [ ! -d /usr/src/linux-headers-$(uname -r) ] && [ ! -d /lib/modules/$(uname -r)/build ]; then
    MISSING="$MISSING linux-headers-$(uname -r)"
fi

if [ -n "$MISSING" ]; then
    echo "    [!] Missing dependencies:$MISSING"
    echo ""
    echo "Install with:"
    if [ -f /etc/debian_version ]; then
        echo "    sudo apt-get install clang llvm libbpf-dev linux-headers-\$(uname -r)"
    elif [ -f /etc/redhat-release ]; then
        echo "    sudo dnf install clang llvm libbpf-devel kernel-devel"
    else
        echo "    (See EBPF_README.md for your distribution)"
    fi
    exit 1
else
    echo "    [✓] All dependencies found"
fi

# Compile eBPF program
echo ""
echo "[2] Compiling eBPF kernel module..."

# Find kernel headers
KERNEL_HEADERS=""
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    KERNEL_HEADERS="/lib/modules/$(uname -r)/build"
elif [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    KERNEL_HEADERS="/usr/src/linux-headers-$(uname -r)"
fi

clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -I/usr/include \
    -I${KERNEL_HEADERS}/include \
    -I${KERNEL_HEADERS}/include/uapi \
    -I${KERNEL_HEADERS}/include/generated/uapi \
    -I${KERNEL_HEADERS}/arch/x86/include \
    -I${KERNEL_HEADERS}/arch/x86/include/uapi \
    -I${KERNEL_HEADERS}/arch/x86/include/generated \
    -I${KERNEL_HEADERS}/arch/x86/include/generated/uapi \
    -c ebpf_monitor.c -o ebpf_monitor.o

if [ $? -eq 0 ]; then
    echo "    [✓] ebpf_monitor.o"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Verify eBPF object
echo ""
echo "[3] Verifying eBPF object..."
llvm-objdump -h ebpf_monitor.o | grep -q "tracepoint" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "    [✓] Valid eBPF object"
else
    echo "    [!] Invalid eBPF object"
    exit 1
fi

# Compile standalone monitor
echo ""
echo "[4] Compiling standalone monitor..."
gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz

if [ $? -eq 0 ]; then
    echo "    [✓] ebpf_standalone"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Done
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Compilation complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Usage:"
echo "  sudo ./ebpf_standalone              # Monitor all processes"
echo "  sudo ./ebpf_standalone --pid 1234   # Monitor specific PID"
echo ""
echo "Examples:"
echo "  # Watch for suspicious syscalls"
echo "  sudo ./ebpf_standalone"
echo ""
echo "  # Run test demo"
echo "  sudo ./demo_ebpf.sh"
echo ""
echo "  # Monitor alongside memory dumper"
echo "  sudo ./ebpf_standalone &"
echo "  sudo ./realtime_memdump_tool --sandbox ./malware"
echo ""
echo "See EBPF_README.md for full documentation"
echo ""
