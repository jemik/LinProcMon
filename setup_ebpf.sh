#!/bin/bash
# Setup script for eBPF + Memory Dumper integration

set -e

echo "=========================================="
echo " LinProcMon eBPF Integration Setup"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (sudo)"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "[!] Cannot detect distribution"
    exit 1
fi

echo "[+] Detected distribution: $DISTRO"

# Install dependencies
echo "[+] Installing eBPF dependencies..."

if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
    apt-get update
    apt-get install -y \
        clang \
        llvm \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        linux-headers-$(uname -r) \
        linux-tools-$(uname -r) \
        linux-tools-common \
        libssl-dev \
        build-essential
    
    # bpftool is optional - try to install but don't fail if not available
    apt-get install -y linux-tools-generic 2>/dev/null || true
        
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "centos" ]; then
    dnf install -y \
        clang \
        llvm \
        libbpf-devel \
        elfutils-libelf-devel \
        zlib-devel \
        kernel-devel \
        openssl-devel \
        bpftool
        
elif [ "$DISTRO" = "arch" ]; then
    pacman -S --noconfirm \
        clang \
        llvm \
        libbpf \
        linux-headers \
        bpf
else
    echo "[!] Unsupported distribution: $DISTRO"
    echo "[!] Please install manually: clang, llvm, libbpf-dev, kernel-headers, bpftool"
    exit 1
fi

# Verify BTF support
echo ""
echo "[+] Checking BTF (BPF Type Format) support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "    [✓] BTF enabled (/sys/kernel/btf/vmlinux exists)"
else
    echo "    [!] BTF not found - you may need a newer kernel (5.2+)"
    echo "    [!] Some eBPF features may not work"
fi

# Compile eBPF program
echo ""
echo "[+] Compiling eBPF kernel program..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -D__BPF_TRACING__ \
    -c ebpf_monitor.c -o ebpf_monitor.o

if [ $? -eq 0 ]; then
    echo "    [✓] eBPF kernel program compiled: ebpf_monitor.o"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Compile eBPF userspace monitor
echo ""
echo "[+] Compiling eBPF userspace monitor..."
gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz -O2

if [ $? -eq 0 ]; then
    echo "    [✓] eBPF monitor compiled: ebpf_standalone"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Verify eBPF object
echo ""
echo "[+] Verifying eBPF object..."
llvm-objdump -h ebpf_monitor.o | grep -q "tracepoint"
if [ $? -eq 0 ]; then
    echo "    [✓] eBPF object is valid (contains tracepoint sections)"
else
    echo "    [!] Warning: No tracepoint sections found (may still work)"
fi

# Compile memory dumper tool
echo ""
echo "[+] Compiling realtime_memdump_tool..."
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -O2

if [ $? -eq 0 ]; then
    echo "    [✓] Memory dumper compiled: realtime_memdump_tool"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Make scripts executable
echo ""
echo "[+] Making scripts executable..."
chmod +x run_integrated.sh
chmod +x compile_ebpf.sh
echo "    [✓] Scripts are executable"

echo ""
echo "=========================================="
echo " Setup Complete!"
echo "=========================================="
echo ""
echo "Compiled files:"
echo "  - ebpf_monitor.o         (eBPF kernel program)"
echo "  - ebpf_standalone        (eBPF userspace monitor)"
echo "  - realtime_memdump_tool  (Memory scanner)"
echo ""
echo "Quick Start:"
echo "  sudo ./run_integrated.sh /path/to/suspicious_binary"
echo ""
echo "This will:"
echo "  1. Create named pipe for IPC"
echo "  2. Start eBPF monitor (detects syscalls)"
echo "  3. Start memory dumper (scans on eBPF events)"
echo "  4. Execute and monitor the binary"
echo ""
echo "eBPF monitors these syscalls:"
echo "  - mmap(PROT_EXEC)       Allocate executable memory"
echo "  - mprotect(PROT_EXEC)   Make memory executable (XOR decryption)"
echo "  - memfd_create()        Fileless execution"
echo "  - execve()              Process execution"
echo ""
echo "Results:"
echo "  - Memory dumps:  sandbox_*/memory_dumps/*.bin"
echo "  - JSON report:   sandbox_*/analysis_report_*.json"
echo "  - eBPF log:      /tmp/ebpf_*_ebpf.log"
echo ""
echo "For more details, see:"
echo "  - INTEGRATION_COMPLETE.md"
echo "  - QUICK_START_INTEGRATED.md"
echo "  - EBPF_IPC_INTEGRATION.md"
echo ""
