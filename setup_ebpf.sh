#!/bin/bash
# Setup script for eBPF integration

set -e

echo "[+] LinProcMon eBPF Setup"
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
        linux-headers-$(uname -r) \
        linux-tools-$(uname -r) \
        linux-tools-common
    
    # bpftool is optional - try to install but don't fail if not available
    apt-get install -y linux-tools-generic 2>/dev/null || true
        
elif [ "$DISTRO" = "fedora" ] || [ "$DISTRO" = "rhel" ] || [ "$DISTRO" = "centos" ]; then
    dnf install -y \
        clang \
        llvm \
        libbpf-devel \
        kernel-devel \
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
echo "[+] Compiling eBPF program..."
clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
    -c ebpf_monitor.c -o ebpf_monitor.o

if [ $? -eq 0 ]; then
    echo "    [✓] eBPF program compiled: ebpf_monitor.o"
else
    echo "    [!] Compilation failed"
    exit 1
fi

# Verify eBPF object
echo ""
echo "[+] Verifying eBPF object..."
llvm-objdump -h ebpf_monitor.o | grep -q "tracepoint"
if [ $? -eq 0 ]; then
    echo "    [✓] eBPF object is valid"
else
    echo "    [!] Invalid eBPF object"
    exit 1
fi

# Compile main tool with eBPF support
echo ""
echo "[+] Compiling realtime_memdump_tool with eBPF support..."
gcc -o realtime_memdump_tool_ebpf realtime_memdump_tool.c \
    -DUSE_EBPF \
    -static \
    -pthread \
    -lssl \
    -lcrypto \
    -lbpf \
    -lelf \
    -lz \
    -O2

if [ $? -eq 0 ]; then
    echo "    [✓] Tool compiled: realtime_memdump_tool_ebpf"
else
    echo "    [!] Compilation failed"
    exit 1
fi

echo ""
echo "[+] Setup complete!"
echo ""
echo "Usage:"
echo "  sudo ./realtime_memdump_tool_ebpf --ebpf --sandbox ./suspicious_binary"
echo ""
echo "eBPF will monitor:"
echo "  - mmap() with PROT_EXEC"
echo "  - mprotect() changing to PROT_EXEC"
echo "  - memfd_create()"
echo "  - execve()"
echo ""
