#!/bin/bash
#
# Build all LinProcMon components
#

set -e

echo "========================================"
echo " Building LinProcMon"
echo "========================================"
echo ""

# Clean old binaries
echo "[0/3] Cleaning old binaries..."
rm -f ebpf_monitor.o realtime_memdump_tool ebpf_standalone
echo "      [✓] Clean complete"
echo ""

# 1. Compile eBPF program
echo "[1/3] Compiling eBPF monitor..."
clang -O2 -target bpf -c ebpf_monitor.c -o ebpf_monitor.o
echo "      [✓] ebpf_monitor.o"

# 2. Compile memory dump tool
echo "[2/3] Compiling memory dump tool..."
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lpthread -lssl -lcrypto
echo "      [✓] realtime_memdump_tool"

# 3. Compile eBPF standalone monitor
echo "[3/3] Compiling eBPF standalone..."
gcc -o ebpf_standalone ebpf_standalone.c -lbpf -lelf -lz
echo "      [✓] ebpf_standalone"

echo ""
echo "========================================"
echo " Build Complete"
echo "========================================"
echo ""
echo "eBPF programs attached:"
echo "  - sys_enter_mmap / sys_enter_mprotect"
echo "  - sys_enter_memfd_create"
echo "  - sys_enter_execve / sys_exit_execve"
echo "  - sys_enter_execveat / sys_exit_execveat (fexecve)"
echo ""
echo "Run integrated test:"
echo "  sudo ./run_integrated.sh /tmp/elf_shell"
echo ""
