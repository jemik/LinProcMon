#!/bin/bash
# Build test malware samples

echo "Building test malware samples..."
echo ""

# Build RWX memory test
echo "[1] Building test_memload (RWX memory execution)..."
gcc -o test_memload test_memload.c -static
if [ $? -eq 0 ]; then
    echo "    ✓ Built: test_memload"
else
    echo "    ✗ Failed to build test_memload"
fi

# Build memfd execution test
echo "[2] Building test_memfd_exec (fileless execution)..."
gcc -o test_memfd_exec test_memfd_exec.c -static
if [ $? -eq 0 ]; then
    echo "    ✓ Built: test_memfd_exec"
else
    echo "    ✗ Failed to build test_memfd_exec"
fi

echo ""
echo "Build complete!"
echo ""
echo "Test samples:"
echo "  ./test_memload        - Allocates RWX memory and executes shellcode"
echo "  ./test_memfd_exec     - Creates memfd and executes ELF from memory"
echo ""
echo "Run with sandbox mode:"
echo "  sudo ./realtime_memdump_tool --sandbox ./test_memload"
echo "  sudo ./realtime_memdump_tool --sandbox ./test_memfd_exec"
echo ""
