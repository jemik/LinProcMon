#!/bin/bash
# Quick test runner for malware samples

cd /workspaces/LinProcMon

echo "=========================================="
echo "Building Test Samples"
echo "=========================================="
chmod +x build_tests.sh
./build_tests.sh

echo ""
echo "=========================================="
echo "Test 1: RWX Memory Execution"
echo "=========================================="
echo "Running: sudo ./realtime_memdump_tool --sandbox ./test_memload"
timeout 10 sudo ./realtime_memdump_tool --sandbox ./test_memload 2>&1 | grep -E "SANDBOX|ALERT|TEST"

echo ""
echo "=========================================="
echo "Test 2: Memfd Execution (Fileless)"
echo "=========================================="
echo "Running: sudo ./realtime_memdump_tool --sandbox ./test_memfd_exec"
timeout 10 sudo ./realtime_memdump_tool --sandbox ./test_memfd_exec 2>&1 | grep -E "SANDBOX|ALERT|TEST|memfd"

echo ""
echo "=========================================="
echo "Tests Complete"
echo "=========================================="
