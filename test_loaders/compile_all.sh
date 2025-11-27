#!/bin/bash
#
# Compile all test loaders
#

set -e

echo "Compiling test loaders..."
echo

mkdir -p test_output

echo "[1/5] Compiling memfd loader..."
gcc -o test_output/1_memfd_loader 1_memfd_loader.c -Wall
echo "  ✓ test_output/1_memfd_loader"

echo "[2/5] Compiling RWX injection loader..."
gcc -o test_output/2_rwx_injection_loader 2_rwx_injection_loader.c -Wall
echo "  ✓ test_output/2_rwx_injection_loader"

echo "[3/5] Compiling deleted binary loader..."
gcc -o test_output/3_deleted_binary_loader 3_deleted_binary_loader.c -Wall
echo "  ✓ test_output/3_deleted_binary_loader"

echo "[4/5] Compiling heap execution loader..."
gcc -o test_output/4_heap_execution_loader 4_heap_execution_loader.c -Wall
echo "  ✓ test_output/4_heap_execution_loader"

echo "[5/5] Compiling LD_PRELOAD loader (executable)..."
gcc -o test_output/5_preload_victim 5_preload_loader.c -Wall
echo "  ✓ test_output/5_preload_victim"

echo "[5/5] Compiling LD_PRELOAD loader (shared library)..."
gcc -shared -fPIC -o test_output/malicious_preload.so 5_preload_loader.c -Wall -ldl
echo "  ✓ test_output/malicious_preload.so"

echo
echo "All loaders compiled successfully!"
echo
echo "To run tests:"
echo "  ./run_all_tests.sh          (automated)"
echo "  cd test_output && ./1_memfd_loader    (manual)"
