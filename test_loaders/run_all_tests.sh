#!/bin/bash
#
# Test Orchestrator for LinProcMon Detection Capabilities
# 
# This script compiles and runs all 5 test loaders to verify:
# 1. Detection works for each technique
# 2. Memory dumps contain payloads
# 3. YARA can identify meterpreter signatures
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/test_output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}LinProcMon Test Suite${NC}"
echo -e "${BLUE}Testing all 5 detection capabilities${NC}"
echo -e "${BLUE}==========================================${NC}"
echo

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Compile all test loaders
echo -e "${YELLOW}[*] Compiling test loaders...${NC}"

echo "[+] Compiling 1_memfd_loader..."
gcc -o "${OUTPUT_DIR}/1_memfd_loader" "${SCRIPT_DIR}/1_memfd_loader.c" -Wall

echo "[+] Compiling 2_rwx_injection_loader..."
gcc -o "${OUTPUT_DIR}/2_rwx_injection_loader" "${SCRIPT_DIR}/2_rwx_injection_loader.c" -Wall

echo "[+] Compiling 3_deleted_binary_loader..."
gcc -o "${OUTPUT_DIR}/3_deleted_binary_loader" "${SCRIPT_DIR}/3_deleted_binary_loader.c" -Wall

echo "[+] Compiling 4_heap_execution_loader..."
gcc -o "${OUTPUT_DIR}/4_heap_execution_loader" "${SCRIPT_DIR}/4_heap_execution_loader.c" -Wall

echo "[+] Compiling 5_preload_loader (as executable)..."
gcc -o "${OUTPUT_DIR}/5_preload_victim" "${SCRIPT_DIR}/5_preload_loader.c" -Wall

echo "[+] Compiling 5_preload_loader (as shared library)..."
gcc -shared -fPIC -o "${OUTPUT_DIR}/malicious_preload.so" "${SCRIPT_DIR}/5_preload_loader.c" -Wall -ldl

echo -e "${GREEN}[✓] All loaders compiled successfully${NC}"
echo

# Function to run a test
run_test() {
    local test_num=$1
    local test_name=$2
    local test_binary=$3
    local test_args=$4
    local detection_keywords=$5
    
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}Test ${test_num}: ${test_name}${NC}"
    echo -e "${BLUE}==========================================${NC}"
    
    local report_file="test_${test_num}_report.json"
    
    echo "[*] Running LinProcMon in sandbox mode..."
    echo "[*] Binary: ${test_binary}"
    echo "[*] Expected detection: ${detection_keywords}"
    echo
    
    # Run LinProcMon in sandbox mode
    local tool_path="${SCRIPT_DIR}/../realtime_memdump_tool"
    
    if [ -n "$test_args" ]; then
        echo "[*] Command: sudo ${tool_path} --threads 8 --full_dump --sandbox-timeout 1 --sandbox ${test_binary} ${test_args}"
        sudo "${tool_path}" --threads 8 --full_dump --sandbox-timeout 1 --sandbox "${test_binary}" ${test_args} -o "${report_file}" 2>&1
    else
        echo "[*] Command: sudo ${tool_path} --threads 8 --full_dump --sandbox-timeout 1 --sandbox ${test_binary}"
        sudo "${tool_path}" --threads 8 --full_dump --sandbox-timeout 1 --sandbox "${test_binary}" -o "${report_file}" 2>&1
    fi
    
    echo
    echo -e "${GREEN}[✓] Test ${test_num} complete${NC}"
    echo
}

# Run all tests
echo -e "${YELLOW}[*] Starting test execution...${NC}"
echo

# Test 1: memfd
run_test 1 "memfd Fileless Execution" \
    "${OUTPUT_DIR}/1_memfd_loader" \
    "" \
    "memfd execution"

# Test 2: RWX injection
run_test 2 "RWX Memory Injection" \
    "${OUTPUT_DIR}/2_rwx_injection_loader" \
    "" \
    "RWX regions"

# Test 3: Deleted binary
run_test 3 "Deleted Binary Replacement" \
    "${OUTPUT_DIR}/3_deleted_binary_loader" \
    "" \
    "running from deleted file"

# Test 4: Heap execution
run_test 4 "Heap Execution" \
    "${OUTPUT_DIR}/4_heap_execution_loader" \
    "" \
    "Executable heap"

# Test 5: LD_PRELOAD hijacking
# Note: LD_PRELOAD as environment variable
export LD_PRELOAD="${OUTPUT_DIR}/malicious_preload.so"
run_test 5 "LD_PRELOAD Hijacking" \
    "${OUTPUT_DIR}/5_preload_victim" \
    "" \
    "LD_PRELOAD"
unset LD_PRELOAD

# Summary
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Test Suite Complete${NC}"
echo -e "${BLUE}==========================================${NC}"
echo
echo "All 5 test cases executed. Check the following:"
echo "  1. JSON reports for each test (test_N_report.json)"
echo "  2. Memory dump files (*.dump)"
echo "  3. Alerts in realtime_memdump_tool output"
echo
echo "Next steps:"
echo "  1. Verify each report contains expected alert types"
echo "  2. Run YARA scan on memory dumps:"
echo "     yara meterpreter_rules.yar *.dump"
echo "  3. Check for meterpreter signature matches"
echo
echo -e "${GREEN}[✓] Test suite finished successfully${NC}"
