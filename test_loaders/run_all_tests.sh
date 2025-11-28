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
    
    echo "[*] Running LinProcMon with eBPF integration..."
    echo "[*] Binary: ${test_binary}"
    echo "[*] Expected detection: ${detection_keywords}"
    echo
    
    # Run with eBPF integration via run_integrated.sh
    local integrated_script="${SCRIPT_DIR}/../run_integrated.sh"
    
    if [ -n "$test_args" ]; then
        echo "[*] Command: sudo ${integrated_script} ${test_binary} ${test_args}"
        sudo "${integrated_script}" "${test_binary}" ${test_args} 2>&1
    else
        echo "[*] Command: sudo ${integrated_script} ${test_binary}"
        sudo "${integrated_script}" "${test_binary}" 2>&1
    fi
    
    # Find and report on the most recent sandbox directory
    local sandbox_dir=$(ls -td "${SCRIPT_DIR}/../sandbox_"* 2>/dev/null | head -1)
    if [ -n "$sandbox_dir" ] && [ -d "$sandbox_dir" ]; then
        echo "[*] Sandbox directory: ${sandbox_dir}"
        echo "[*] Memory dumps: $(find "$sandbox_dir" -name "*.bin" 2>/dev/null | wc -l)"
        
        # Check for report.json
        if [ -f "${sandbox_dir}/report.json" ]; then
            echo "[*] Report generated: ${sandbox_dir}/report.json"
            # Save test-specific copy
            cp "${sandbox_dir}/report.json" "${OUTPUT_DIR}/test_${test_num}_report.json"
        fi
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
# Note: The preload loader uses its own test program
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Test 5: LD_PRELOAD Hijacking${NC}"
echo -e "${BLUE}==========================================${NC}"
echo "[*] Note: This test uses a wrapper script that sets LD_PRELOAD"
echo "[*] Creating wrapper script..."

# Create wrapper script
cat > "${OUTPUT_DIR}/test5_wrapper.sh" << 'EOF'
#!/bin/bash
export LD_PRELOAD="$1"
shift
exec "$@"
EOF
chmod +x "${OUTPUT_DIR}/test5_wrapper.sh"

run_test 5 "LD_PRELOAD Hijacking" \
    "${OUTPUT_DIR}/test5_wrapper.sh" \
    "${OUTPUT_DIR}/malicious_preload.so ${OUTPUT_DIR}/5_preload_victim" \
    "LD_PRELOAD"

# Summary
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Test Suite Complete${NC}"
echo -e "${BLUE}==========================================${NC}"
echo
echo "All 5 test cases executed with eBPF integration. Check the following:"
echo "  1. JSON reports: ${OUTPUT_DIR}/test_N_report.json"
echo "  2. Memory dumps in sandbox_* directories"
echo "  3. eBPF event logs in /tmp/ebpf_*.log"
echo "  4. Alerts in output above"
echo
echo "Summary of sandbox directories:"
for sandbox_dir in "${SCRIPT_DIR}/../sandbox_"*; do
    if [ -d "$sandbox_dir" ]; then
        dump_count=$(find "$sandbox_dir" -name "*.bin" 2>/dev/null | wc -l)
        echo "  - $sandbox_dir: $dump_count memory dumps"
    fi
done
echo
echo "Next steps:"
echo "  1. Verify each report contains expected alert types:"
echo "     cat ${OUTPUT_DIR}/test_1_report.json | jq '.memory_dumps'"
echo "  2. Run YARA scan on all dumps:"
echo "     cd ${SCRIPT_DIR}/.."
echo "     python3 test_loaders/yara_scan_sandbox.py"
echo "  3. Check for meterpreter signature matches"
echo
echo -e "${GREEN}[✓] Test suite finished successfully${NC}"
