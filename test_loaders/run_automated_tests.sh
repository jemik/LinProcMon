#!/bin/bash
#
# Interactive Test Runner for LinProcMon
# Automates the complete test workflow for each loader
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_PATH="${SCRIPT_DIR}/../realtime_memdump_tool"
OUTPUT_DIR="${SCRIPT_DIR}/test_output"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] This script requires root privileges to run LinProcMon${NC}"
    echo -e "${YELLOW}[*] Please run: sudo $0${NC}"
    exit 1
fi

echo -e "${MAGENTA}╔════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║   LinProcMon Detection Capability Test Suite  ║${NC}"
echo -e "${MAGENTA}║   Automated Testing with YARA Verification    ║${NC}"
echo -e "${MAGENTA}╔════════════════════════════════════════════════╗${NC}"
echo

# Compile loaders first
if [ ! -d "$OUTPUT_DIR" ]; then
    echo -e "${YELLOW}[*] Compiling test loaders...${NC}"
    cd "$SCRIPT_DIR"
    ./compile_all.sh
    echo
fi

# Verify tool exists
if [ ! -f "$TOOL_PATH" ]; then
    echo -e "${RED}[!] LinProcMon tool not found: $TOOL_PATH${NC}"
    echo -e "${YELLOW}[*] Compile it first: make${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] All prerequisites met${NC}"
echo

# Function to run a single test with monitoring
run_monitored_test() {
    local test_num=$1
    local test_name=$2
    local test_binary=$3
    local test_args=$4
    local detection_keywords=$5
    
    echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Test ${test_num}: ${test_name}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
    
    # Report file location
    local report_file="${SCRIPT_DIR}/test${test_num}_report.json"
    
    echo -e "${YELLOW}[*] Expected detection: ${detection_keywords}${NC}"
    echo -e "${CYAN}[*] Starting LinProcMon in sandbox mode...${NC}"
    echo -e "${YELLOW}    Report: ${report_file}${NC}"
    echo
    
    # Run LinProcMon in sandbox mode
    if [ -n "$test_args" ]; then
        "$TOOL_PATH" --threads 8 --full_dump --sandbox-timeout 1 --sandbox "$test_binary" $test_args -o "$report_file" 2>&1 | while IFS= read -r line; do
            # Highlight alerts
            if [[ "$line" =~ "ALERT" ]] || [[ "$line" =~ "WARN" ]]; then
                echo -e "${RED}${line}${NC}"
            elif [[ "$line" =~ "Dumping" ]] || [[ "$line" =~ "saved" ]]; then
                echo -e "${GREEN}${line}${NC}"
            else
                echo "$line"
            fi
        done || true
    else
        "$TOOL_PATH" --threads 8 --full_dump --sandbox-timeout 1 --sandbox "$test_binary" -o "$report_file" 2>&1 | while IFS= read -r line; do
            # Highlight alerts
            if [[ "$line" =~ "ALERT" ]] || [[ "$line" =~ "WARN" ]]; then
                echo -e "${RED}${line}${NC}"
            elif [[ "$line" =~ "Dumping" ]] || [[ "$line" =~ "saved" ]]; then
                echo -e "${GREEN}${line}${NC}"
            else
                echo "$line"
            fi
        done || true
    fi
    
    echo
    echo -e "${YELLOW}[*] Checking test results...${NC}"
    
    # Verify report was created
    if [ -f "$report_file" ]; then
        echo -e "${GREEN}[✓] Report generated: $report_file${NC}"
        
        # Count alerts
        if command -v jq &> /dev/null; then
            local alert_count=$(jq '.alerts | length' "$report_file" 2>/dev/null || echo "0")
            echo -e "${GREEN}[✓] Alerts found: ${alert_count}${NC}"
        fi
    else
        echo -e "${RED}[!] No report generated${NC}"
    fi
    
    # Check for memory dumps
    local dump_count=$(find "$SCRIPT_DIR" -name "test${test_num}_report.json_*_memory.dump" 2>/dev/null | wc -l)
    if [ $dump_count -gt 0 ]; then
        echo -e "${GREEN}[✓] Memory dumps created: ${dump_count}${NC}"
    else
        echo -e "${YELLOW}[!] No memory dumps found${NC}"
    fi
    
    echo -e "${GREEN}[✓] Test ${test_num} complete${NC}"
    echo
    
    # Pause between tests
    sleep 2
}

# Run all tests
echo -e "${YELLOW}[*] Running all 5 test cases...${NC}"
echo

run_monitored_test 1 "memfd Fileless Execution" \
    "${OUTPUT_DIR}/1_memfd_loader" \
    "" \
    "memfd execution"

run_monitored_test 2 "RWX Memory Injection" \
    "${OUTPUT_DIR}/2_rwx_injection_loader" \
    "" \
    "RWX regions"

run_monitored_test 3 "Deleted Binary Replacement" \
    "${OUTPUT_DIR}/3_deleted_binary_loader" \
    "" \
    "running from deleted file"

run_monitored_test 4 "Heap Execution" \
    "${OUTPUT_DIR}/4_heap_execution_loader" \
    "" \
    "Executable heap"

run_monitored_test 5 "LD_PRELOAD Hijacking" \
    "${OUTPUT_DIR}/5_preload_victim" \
    "" \
    "LD_PRELOAD"

# Summary
echo -e "${MAGENTA}╔════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║              Test Suite Complete               ║${NC}"
echo -e "${MAGENTA}╚════════════════════════════════════════════════╝${NC}"
echo

echo -e "${CYAN}[*] Scanning memory dumps with YARA...${NC}"
echo

# Run YARA scan
cd "$SCRIPT_DIR"
if ./scan_dumps.sh; then
    echo -e "${GREEN}[✓] YARA scan completed successfully${NC}"
else
    echo -e "${YELLOW}[!] YARA scan had warnings (this may be normal)${NC}"
fi

echo
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"
echo -e "${CYAN}Summary:${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════${NC}"

# Count reports
REPORT_COUNT=$(ls -1 test*_report.json 2>/dev/null | wc -l)
echo "  Reports generated: $REPORT_COUNT / 5"

# Count dumps
DUMP_COUNT=$(ls -1 *.dump 2>/dev/null | wc -l)
echo "  Memory dumps: $DUMP_COUNT"

# Check YARA availability
if command -v yara &> /dev/null; then
    echo "  YARA: Available"
else
    echo "  YARA: Not installed (scan skipped)"
fi

echo
echo -e "${CYAN}Next Steps:${NC}"
echo "  1. Review JSON reports: test*_report.json"
echo "  2. Check memory dumps: *.dump"
echo "  3. Verify alerts match expected detections"
echo "  4. Confirm YARA matches meterpreter signatures"
echo
echo -e "${GREEN}[✓] Automated test suite finished${NC}"
