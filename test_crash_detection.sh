#!/bin/bash
# Test script to demonstrate tool crash detection

echo "=== Tool Crash Detection Tests ==="
echo ""

# Compile the tool first
echo "[1/4] Compiling realtime_memdump_tool..."
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lssl -lcrypto -lpthread -O2 -Wall 2>&1 | tail -n 5
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi
echo "✓ Compilation successful"
echo ""

# Test 1: Normal completion
echo "[2/4] Testing normal completion (exit code 0)..."
sudo ./realtime_memdump_tool --sandbox /bin/true > /dev/null 2>&1
REPORT_DIR=$(ls -td analysis_* 2>/dev/null | head -1)
if [ -f "$REPORT_DIR/report.json" ]; then
    echo "Sample termination:"
    grep -A 3 '"termination_status"' "$REPORT_DIR/report.json" | grep -v "^--$"
    echo ""
fi

# Test 2: Error exit
echo "[3/4] Testing error exit (exit code 1)..."
sudo ./realtime_memdump_tool --sandbox /bin/false > /dev/null 2>&1
REPORT_DIR=$(ls -td analysis_* 2>/dev/null | head -1)
if [ -f "$REPORT_DIR/report.json" ]; then
    echo "Sample termination:"
    grep -A 3 '"termination_status"' "$REPORT_DIR/report.json" | grep -v "^--$"
    echo ""
fi

# Test 3: Create a simple crashing program
echo "[4/4] Testing sample that crashes (segfault)..."
cat > /tmp/crash_test.c << 'EOF'
#include <stdio.h>
int main() {
    printf("About to crash...\n");
    int *ptr = NULL;
    *ptr = 42;  // Segfault
    return 0;
}
EOF

gcc -o /tmp/crash_test /tmp/crash_test.c 2>/dev/null
if [ -f /tmp/crash_test ]; then
    sudo ./realtime_memdump_tool --sandbox /tmp/crash_test > /dev/null 2>&1
    REPORT_DIR=$(ls -td analysis_* 2>/dev/null | head -1)
    if [ -f "$REPORT_DIR/report.json" ]; then
        echo "Sample termination:"
        grep -A 3 '"termination_status"' "$REPORT_DIR/report.json" | grep -v "^--$"
        echo ""
    fi
    rm -f /tmp/crash_test /tmp/crash_test.c
fi

echo ""
echo "=== Test Summary ==="
echo "Check the analysis_* directories for full JSON reports"
echo ""
echo "Expected outcomes:"
echo "  - Test 1: termination_status: 'completed', exit_code: 0"
echo "  - Test 2: termination_status: 'error', exit_code: 1"
echo "  - Test 3: termination_status: 'crashed', exit_code: 11 (SIGSEGV)"
echo ""
echo "If a sample causes the tool itself to crash, you'll see:"
echo "  - tool_crashed: true"
echo "  - crash_reason: 'Monitoring tool crashed with signal X'"
