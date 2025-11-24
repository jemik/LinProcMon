#!/bin/bash
# Test immediate-write report generation

echo "=== Testing Immediate-Write Report Generation ==="
echo ""

# Compile the tool
echo "[1] Compiling..."
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lcrypto -lpthread -Wall -Wextra -O2
if [ $? -ne 0 ]; then
    echo "ERROR: Compilation failed!"
    exit 1
fi
echo "✓ Compilation successful"
echo ""

# Create a test malware sample that crashes immediately
echo "[2] Creating test sample that crashes..."
cat > /tmp/crash_test.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // Do some network activity
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // Create a file
    FILE *f = fopen("/tmp/malware_test_file.txt", "w");
    if (f) {
        fprintf(f, "malware was here\n");
        fclose(f);
    }
    
    printf("Malware activity complete, now crashing...\n");
    sleep(1);
    
    // Trigger segfault
    int *ptr = NULL;
    *ptr = 42;
    
    return 0;
}
EOF

gcc -o /tmp/crash_test /tmp/crash_test.c
echo "✓ Test sample created"
echo ""

# Run the monitoring tool in sandbox mode with short timeout
echo "[3] Running sandbox monitor (will auto-exit when sample crashes)..."
echo "Command: sudo ./realtime_memdump_tool -s /tmp/crash_test -t 10 -o /tmp/sandbox_crash_test"
echo ""

sudo ./realtime_memdump_tool -s /tmp/crash_test -t 10 -o /tmp/sandbox_crash_test

echo ""
echo "[4] Checking results..."
echo ""

# Check if report.json was created
if [ ! -f "/tmp/sandbox_crash_test/report.json" ]; then
    echo "ERROR: report.json not found!"
    exit 1
fi

echo "✓ report.json created"
echo ""

# Show the report structure
echo "[5] Report contents:"
echo ""
cat /tmp/sandbox_crash_test/report.json | python3 -m json.tool 2>&1
if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Valid JSON"
else
    echo ""
    echo "ERROR: Invalid JSON!"
    echo "Raw report:"
    cat /tmp/sandbox_crash_test/report.json
    exit 1
fi

echo ""
echo "[6] Checking temp files..."
ls -la /tmp/sandbox_crash_test/.*.tmp 2>/dev/null
echo ""

# Count sections
echo "[7] Report section summary:"
echo -n "  - Processes: "
cat /tmp/sandbox_crash_test/report.json | python3 -c "import json, sys; data=json.load(sys.stdin); print(len(data.get('processes', [])))"
echo -n "  - File operations: "
cat /tmp/sandbox_crash_test/report.json | python3 -c "import json, sys; data=json.load(sys.stdin); print(len(data.get('file_operations', [])))"
echo -n "  - Network activity: "
cat /tmp/sandbox_crash_test/report.json | python3 -c "import json, sys; data=json.load(sys.stdin); print(len(data.get('network_activity', [])))"
echo -n "  - Memory dumps: "
cat /tmp/sandbox_crash_test/report.json | python3 -c "import json, sys; data=json.load(sys.stdin); print(len(data.get('memory_dumps', [])))"

echo ""
echo ""
echo "=== Test Complete ==="
echo ""
echo "If all sections have data, the immediate-write solution is working!"
echo "If only 'analysis' section has data, the problem persists."
