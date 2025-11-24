#!/bin/bash
# Test script to verify JSON report completion

echo "[*] Testing JSON report completion..."

# Create a simple test binary
cat > /tmp/test_sleep.c << 'EOF'
#include <unistd.h>
int main() {
    sleep(2);
    return 0;
}
EOF

gcc -o /tmp/test_sleep /tmp/test_sleep.c
chmod +x /tmp/test_sleep

# Run sandbox with timeout
echo "[*] Running sandbox for 2 seconds (process will exit naturally)..."
sudo ./realtime_memdump_tool --sandbox-timeout 1 --sandbox /tmp/test_sleep 2>&1 | tail -20

echo ""
echo "[*] Checking for report files..."
REPORT_DIR=$(ls -td sandbox_* 2>/dev/null | head -1)

if [ -z "$REPORT_DIR" ]; then
    echo "[!] ERROR: No sandbox directory found!"
    exit 1
fi

echo "[+] Found report directory: $REPORT_DIR"
echo ""

if [ -f "$REPORT_DIR/report.json" ]; then
    echo "[+] report.json exists"
    echo ""
    echo "[*] JSON content:"
    cat "$REPORT_DIR/report.json"
    echo ""
    
    # Validate JSON
    if command -v jq &> /dev/null; then
        echo "[*] Validating JSON with jq..."
        if jq empty "$REPORT_DIR/report.json" 2>&1; then
            echo "[+] JSON is valid!"
            
            # Check for required fields
            echo ""
            echo "[*] Checking required fields..."
            HAS_ANALYSIS=$(jq 'has("analysis")' "$REPORT_DIR/report.json")
            HAS_PROCESSES=$(jq 'has("processes")' "$REPORT_DIR/report.json")
            HAS_SUMMARY=$(jq 'has("summary")' "$REPORT_DIR/report.json")
            
            echo "  - analysis section: $HAS_ANALYSIS"
            echo "  - processes section: $HAS_PROCESSES"
            echo "  - summary section: $HAS_SUMMARY"
            
            if [ "$HAS_ANALYSIS" = "true" ] && [ "$HAS_PROCESSES" = "true" ] && [ "$HAS_SUMMARY" = "true" ]; then
                echo ""
                echo "[+] SUCCESS: Report is complete with all sections!"
                exit 0
            else
                echo ""
                echo "[!] ERROR: Report is missing sections!"
                exit 1
            fi
        else
            echo "[!] ERROR: JSON is invalid!"
            exit 1
        fi
    else
        echo "[*] jq not available, skipping JSON validation"
        
        # Basic check - does it have closing brace?
        if tail -1 "$REPORT_DIR/report.json" | grep -q '^}$'; then
            echo "[+] SUCCESS: Report appears complete (has closing brace)"
            exit 0
        else
            echo "[!] ERROR: Report appears incomplete (missing closing brace)"
            exit 1
        fi
    fi
else
    echo "[!] ERROR: report.json not found!"
    exit 1
fi

# Cleanup
rm -f /tmp/test_sleep /tmp/test_sleep.c
