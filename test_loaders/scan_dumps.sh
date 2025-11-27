#!/bin/bash
#
# YARA Scanner for Memory Dumps
# 
# This script scans all memory dumps with meterpreter detection rules
# and generates a report of matches
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="${SCRIPT_DIR}/meterpreter_detection.yar"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}YARA Scanner for Meterpreter Detection${NC}"
echo -e "${BLUE}==========================================${NC}"
echo

# Check if YARA is installed
if ! command -v yara &> /dev/null; then
    echo -e "${RED}[!] YARA not found. Installing...${NC}"
    sudo apt-get update
    sudo apt-get install -y yara
    echo -e "${GREEN}[✓] YARA installed${NC}"
    echo
fi

# Find all .dump files
DUMP_FILES=$(find . -name "*.dump" 2>/dev/null)

if [ -z "$DUMP_FILES" ]; then
    echo -e "${YELLOW}[!] No .dump files found${NC}"
    echo "[*] Run the test loaders first and capture memory dumps"
    exit 1
fi

echo -e "${GREEN}[+] Found memory dump files:${NC}"
echo "$DUMP_FILES" | while read -r file; do
    echo "    - $file"
done
echo

# Scan each dump file
echo -e "${YELLOW}[*] Scanning memory dumps with YARA rules...${NC}"
echo

TOTAL_MATCHES=0

for dump_file in $DUMP_FILES; do
    echo -e "${BLUE}----------------------------------------${NC}"
    echo -e "${BLUE}Scanning: $(basename $dump_file)${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    
    # Run YARA scan
    MATCHES=$(yara -s -w "$RULES_FILE" "$dump_file" 2>/dev/null || true)
    
    if [ -n "$MATCHES" ]; then
        echo -e "${GREEN}[✓] Detections found:${NC}"
        echo "$MATCHES"
        MATCH_COUNT=$(echo "$MATCHES" | grep -c "^" || true)
        TOTAL_MATCHES=$((TOTAL_MATCHES + MATCH_COUNT))
    else
        echo -e "${YELLOW}[!] No matches in this dump${NC}"
    fi
    echo
done

# Summary
echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}Scan Summary${NC}"
echo -e "${BLUE}==========================================${NC}"
echo
echo "Total memory dumps scanned: $(echo "$DUMP_FILES" | wc -l)"
echo "Total YARA rule matches: $TOTAL_MATCHES"
echo

if [ $TOTAL_MATCHES -gt 0 ]; then
    echo -e "${GREEN}[✓] Successfully detected meterpreter signatures in memory dumps${NC}"
    echo -e "${GREEN}[✓] LinProcMon correctly captured malicious payloads${NC}"
else
    echo -e "${YELLOW}[!] No meterpreter signatures detected${NC}"
    echo "[*] This could mean:"
    echo "    1. Memory dumps don't contain the payload"
    echo "    2. YARA rules need adjustment"
    echo "    3. Test loaders need to run longer"
fi

echo
echo "For detailed analysis, run:"
echo "  yara -s -m $RULES_FILE <dump_file>"
