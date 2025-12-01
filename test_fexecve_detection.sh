#!/bin/bash
#
# Test suite for fexecve detection
#

set -e

echo "========================================"
echo " Testing fexecve Detection"
echo "========================================"
echo ""

# Build everything first
if [ ! -f "ebpf_monitor.o" ] || [ ! -f "realtime_memdump_tool" ] || [ ! -f "ebpf_standalone" ]; then
    echo "[*] Building components..."
    ./build_all.sh
    echo ""
fi

# Test 1: Non-interactive test payload
if [ -f "test_loaders/test_fexecve_final" ]; then
    echo "[TEST 1] Non-interactive fexecve test"
    echo "----------------------------------------"
    sudo ./run_integrated.sh test_loaders/test_fexecve_final
    
    DUMPS=$(find sandbox_*/memory_dumps -name "*.bin" 2>/dev/null | wc -l)
    echo ""
    if [ "$DUMPS" -gt 0 ]; then
        echo "✓ TEST 1 PASSED: $DUMPS dump(s) created"
        ls -lh sandbox_*/memory_dumps/*.bin 2>/dev/null | tail -5
    else
        echo "✗ TEST 1 FAILED: No dumps created"
    fi
    echo ""
else
    echo "[TEST 1] Skipped - test_fexecve_final not built"
    echo "         Run: cd test_loaders && ./build_fexecve_test.sh"
    echo ""
fi

# Test 2: Interactive crackme (elf_shell)
if [ -f "/tmp/elf_shell" ]; then
    echo "[TEST 2] Interactive crackme (elf_shell)"
    echo "----------------------------------------"
    sudo timeout 5 ./run_integrated.sh /tmp/elf_shell || true
    
    DUMPS=$(find sandbox_*/memory_dumps -name "*.bin" 2>/dev/null | wc -l)
    echo ""
    if [ "$DUMPS" -gt 0 ]; then
        echo "✓ TEST 2 PASSED: $DUMPS dump(s) created"
        
        # Check for expected SHA1
        FOUND_SHA1=$(grep -h "SHA-1:" sandbox_*/memory_dumps/*.txt 2>/dev/null | grep "b62834851c23dea11256ec7fb4750365862e7843" | wc -l)
        if [ "$FOUND_SHA1" -gt 0 ]; then
            echo "✓ BONUS: Correct SHA1 hash found!"
        else
            echo "⚠ Warning: Expected SHA1 not found (might be different region)"
        fi
        
        ls -lh sandbox_*/memory_dumps/*.bin 2>/dev/null | tail -5
    else
        echo "✗ TEST 2 FAILED: No dumps created"
        echo ""
        echo "Debugging info:"
        echo "- Check eBPF events for PID in /tmp/ebpf_*.log"
        echo "- Look for 'execve()' events with comm='memfd:...'"
        echo "- Verify exit hooks are attached (should see 9 programs attached)"
    fi
    echo ""
else
    echo "[TEST 2] Skipped - /tmp/elf_shell not found"
    echo ""
fi

echo "========================================"
echo " Test Summary"
echo "========================================"
echo ""
echo "Expected behavior:"
echo "  - Non-interactive: Should dump payload (any size)"
echo "  - Interactive: Should dump 520KB with SHA1 b62834851..."
echo ""
echo "If tests fail, check:"
echo "  1. eBPF compiled with exit hooks (should attach 9 programs)"
echo "  2. Exit events appear in eBPF log"
echo "  3. Comm shows 'memfd:...' in exit events"
echo ""
