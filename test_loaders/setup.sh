#!/bin/bash
# Quick test - just make scripts executable
chmod +x *.sh
echo "All scripts are now executable"
echo ""
echo "To run tests:"
echo "  ./compile_all.sh          - Compile all loaders"
echo "  sudo ./run_automated_tests.sh - Run full automated test suite"
echo "  ./run_all_tests.sh        - Interactive test runner"
echo "  ./scan_dumps.sh           - Scan dumps with YARA"
