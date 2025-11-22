#!/bin/bash
# Test script to verify sandbox monitoring

echo "[TEST] Starting test sample..."
sleep 1

# Create a file in /tmp
echo "test data" > /tmp/test_sandbox_file.txt
echo "[TEST] Created file in /tmp"

# Fork a child process
(sleep 1; echo "[TEST] Child process running") &

# Create another file
echo "more data" > /tmp/test_sandbox_file2.txt
echo "[TEST] Created second file"

echo "more data" > test_sandbox_file3.txt
echo "[TEST] Created second file"

sleep 2
echo "[TEST] Test sample complete"
