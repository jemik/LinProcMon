#!/usr/bin/env python3
# Test Python script for sandbox monitoring

import os
import time
import socket

print("[TEST] Python test sample starting...")
time.sleep(1)

# Create file in /tmp
with open("/tmp/test_python_file.txt", "w") as f:
    f.write("test data from python\n")
print("[TEST] Created file in /tmp")

# Try to create a socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[TEST] Created socket")
    sock.close()
except Exception as e:
    print(f"[TEST] Socket creation: {e}")

# Fork a child process
pid = os.fork()
if pid == 0:
    # Child
    time.sleep(1)
    print("[TEST] Child process running")
    exit(0)
else:
    # Parent
    print(f"[TEST] Forked child process: {pid}")
    time.sleep(2)

print("[TEST] Python test complete")
