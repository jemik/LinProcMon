#!/bin/bash
set -e
echo "Recompiling realtime_memdump_tool..."
gcc -o realtime_memdump_tool realtime_memdump_tool.c -lpthread
echo "Done! Binary ready to test."
