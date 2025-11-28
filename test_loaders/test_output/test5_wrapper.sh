#!/bin/bash
export LD_PRELOAD="$1"
shift
exec "$@"
