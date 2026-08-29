#!/usr/bin/env bash
# SPDX-License-Identifier: CC-BY-4.0
# Fetch and summarize results from a run-remote.sh launch.
set -euo pipefail
HOST="${1:?usage: collect-remote.sh <ssh-host> <remote-dir>}"
DIR="${2:?usage: collect-remote.sh <ssh-host> <remote-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/results"

scp -q -o BatchMode=yes "$HOST:~/$DIR/*.out" "$HERE/results/" 2>/dev/null || true

fail=0
for f in "$HERE"/results/*.out; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .out)
    if ! grep -q "Verification summary" "$f"; then
        echo "  $name: NO SUMMARY — still running, or did not terminate"
        continue
    fi
    if grep -q "is false" "$f"; then
        echo "  $name: FAILED"
        grep "is false" "$f" | sed 's/^/      /'
        fail=1
    else
        n=$(grep -c "is true" "$f")
        echo "  $name: all $n queries true"
    fi
done
exit "$fail"
