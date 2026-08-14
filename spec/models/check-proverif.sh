#!/usr/bin/env bash
# Run a ProVerif model and require POSITIVE confirmation that every expected
# query returned true.
#
# The obvious check — `grep "is false"` — is wrong, and dangerously so: a model
# that times out or errors produces no output at all, so "no failures found"
# passes a run that never verified anything. This script instead counts
# `is true` and compares against the expected number, and checks the exit
# status of proverif rather than of a pipeline.
#
# Usage: check-proverif.sh <model.pv> <timeout_seconds> <expected_true_queries>
set -uo pipefail

model="${1:?model path}"
limit="${2:?timeout seconds}"
expected="${3:?expected number of passing queries}"
out="$(mktemp)"

timeout "$limit" proverif "$model" > "$out" 2>&1
status=$?

sed -n '/Verification summary/,$p' "$out"

if [ "$status" -eq 124 ]; then
    echo "::error::$model did not terminate within ${limit}s — NOT verified"
    exit 1
fi
if [ "$status" -ne 0 ]; then
    echo "::error::proverif exited $status on $model"
    tail -20 "$out"
    exit 1
fi

# Count ONLY inside the summary: ProVerif also prints each result inline as it
# works, so counting the whole file double-counts every query.
summary="$(sed -n '/Verification summary/,$p' "$out")"
false_count=$(printf '%s' "$summary" | grep -c "is false" || true)
true_count=$(printf '%s' "$summary" | grep -c "is true" || true)

if [ -z "$summary" ]; then
    echo "::error::$model produced no verification summary — NOT verified"
    exit 1
fi

if [ "$false_count" -ne 0 ]; then
    echo "::error::$model — $false_count query/queries returned false"
    exit 1
fi
if [ "$true_count" -ne "$expected" ]; then
    echo "::error::$model — expected $expected passing queries, saw $true_count."
    echo "Either a query was removed, or the run did not complete."
    exit 1
fi

echo "$model: $true_count/$expected queries verified."
