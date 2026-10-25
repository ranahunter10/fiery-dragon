#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run every unit-test file on its own (several share module names, e.g. run.py) and
# fail if any file fails. Prints one line per file so CI logs show where it broke.
set -u
cd "$(dirname "$0")/../.."
fail=0; n=0
while IFS= read -r t; do
    n=$((n + 1))
    if out=$(python3 -m unittest "$t" 2>&1); then
        echo "ok    $t: $(printf '%s\n' "$out" | grep -E '^Ran ' | tail -1)"
    else
        echo "FAIL  $t"; printf '%s\n' "$out" | tail -30; fail=$((fail + 1))
    fi
done < <(find bench tools schema -name 'test_*.py' -not -path '*/testdata/*' | sort)
echo "$n test files, $fail failed"
[ "$n" -gt 0 ] && [ "$fail" -eq 0 ]
