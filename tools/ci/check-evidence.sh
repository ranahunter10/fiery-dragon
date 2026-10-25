#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Verify every SHA256SUMS under docs/evidence/: raw evidence must stay byte for byte.
set -u
cd "$(dirname "$0")/../.."
fail=0; n=0
while IFS= read -r s; do
    n=$((n + 1))
    if (cd "$(dirname "$s")" && sha256sum -c --quiet SHA256SUMS); then
        echo "ok    $s"
    else
        echo "FAIL  $s"; fail=$((fail + 1))
    fi
done < <(find docs/evidence -name SHA256SUMS | sort)
echo "$n checksum files, $fail failed"
[ "$n" -gt 0 ] && [ "$fail" -eq 0 ]
