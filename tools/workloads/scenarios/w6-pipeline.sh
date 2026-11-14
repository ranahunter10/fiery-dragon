#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# A shell pipeline: find, xargs, cat, tr, sort, uniq and head over the system's copyright files:
# many processes joined by pipes.
set -eu
W=$1
find /usr/share/doc -name copyright | head -300 | xargs cat | tr -s ' \t' '\n\n' | sort | uniq -c | sort -rn | head -50 >"$W/top.txt"
wc -l "$W/top.txt"
