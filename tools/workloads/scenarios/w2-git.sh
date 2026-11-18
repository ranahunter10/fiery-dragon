#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: light
# git: a shallow clone of this repository over file://, then log, status and grep in the clone.
# Light trace (processes, opens, connects): pack files make byte-level strace logs very large.
set -eu
W=$1
# the harness runs as root and the repo belongs to its user: -c reaches upload-pack through
# GIT_CONFIG_PARAMETERS, so git does not refuse the clone for "dubious ownership"
git -c safe.directory="*" clone -q --depth 30 "file://$P15_REPO" "$W/r"
git -C "$W/r" log --oneline | wc -l
git -C "$W/r" status --short | wc -l
git -C "$W/r" grep -l ADR -- docs | wc -l
