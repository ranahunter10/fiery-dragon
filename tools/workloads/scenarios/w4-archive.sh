#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# An archive round trip: the repo's docs copied, tarred and gzipped, checksummed, unpacked
# elsewhere and compared file by file.
set -eu
W=$1
cp -r "$P15_REPO/docs" "$W/d"
tar czf "$W/d.tgz" -C "$W" d
sha256sum "$W/d.tgz"
mkdir "$W/x"
tar xzf "$W/d.tgz" -C "$W/x"
diff -r "$W/d" "$W/x/d" && echo identical
