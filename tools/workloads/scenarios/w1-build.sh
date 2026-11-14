#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# trace: full
# A real C build: libbpf's sources and headers (the repo's submodule, copied) compiled into a static library
# with make -j3: make, the compiler driver, cc1, the assembler and ar, many short processes and files.
set -eu
W=$1
mkdir "$W/libbpf"
cp -r "$P15_REPO/third_party/libbpf/src" "$P15_REPO/third_party/libbpf/include" "$W/libbpf/"
make -s -C "$W/libbpf/src" -j3 BUILD_STATIC_ONLY=y OBJDIR="$W/obj" >/dev/null
ls -l "$W/obj/libbpf.a"
