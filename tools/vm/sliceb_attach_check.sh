#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Slice B attach-point check (ADR-0005, ADR-0015; design checks O1-O3 in
# docs/research/2026-11-09-slice-b-design-checks.md). Read-only: it reads the
# kernel config, BTF and tracefs, and loads nothing.
#   sudo tools/vm/sliceb_attach_check.sh OUT_FILE
# For each function slice B plans to hook it prints whether the kernel's BTF has
# it and whether ftrace can attach to it (available_filter_functions), the config
# options the design depends on, and which module BTFs are present.
set -euo pipefail

out=${1:?usage: sliceb_attach_check.sh OUT_FILE}
tracefs=/sys/kernel/tracing
[ -r "$tracefs/available_filter_functions" ] || { echo "tracefs not at $tracefs" >&2; exit 69; }
command -v bpftool >/dev/null || { echo "bpftool not found" >&2; exit 69; }

funcs=(
  security_file_open security_file_release security_file_free security_inode_free
  security_mmap_file security_file_mprotect
  vfs_read vfs_write vfs_readv vfs_writev
  do_splice do_sendfile vfs_copy_file_range vmsplice_to_pipe vmsplice_to_user do_tee
  security_inode_rename security_inode_unlink security_inode_link security_path_truncate
  vfs_rename vfs_unlink vfs_link do_truncate
  __fput do_file_open filename_unlinkat filename_renameat2
)
tps=(sock/sock_send_length sock/sock_recv_length io_uring/io_uring_complete
     io_uring/io_uring_submit_req io_uring/io_uring_cqe_overflow)
opts=(CONFIG_FPROBE CONFIG_FUNCTION_GRAPH_TRACER CONFIG_DYNAMIC_FTRACE_WITH_ARGS
      CONFIG_KPROBES CONFIG_PREEMPT_RCU CONFIG_PREEMPT_DYNAMIC CONFIG_SECURITY
      CONFIG_SECURITY_PATH CONFIG_BTRFS_FS CONFIG_OVERLAY_FS CONFIG_IO_URING
      CONFIG_IA32_EMULATION)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
btf_funcs=$tmp/btf_funcs
ftrace_funcs=$tmp/ftrace_funcs
config=$tmp/config
# Every source is read once, up front, so an unreadable one stops the run (set -e)
# instead of turning into a column of NO.
bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null \
  | sed -n "s/^\[[0-9]*\] FUNC '\([^']*\)'.*/\1/p" | sort -u > "$btf_funcs"
[ -s "$btf_funcs" ] || { echo "no FUNC entries read from /sys/kernel/btf/vmlinux" >&2; exit 69; }
cut -d' ' -f1 "$tracefs/available_filter_functions" | sort -u > "$ftrace_funcs"
[ -s "$ftrace_funcs" ] || { echo "available_filter_functions is empty" >&2; exit 69; }
if [ -r "/boot/config-$(uname -r)" ]; then
  cp "/boot/config-$(uname -r)" "$config"; config_src="/boot/config-$(uname -r)"
elif [ -r /proc/config.gz ]; then
  zcat /proc/config.gz > "$config"; config_src=/proc/config.gz
else
  echo "no kernel config at /boot/config-$(uname -r) or /proc/config.gz" >&2; exit 69
fi

{
  echo "== slice B attach check $(date -u +%Y-%m-%dT%H:%M:%SZ) kernel $(uname -r)"
  printf '%-28s %-4s %-6s\n' FUNCTION BTF FTRACE
  for f in "${funcs[@]}"; do
    b=NO; t=NO
    grep -qx "$f" "$btf_funcs" && b=yes
    grep -qx "$f" "$ftrace_funcs" && t=yes
    printf '%-28s %-4s %-6s\n' "$f" "$b" "$t"
  done
  echo "== tracepoints"
  for t in "${tps[@]}"; do
    if [ -d "$tracefs/events/$t" ]; then echo "yes  $t"; else echo "NO   $t"; fi
  done
  echo "== config ($config_src)"
  for o in "${opts[@]}"; do
    v=$(grep -E "^$o=|^# $o is not set" "$config" || true)
    echo "${v:-$o: absent}"
  done
  echo "== module BTF present"
  ls /sys/kernel/btf | grep -E '^(btrfs|overlay)$' || echo "(neither btrfs nor overlay loaded)"
  echo "== struct backing_file in vmlinux BTF"
  bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | sed -n '/^struct backing_file {/,/^};/p'
} > "$out"

sha256sum "$out"
