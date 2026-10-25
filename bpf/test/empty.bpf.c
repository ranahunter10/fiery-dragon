// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * empty.bpf.c: the CI skeleton's BPF smoke test. It has no logic; it proves
 * that the toolchain builds a BPF object with BTF and that the kernel's
 * verifier accepts the two program types the spine relies on (blueprint v1
 * §10, Phase 0 gate). Replaced by the real programs in Phase 1.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* tp_btf: how the spine attaches to sched_process_{fork,exec,exit} and task_rename. */
SEC("tp_btf/sched_process_exec")
int fd_empty_exec(unsigned long long *ctx)
{
	return 0;
}

/* syscall: the program type used to execute BPF logic in tests (BPF_PROG_RUN). */
SEC("syscall")
int fd_empty_syscall(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
