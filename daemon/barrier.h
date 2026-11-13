/* SPDX-License-Identifier: MIT */
/*
 * A grace-period barrier from user space (docs/research/2026-11-13-detach-fault-design.md §3.1).
 *
 * p15d changes what its BPF programs see by storing into their mapped globals (ADR-0026: no map
 * system call once attached). A store alone does not say when the programs have seen it: a
 * program run that read the old value may still be between that read and its next write, for as
 * long as its CPU is not scheduled by the host (E-0250). p15_barrier() returns only when every
 * program run that had started before the call has finished: membarrier(MEMBARRIER_CMD_GLOBAL)
 * is synchronize_rcu() (kernel/sched/membarrier.c at v7.0), and the programs run inside
 * rcu_read_lock (kernel/trace/bpf_trace.c). It is not a BPF system call and does not touch
 * bpf_prog_active.
 */
#ifndef P15_BARRIER_H
#define P15_BARRIER_H

#include "compiler.h"

/* 0 when the grace period has passed; -errno when the kernel refused (nohz_full, or no membarrier):
 * the caller's counts are then not exact, and it must say so, never sleep instead. test_fail: the
 * TEST ONLY switch --test-barrier-fail, which makes it report -ENOSYS without calling the kernel. */
P15_MUST_CHECK int p15_barrier(int test_fail);

#endif
