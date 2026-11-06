/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Kernel facts the BPF programs need that vmlinux.h does not carry (macros are not in BTF).
 * Each names its source in the v7.0 tree.
 */
#ifndef P15_KERNEL_H
#define P15_KERNEL_H

/* Multigrain timestamps (include/linux/fs.h, since 6.13): bit 31 of inode->i_ctime_nsec is the
 * I_CTIME_QUERIED flag, not part of the time; inode_get_ctime_nsec() masks it off. A raw read
 * must do the same. Safe on any kernel: a real nanosecond value is below 10^9 < 2^30. Found by
 * the spine self-test, whose record was 2^31 ns above stat(2)'s ctime. */
#define P15_CTIME_NSEC_MASK 0x7fffffffu

#endif
