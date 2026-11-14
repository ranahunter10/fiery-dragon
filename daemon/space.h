/* SPDX-License-Identifier: MIT */
/*
 * The WAL's free-space guard (the design review's F-02; docs/research/2026-11-14-full-disk.md).
 *
 * A full disk used to end the run: the first failed write made the WAL fail for good, and p15d
 * exited INVALID with capture gone for the rest of the boot. The guard follows auditd's tiers
 * (auditd.conf(5): space_left, admin_space_left, disk_full_action): before the disk is full, p15d
 * sheds what it can best afford to lose, says so, and keeps running.
 *
 *   level 0 OK         every ring is written;
 *   level 1 SHED_BULK  free space < low: the bulk ring (NET, file identity, data flow) is shed;
 *   level 2 SHED_ALL   free space < reserve: the spine is shed too. Only the daemon ring (STATS,
 *                      the guard's own WAL_SPACE records, END), a few hundred bytes a second, is
 *                      written, into the reserve.
 * A level is left only when free space is back above its threshold plus a margin (hysteresis), so
 * a disk at the edge does not flap. Every shed record is counted, a WAL_SPACE record marks each
 * change of level, and the run is DEGRADED from the first shed record.
 *
 * Free space is read with fstatvfs at most once per refresh (the writer's loop, at least every
 * P15_WRITER_WAIT_MAX_MS) and lowered by every byte written in between, so the check before a
 * batch costs no system call.
 *
 * This module only decides; the writer counts and writes (writer.c). Pure logic, tested in
 * daemon/tests/test_space.c with an injected free-space reader.
 */
#ifndef P15_SPACE_H
#define P15_SPACE_H

#include <stdint.h>

#define P15_SPACE_OK 0
#define P15_SPACE_SHED_BULK 1
#define P15_SPACE_SHED_ALL 2

/* auto sizes (when the options are 0): the smaller of a fixed size and a share of the filesystem */
#define P15_SPACE_LOW_MAX (512ull << 20)
#define P15_SPACE_LOW_PCT 10
#define P15_SPACE_RESERVE_MAX (64ull << 20)
#define P15_SPACE_RESERVE_PCT 2
#define P15_SPACE_RESERVE_MIN (4ull << 20)     /* room for the daemon ring and one segment header */

/* reads the bytes available to an unprivileged writer and the filesystem's size; 0 or -errno */
typedef int (*p15_space_statfs_fn)(int fd, uint64_t *avail, uint64_t *total);

struct p15_space {
	int on;                     /* 0: the guard is off (--wal-space-guard 0): every ring always allowed */
	uint64_t low, reserve;      /* bytes */
	int level;
	uint64_t avail;             /* the estimate: the last reading less what was written since */
	uint64_t total;
	uint64_t refreshes, refresh_errors, transitions;
	p15_space_statfs_fn statfs; /* NULL: fstatvfs */
};

/* The thresholds for a filesystem of `total` bytes: low_mb and reserve_mb as given, or auto when 0.
 * The reserve is at least P15_SPACE_RESERVE_MIN and below low (low is raised to reserve * 2 if
 * needed). */
void p15_space_sizes(uint64_t total, uint32_t low_mb, uint32_t reserve_mb, uint64_t *low, uint64_t *reserve);
void p15_space_init(struct p15_space *s, int on, uint64_t low, uint64_t reserve);
/* Read the free space of the filesystem holding fd. Returns 1 if the level changed, 0 if not, or
 * -errno if it could not be read (the level and the estimate are kept; counted). */
int p15_space_refresh(struct p15_space *s, int fd);
/* `bytes` were written: lower the estimate. Returns 1 if that changed the level. */
int p15_space_wrote(struct p15_space *s, uint64_t bytes);
/* A write failed with ENOSPC: the estimate drops to 0 (level SHED_ALL) until the next refresh. */
void p15_space_full(struct p15_space *s);
/* May a batch of ring `ring` (P15W_RING_*) be written at the current level? */
int p15_space_allows(const struct p15_space *s, unsigned ring);
const char *p15_space_level_name(int level);

#endif
