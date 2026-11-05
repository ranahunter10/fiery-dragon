// SPDX-License-Identifier: MIT
#include "records.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static size_t fixed_size(__u16 type, __u16 version)
{
	switch (type) {
	case P15_T_FORK:   return version == 1 ? sizeof(struct p15_fork_v1) : 0;
	case P15_T_EXEC:   return version == 1 ? sizeof(struct p15_exec_v1) : 0;
	case P15_T_EXIT:   return version == 1 ? sizeof(struct p15_exit_v1) : 0;
	case P15_T_RENAME: return version == 1 ? sizeof(struct p15_rename_v1) : 0;
	case P15_T_CLOCK_SYNC: return version == 1 ? sizeof(struct p15_clock_sync_v1) : 0;
	case P15_T_STATS:  return version == 1 ? sizeof(struct p15_stats_v1) : 0;
	case P15_T_GAP:    return version == 1 ? sizeof(struct p15_gap_v1) : 0;
	case P15_T_END:    return version == 1 ? sizeof(struct p15_end_v1) : 0;
	}
	return 0;
}

/*
 * The variable fields of a record take `used` bytes after its fixed part. They must end inside
 * len; len must be exactly their padded end, unless `slack_ok`; and every byte after them up to
 * len must be zero. EXEC is built in a reused per-CPU scratch buffer (ADR-0017), so a padding
 * bug would otherwise carry an earlier record's bytes into this one.
 */
static int check_tail(const void *data, size_t fixed, size_t used, int slack_ok, const char **why)
{
	const struct p15_hdr *h = data;

	if (fixed + used > h->len) {
		*why = "variable field beyond len";
		return -EINVAL;
	}
	if (h->len != ((fixed + used + 7) & ~(size_t)7) && !slack_ok) {
		*why = "len larger than its fields need";
		return -EINVAL;
	}
	for (size_t i = fixed + used; i < h->len; i++)
		if (((const __u8 *)data)[i]) {
			*why = "non-zero bytes after the variable fields";
			return -EINVAL;
		}
	return 0;
}

int p15_rec_check(const void *data, size_t size, const char **why)
{
	const struct p15_hdr *h = data;
	size_t fixed;

	if (size < sizeof(*h)) {
		*why = "shorter than the header";
		return -EINVAL;
	}
	if (h->len > size) {
		*why = "len beyond the bytes received";
		return -EINVAL;
	}
	if (h->len % 8) {
		*why = "len not a multiple of 8";
		return -EINVAL;
	}
	fixed = fixed_size(h->type, h->version);
	if (!fixed) {
		*why = "unknown type or version";
		return -EINVAL;
	}
	if (h->len < fixed) {
		*why = "len shorter than the fixed part";
		return -EINVAL;
	}
	if (h->type == P15_T_EXEC) {
		const struct p15_exec_v1 *e = data;

		if (e->filename_len > P15_EXEC_V1_FILENAME_MAX || e->argv_len > P15_EXEC_V1_ARGV_MAX) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		/* slack only after a failed read: the DYNPTR way keeps its reservation */
		if (check_tail(data, fixed, (size_t)e->filename_len + e->argv_len, h->flags & P15_F_READ_FAILED, why))
			return -EINVAL;
	} else if (h->type == P15_T_END) {
		const struct p15_end_v1 *e = data;

		if (e->reason_len > P15_END_V1_REASON_MAX) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (check_tail(data, fixed, e->reason_len, 0, why))
			return -EINVAL;
	} else if (h->len != fixed) {
		*why = "len differs from the fixed size";
		return -EINVAL;
	}
	*why = NULL;
	return 0;
}

const __u8 *p15_exec_filename(const struct p15_exec *r, __u16 *len)
{
	*len = r->filename_len;
	return (const __u8 *)(r + 1);
}

const __u8 *p15_exec_argv(const struct p15_exec *r, __u16 *len)
{
	*len = r->argv_len;
	return (const __u8 *)(r + 1) + r->filename_len;
}

/* printable copy of a byte string: NUL -> ' ', other non-printables -> '.' */
static void printable(char *dst, size_t n, const __u8 *src, size_t len)
{
	size_t i;

	if (!n)
		return;
	for (i = 0; i < len && i + 1 < n; i++)
		dst[i] = src[i] == 0 ? ' ' : (src[i] < 32 || src[i] > 126) ? '.' : (char)src[i];
	dst[i] = '\0';
}

const char *p15_type_name(__u16 type)
{
	switch (type) {
	case P15_T_FORK:       return "FORK";
	case P15_T_EXEC:       return "EXEC";
	case P15_T_EXIT:       return "EXIT";
	case P15_T_RENAME:     return "RENAME";
	case P15_T_CLOCK_SYNC: return "CLOCK_SYNC";
	case P15_T_STATS:      return "STATS";
	case P15_T_GAP:        return "GAP";
	case P15_T_END:        return "END";
	}
	return "?";
}

int p15_rec_format(const void *data, char *buf, size_t n)
{
	const struct p15_hdr *h = data;
	char a[1100], b[300];
	int k = snprintf(buf, n, "%-6s ts=%llu tgid=%u tid=%u start=%llu flags=0x%x", p15_type_name(h->type),
			 (unsigned long long)h->ts_ns, h->tgid, h->tid, (unsigned long long)h->start_ns, h->flags);

	if (k < 0 || (size_t)k >= n)
		return k;
	switch (h->type) {
	case P15_T_FORK: {
		const struct p15_fork *r = data;

		return k + snprintf(buf + k, n - k, " child=%u/%u child_start=%llu kind=%s", r->child_tgid,
				    r->child_tid, (unsigned long long)r->child_start_ns,
				    r->kind == 1 ? "process" : r->kind == 2 ? "thread" : "?");
	}
	case P15_T_EXEC: {
		const struct p15_exec *r = data;
		__u16 fl, al;
		const __u8 *f = p15_exec_filename(r, &fl), *v = p15_exec_argv(r, &al);

		printable(b, sizeof(b), f, fl);
		printable(a, sizeof(a), v, al);
		return k + snprintf(buf + k, n - k, " old_tid=%u exe=%u:%llu gen=%u file=\"%s\" (%u/%u) argv=\"%s\" (%u/%u)",
				    r->old_tid, r->exe_dev, (unsigned long long)r->exe_ino, r->exe_gen, b, fl,
				    r->filename_full, a, al, r->argv_full);
	}
	case P15_T_EXIT: {
		const struct p15_exit *r = data;

		return k + snprintf(buf + k, n - k, " exit_code=%d group_dead=%u", r->exit_code, r->group_dead);
	}
	case P15_T_RENAME: {
		const struct p15_rename *r = data;

		printable(a, sizeof(a), (const __u8 *)r->old_comm, strnlen(r->old_comm, sizeof(r->old_comm)));
		printable(b, sizeof(b), (const __u8 *)r->new_comm, strnlen(r->new_comm, sizeof(r->new_comm)));
		return k + snprintf(buf + k, n - k, " old=\"%s\" new=\"%s\"", a, b);
	}
	case P15_T_CLOCK_SYNC: {
		const struct p15_clock_sync *r = data;

		return k + snprintf(buf + k, n - k, " boot=%llu mono=%llu real=%llu spread=%llu",
				    (unsigned long long)r->boottime_ns, (unsigned long long)r->monotonic_ns,
				    (unsigned long long)r->realtime_ns, (unsigned long long)r->read_spread_ns);
	}
	case P15_T_STATS: {
		const struct p15_stats *r = data;

		return k + snprintf(buf + k, n - k, " state=%u emitted=%llu drained=%llu written=%llu lost=%llu+%llu "
				    "invalid=%llu gaps=%llu poll_gap_max=%llu queue_full=%llu fsync_max=%llu",
				    r->run_state,
				    (unsigned long long)(r->fork_emitted + r->exec_emitted + r->exit_emitted +
							 r->rename_emitted),
				    (unsigned long long)(r->fork_drained + r->exec_drained + r->exit_drained +
							 r->rename_drained),
				    (unsigned long long)r->spine_written,
				    (unsigned long long)(r->fork_reserve_failed + r->exec_reserve_failed +
							 r->exit_reserve_failed + r->rename_reserve_failed),
				    (unsigned long long)(r->fork_build_failed + r->exec_build_failed +
							 r->exit_build_failed + r->rename_build_failed),
				    (unsigned long long)r->spine_invalid, (unsigned long long)r->gap_records,
				    (unsigned long long)r->poll_gap_max_ns, (unsigned long long)r->queue_full,
				    (unsigned long long)r->wal_fsync_max_ns);
	}
	case P15_T_GAP: {
		const struct p15_gap *r = data;

		return k + snprintf(buf + k, n - k, " from=%llu to=%llu spine_seq=%llu reserve_failed=%llu/%llu/%llu/%llu "
				    "build_failed=%llu/%llu/%llu/%llu", (unsigned long long)r->from_ns,
				    (unsigned long long)r->to_ns, (unsigned long long)r->spine_seq,
				    (unsigned long long)r->fork_reserve_failed, (unsigned long long)r->exec_reserve_failed,
				    (unsigned long long)r->exit_reserve_failed, (unsigned long long)r->rename_reserve_failed,
				    (unsigned long long)r->fork_build_failed, (unsigned long long)r->exec_build_failed,
				    (unsigned long long)r->exit_build_failed, (unsigned long long)r->rename_build_failed);
	}
	case P15_T_END: {
		const struct p15_end *r = data;

		printable(b, sizeof(b), (const __u8 *)(r + 1), r->reason_len);
		return k + snprintf(buf + k, n - k, " exit=%u state=%u invariant=%u signal=%u reason=\"%s\"",
				    r->exit_code, r->run_state, r->invariant, r->signal, b);
	}
	}
	return k;
}
