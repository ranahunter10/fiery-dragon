// SPDX-License-Identifier: MIT
#include "records.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static size_t fixed_size(__u16 type, __u16 version)
{
	switch (type) {
	case P15_T_FORK:   return version == 1 ? sizeof(struct p15_fork_v1) : 0;
	case P15_T_EXEC:   return version == 1 ? sizeof(struct p15_exec_v1) : version == 2 ? sizeof(struct p15_exec_v2) : 0;
	case P15_T_EXIT:   return version == 1 ? sizeof(struct p15_exit_v1) : 0;
	case P15_T_RENAME: return version == 1 ? sizeof(struct p15_rename_v1) : 0;
	case P15_T_CLOCK_SYNC: return version == 1 ? sizeof(struct p15_clock_sync_v1) : 0;
	case P15_T_STATS:  return version == 1 ? sizeof(struct p15_stats_v1) : version == 2 ? sizeof(struct p15_stats_v2) : 0;
	case P15_T_GAP:    return version == 1 ? sizeof(struct p15_gap_v1) : version == 2 ? sizeof(struct p15_gap_v2) : 0;
	case P15_T_END:    return version == 1 ? sizeof(struct p15_end_v1) : version == 2 ? sizeof(struct p15_end_v2) : 0;
	case P15_T_PROC:   return version == 1 ? sizeof(struct p15_proc_v1) : version == 2 ? sizeof(struct p15_proc_v2) : 0;
	case P15_T_SNAP_DONE: return version == 1 ? sizeof(struct p15_snap_done_v1) : 0;
	case P15_T_NET:    return version == 1 ? sizeof(struct p15_net_v1) : version == 2 ? sizeof(struct p15_net_v2) : 0;
	case P15_T_NET_STATS: return version == 1 ? sizeof(struct p15_net_stats_v1) : version == 2 ? sizeof(struct p15_net_stats_v2) : 0;
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
	if (h->flags & ~(__u16)(P15_F_TRUNCATED | P15_F_READ_FAILED | P15_F_ISN)) {
		*why = "unknown flag bits";
		return -EINVAL;
	}
	if ((h->flags & P15_F_ISN) && !(h->type == P15_T_NET && h->version >= 2)) {
		*why = "ISN flag on a record that has no ISN";
		return -EINVAL;
	}
	if (h->type == P15_T_NET && h->version >= 2) {
		const struct p15_net_v2 *r = data;

		/* every byte has one meaning: the alignment field is zero, and so is an ISN nobody read */
		if (r->reserved || (!(h->flags & P15_F_ISN) && r->tcp_isn)) {
			*why = "NET v2: non-zero reserved, or tcp_isn without P15_F_ISN";
			return -EINVAL;
		}
	}
	if (h->type == P15_T_SNAP_DONE && ((const struct p15_snap_done_v1 *)data)->kind != 1 &&
	    ((const struct p15_snap_done_v1 *)data)->kind != 2) {
		*why = "SNAP_DONE: unknown kind";
		return -EINVAL;
	}
	if (h->type == P15_T_EXEC) {
		size_t tail;

		if (h->version == 1) {
			const struct p15_exec_v1 *e = data;

			if (e->filename_len > P15_EXEC_V1_FILENAME_MAX || e->argv_len > P15_EXEC_V1_ARGV_MAX) {
				*why = "variable field beyond len";
				return -EINVAL;
			}
			tail = (size_t)e->filename_len + e->argv_len;
		} else {
			const struct p15_exec_v2 *e = data;

			if (e->filename_len > P15_EXEC_V2_FILENAME_MAX || e->argv_len > P15_EXEC_V2_ARGV_MAX ||
			    e->exe_name_len > P15_EXEC_V2_EXE_NAME_MAX) {
				*why = "variable field beyond len";
				return -EINVAL;
			}
			tail = (size_t)e->filename_len + e->argv_len + e->exe_name_len;
		}
		/* slack only after a failed read */
		if (check_tail(data, fixed, tail, h->flags & P15_F_READ_FAILED, why))
			return -EINVAL;
	} else if (h->type == P15_T_END) {
		/* v2 appends closing_snapshot and reserved to the fixed part; reason_len stays in place
		 * relative to the end of it, so each version is read through its own struct */
		__u16 rl = h->version == 1 ? ((const struct p15_end_v1 *)data)->reason_len
					   : ((const struct p15_end_v2 *)data)->reason_len;

		if (rl > P15_END_V1_REASON_MAX) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (h->version >= 2 && ((const struct p15_end_v2 *)data)->reserved) {
			*why = "END v2: non-zero reserved";
			return -EINVAL;
		}
		if (check_tail(data, fixed, rl, 0, why))
			return -EINVAL;
	} else if (h->type == P15_T_PROC) {
		__u16 ep_len, av_len, reserved, kind;
		__u32 pflags;

		if (h->version == 1) {
			const struct p15_proc_v1 *r = data;

			ep_len = r->exe_path_len; av_len = r->argv_len; reserved = r->reserved; kind = r->kind;
			pflags = r->pflags;
			if (ep_len > P15_PROC_V1_EXE_PATH_MAX || av_len > P15_PROC_V1_ARGV_MAX) {
				*why = "variable field beyond len";
				return -EINVAL;
			}
		} else {
			const struct p15_proc_v2 *r = data;

			ep_len = r->exe_path_len; av_len = r->argv_len; reserved = r->reserved; kind = r->kind;
			pflags = r->pflags;
			if (ep_len > P15_PROC_V2_EXE_PATH_MAX || av_len > P15_PROC_V2_ARGV_MAX) {
				*why = "variable field beyond len";
				return -EINVAL;
			}
		}
		if (reserved || (kind != 1 && kind != 2) || (pflags & ~3u)) {
			*why = "PROC: non-zero reserved, unknown kind or unknown pflags";
			return -EINVAL;
		}
		if (check_tail(data, fixed, (size_t)ep_len + av_len, 0, why))
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
	case P15_T_NET:        return "NET";
	case P15_T_NET_STATS:  return "NET_STATS";
	case P15_T_PROC:       return "PROC";
	case P15_T_SNAP_DONE:  return "SNAP_DONE";
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
		if (h->version == 1) {
			const struct p15_exec_v1 *r = data;
			const __u8 *tail = (const __u8 *)(r + 1);

			printable(b, sizeof(b), tail, r->filename_len);
			printable(a, sizeof(a), tail + r->filename_len, r->argv_len);
			return k + snprintf(buf + k, n - k,
					    " old_tid=%u exe=%u:%llu gen=%u file=\"%s\" (%u/%u) argv=\"%s\" (%u/%u)", r->old_tid,
					    r->exe_dev, (unsigned long long)r->exe_ino, r->exe_gen, b, r->filename_len,
					    r->filename_full, a, r->argv_len, r->argv_full);
		} else {
			const struct p15_exec_v2 *r = data;
			const __u8 *tail = (const __u8 *)(r + 1);
			char nm[80];

			printable(b, sizeof(b), tail, r->filename_len);
			printable(a, sizeof(a), tail + r->filename_len, r->argv_len);
			printable(nm, sizeof(nm), tail + r->filename_len + r->argv_len, r->exe_name_len);
			return k + snprintf(buf + k, n - k,
					    " old_tid=%u exe=%u:%llu gen=%u name=\"%s\" nlink=%u fsmagic=0x%x mode=0%o "
					    "uid=%u euid=%u self_exec_id=%llu file=\"%s\" (%u/%u) argv=\"%s\" (%u/%u) "
					    "stdin=%llu:0%o stdout=%llu:0%o stderr=%llu:0%o", r->old_tid,
					    r->exe_dev, (unsigned long long)r->exe_ino, r->exe_gen, nm, r->exe_nlink,
					    r->exe_fs_magic, r->exe_mode, r->uid, r->euid, (unsigned long long)r->self_exec_id,
					    b, r->filename_len, r->filename_full, a, r->argv_len, r->argv_full,
					    (unsigned long long)r->stdin_ino, r->stdin_mode,
					    (unsigned long long)r->stdout_ino, r->stdout_mode,
					    (unsigned long long)r->stderr_ino, r->stderr_mode);
		}
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
	case P15_T_NET: {
		const struct p15_net *r = data;
		static const char *const ops[] = { "?", "CONNECT", "ACCEPT", "LISTEN", "BIND" };
		char l[INET6_ADDRSTRLEN] = "?", rm[INET6_ADDRSTRLEN] = "?";
		int af = r->family == 10 ? AF_INET6 : AF_INET, m;

		inet_ntop(af, r->laddr, l, sizeof(l));
		inet_ntop(af, r->raddr, rm, sizeof(rm));
		m = k + snprintf(buf + k, n - k, " op=%s proto=%s ret=%d local=%s%s%s:%u remote=%s%s%s:%u cookie=%llu peer=%llu netns=%u",
				 ops[r->op < 5 ? r->op : 0], r->proto == 6 ? "tcp" : r->proto == 17 ? "udp" : "?", r->ret,
				 af == AF_INET6 ? "[" : "", l, af == AF_INET6 ? "]" : "", r->lport,
				 af == AF_INET6 ? "[" : "", rm, af == AF_INET6 ? "]" : "", r->rport,
				 (unsigned long long)r->sock_cookie, (unsigned long long)r->peer_cookie, r->netns);
		if (r->h.version >= 2 && (r->h.flags & P15_F_ISN) && m >= 0 && (size_t)m < n)
			m += snprintf(buf + m, n - (size_t)m, " isn=%u", r->tcp_isn);
		return m;
	}
	case P15_T_NET_STATS: {
		const struct p15_net_stats *r = data;

		return k + snprintf(buf + k, n - k, " seen=%llu emitted=%llu reserve_failed=%llu excluded=%llu drained=%llu "
				    "invalid=%llu written=%llu drain_lost=%llu fill_max=%llu",
				    (unsigned long long)r->net_seen, (unsigned long long)r->net_emitted,
				    (unsigned long long)r->net_reserve_failed, (unsigned long long)r->net_excluded,
				    (unsigned long long)r->net_drained, (unsigned long long)r->net_invalid,
				    (unsigned long long)r->net_written, (unsigned long long)r->net_drain_lost,
				    (unsigned long long)r->bulk_fill_max);
	}
	case P15_T_END: {
		const struct p15_end_v1 *r1 = data;
		const struct p15_end_v2 *r2 = data;
		int m;

		if (h->version == 1)
			printable(b, sizeof(b), (const __u8 *)(r1 + 1), r1->reason_len);
		else
			printable(b, sizeof(b), (const __u8 *)(r2 + 1), r2->reason_len);
		m = k + snprintf(buf + k, n - k, " exit=%u state=%u invariant=%u signal=%u", r1->exit_code, r1->run_state,
				 r1->invariant, r1->signal);
		if (h->version >= 2 && m >= 0 && (size_t)m < n)
			m += snprintf(buf + m, n - (size_t)m, " closing_snapshot=%d", r2->closing_snapshot);
		if (m >= 0 && (size_t)m < n)
			m += snprintf(buf + m, n - (size_t)m, " reason=\"%s\"", b);
		return m;
	}
	case P15_T_PROC: {
		if (h->version == 1) {
			const struct p15_proc_v1 *r = data;
			const __u8 *tail = (const __u8 *)(r + 1);
			char c[17];

			printable(b, sizeof(b), tail, r->exe_path_len);
			printable(a, sizeof(a), tail + r->exe_path_len, r->argv_len);
			printable(c, sizeof(c), (const __u8 *)r->comm, strnlen(r->comm, sizeof(r->comm)));
			return k + snprintf(buf + k, n - k, " snap=%u/%s parent=%u parent_start=%llu comm=\"%s\" pflags=0x%x "
					    "exe=%u:%llu gen=%u path=\"%s\" (%u/%u) argv=\"%s\" (%u/%u)", r->snap_id,
					    r->kind == 1 ? "opening" : "closing", r->parent_tgid,
					    (unsigned long long)r->parent_start_ns, c, r->pflags, r->exe_dev,
					    (unsigned long long)r->exe_ino, r->exe_gen, b, r->exe_path_len, r->exe_path_full, a,
					    r->argv_len, r->argv_full);
		} else {
			const struct p15_proc_v2 *r = data;
			const __u8 *tail = (const __u8 *)(r + 1);
			char c[17];

			printable(b, sizeof(b), tail, r->exe_path_len);
			printable(a, sizeof(a), tail + r->exe_path_len, r->argv_len);
			printable(c, sizeof(c), (const __u8 *)r->comm, strnlen(r->comm, sizeof(r->comm)));
			return k + snprintf(buf + k, n - k, " snap=%u/%s parent=%u parent_start=%llu comm=\"%s\" pflags=0x%x "
					    "exe=%u:%llu gen=%u nlink=%u fsmagic=0x%x mode=0%o uid=%u self_exec_id=%llu "
					    "path=\"%s\" (%u/%u) argv=\"%s\" (%u/%u)", r->snap_id,
					    r->kind == 1 ? "opening" : "closing", r->parent_tgid,
					    (unsigned long long)r->parent_start_ns, c, r->pflags, r->exe_dev,
					    (unsigned long long)r->exe_ino, r->exe_gen, r->exe_nlink, r->exe_fs_magic, r->exe_mode,
					    r->exe_uid, (unsigned long long)r->self_exec_id, b, r->exe_path_len, r->exe_path_full,
					    a, r->argv_len, r->argv_full);
		}
	}
	case P15_T_SNAP_DONE: {
		const struct p15_snap_done_v1 *r = data;

		return k + snprintf(buf + k, n - k, " snap=%u/%s error=%d duration=%llu tasks=%llu threads=%llu emitted=%llu "
				    "write_failed=%llu entries=%llu invalid=%llu unwritten=%llu kthreads=%llu exiting=%llu "
				    "argv_failed=%llu path_unlocked=%llu path_not_found=%llu path_failed=%llu truncated=%llu",
				    r->snap_id, r->kind == 1 ? "opening" : "closing", r->error,
				    (unsigned long long)r->duration_ns, (unsigned long long)r->tasks,
				    (unsigned long long)r->threads, (unsigned long long)r->emitted,
				    (unsigned long long)r->write_failed, (unsigned long long)r->entries,
				    (unsigned long long)r->invalid, (unsigned long long)r->unwritten,
				    (unsigned long long)r->kthreads, (unsigned long long)r->exiting,
				    (unsigned long long)r->argv_failed, (unsigned long long)r->path_unlocked,
				    (unsigned long long)r->path_not_found, (unsigned long long)r->path_failed,
				    (unsigned long long)r->truncated);
	}
	}
	return k;
}
