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
	case P15_T_SNAP_DONE: return version == 1 ? sizeof(struct p15_snap_done_v1) : version == 2 ? sizeof(struct p15_snap_done_v2) : 0;
	case P15_T_NET:    return version == 1 ? sizeof(struct p15_net_v1) : version == 2 ? sizeof(struct p15_net_v2) : 0;
	case P15_T_NET_STATS: return version == 1 ? sizeof(struct p15_net_stats_v1) : version == 2 ? sizeof(struct p15_net_stats_v2) : 0;
	case P15_T_OPEN:   return version == 1 ? sizeof(struct p15_open_v1) : 0;
	case P15_T_OPEN_VERDICT: return version == 1 ? sizeof(struct p15_open_verdict_v1) : 0;
	case P15_T_BACKING: return version == 1 ? sizeof(struct p15_backing_v1) : 0;
	case P15_T_CLOSE:  return version == 1 ? sizeof(struct p15_close_v1) : 0;
	case P15_T_FD:     return version == 1 ? sizeof(struct p15_fd_v1) : 0;
	case P15_T_FILE_STATS: return version == 1 ? sizeof(struct p15_file_stats_v1) : version == 2 ? sizeof(struct p15_file_stats_v2) : 0;
	case P15_T_FILE:   return version == 1 ? sizeof(struct p15_file_v1) : 0;
	case P15_T_FLOW:   return version == 1 ? sizeof(struct p15_flow_v1) : 0;
	case P15_T_FLOW_STATS: return version == 1 ? sizeof(struct p15_flow_stats_v1) : 0;
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

/* A part field (schema [[part]]): absent, or the whole struct, as its flag says (FD: always). */
static int check_part(const void *data, size_t at, __u16 len, __u32 full, int want, const char *bad, const char *flag,
		      const char **why)
{
	const struct p15_part_objfacts *f = (const void *)((const __u8 *)data + at);

	if ((len != 0 && len != sizeof(*f)) || full != len) {
		*why = bad;
		return -EINVAL;
	}
	if (!!len != !!want) {
		*why = flag;
		return -EINVAL;
	}
	if (len && ((f->oflags & ~1u) || f->seen < 1 || f->seen > 5)) {
		*why = "OBJFACTS: unknown oflags bits or an unknown 'seen'";
		return -EINVAL;
	}
	return 0;
}

/* OPEN, OPEN_VERDICT, BACKING, CLOSE and FD (ADR-0015, STATE decision 19): the same rules and
 * wording as python/p15/records.py. Called after the common header checks. */
static int check_file(const void *data, size_t fixed, const char **why)
{
	const struct p15_hdr *h = data;

	switch (h->type) {
	case P15_T_OPEN: {
		const struct p15_open_v1 *r = data;
		const __u32 ok = P15_FF_OBJ_NEW | P15_FF_PATH_MISSING | P15_FF_PATH_WALKED | P15_FF_PATH_RACED |
				 P15_FF_PATH_ERROR | P15_FF_FULL_SIZE | P15_FF_KTHREAD;
		const __u32 ret = P15_FF_PATH_MISSING | P15_FF_PATH_WALKED;   /* written by the session's return */

		if (r->fflags & ~ok) {
			*why = "OPEN: fflags bits this record never carries";
			return -EINVAL;
		}
		if ((r->fflags & ret) == ret || ((r->fflags & P15_FF_PATH_RACED) && !(r->fflags & P15_FF_PATH_WALKED))) {
			*why = "OPEN: PATH_WALKED with PATH_MISSING, or PATH_RACED without PATH_WALKED";
			return -EINVAL;
		}
		if ((r->fflags & P15_FF_PATH_WALKED) && (r->fflags & (P15_FF_PATH_ERROR | P15_FF_FULL_SIZE))) {
			*why = "OPEN: a walked path with PATH_ERROR or FULL_SIZE (those are the fentry's)";
			return -EINVAL;
		}
		if (!!(r->fflags & P15_FF_PATH_ERROR) != !!r->path_err) {
			*why = "OPEN: path_err without PATH_ERROR, or PATH_ERROR without path_err";
			return -EINVAL;
		}
		if (!(r->fflags & ret) && r->verdict) {
			*why = "OPEN: a verdict on an OPEN the fentry wrote (a denial is OPEN_VERDICT)";
			return -EINVAL;
		}
		if (r->facts_len > P15_PART_OBJFACTS_SIZE || r->path_len > P15_OPEN_V1_PATH_MAX ||
		    fixed + r->facts_len + r->path_len > h->len) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,
			       "OPEN: facts is neither absent nor a whole OBJFACTS",
			       "OPEN: facts present without its flag, or its flag without it", why))
			return -EINVAL;
		/* slack only on a full-size OPEN (no path scratch slot was free), and zero */
		return check_tail(data, fixed, (size_t)r->facts_len + r->path_len,
				  (r->fflags & P15_FF_FULL_SIZE) && h->len == P15_OPEN_V1_MAX_SIZE, why);
	}
	case P15_T_OPEN_VERDICT: {
		const struct p15_open_verdict_v1 *r = data;

		if (r->fflags & ~P15_FF_KTHREAD) {
			*why = "OPEN_VERDICT: fflags bits this record never carries";
			return -EINVAL;
		}
		if (r->verdict >= 0) {
			*why = "OPEN_VERDICT: the verdict is not a denial";
			return -EINVAL;
		}
		break;
	}
	case P15_T_BACKING: {
		const struct p15_backing_v1 *r = data;

		if (r->fflags & ~(P15_FF_OBJ_NEW | P15_FF_USER_OBJ_NEW | P15_FF_KTHREAD)) {
			*why = "BACKING: fflags bits this record never carries";
			return -EINVAL;
		}
		if (r->facts_len > P15_PART_OBJFACTS_SIZE || r->user_facts_len > P15_PART_OBJFACTS_SIZE ||
		    fixed + r->facts_len + r->user_facts_len > h->len) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,
			       "BACKING: facts is neither absent nor a whole OBJFACTS",
			       "BACKING: facts present without its flag, or its flag without it", why) ||
		    check_part(data, fixed + r->facts_len, r->user_facts_len, r->user_facts_full,
			       r->fflags & P15_FF_USER_OBJ_NEW, "BACKING: user_facts is neither absent nor a whole OBJFACTS",
			       "BACKING: user_facts present without its flag, or its flag without it", why))
			return -EINVAL;
		return check_tail(data, fixed, (size_t)r->facts_len + r->user_facts_len, 0, why);
	}
	case P15_T_CLOSE:
		if (((const struct p15_close_v1 *)data)->fflags & ~(P15_FF_NEVER_OPENED | P15_FF_KTHREAD)) {
			*why = "CLOSE: fflags bits this record never carries";
			return -EINVAL;
		}
		break;
	case P15_T_FD: {
		const struct p15_fd_v1 *r = data;

		if (r->fflags & ~P15_FF_PATH_ERROR) {
			*why = "FD: fflags bits this record never carries";
			return -EINVAL;
		}
		if (!!(r->fflags & P15_FF_PATH_ERROR) != !!r->path_err) {
			*why = "FD: path_err without PATH_ERROR, or PATH_ERROR without path_err";
			return -EINVAL;
		}
		if (r->facts_len > P15_PART_OBJFACTS_SIZE || r->path_len > P15_FD_V1_PATH_MAX ||
		    fixed + r->facts_len + r->path_len > h->len) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (check_part(data, fixed, r->facts_len, r->facts_full, 1, "FD: facts is neither absent nor a whole OBJFACTS",
			       "FD: facts present without its flag, or its flag without it", why))
			return -EINVAL;
		return check_tail(data, fixed, (size_t)r->facts_len + r->path_len, 0, why);
	}
	case P15_T_FILE: {
		const struct p15_file_v1 *r = data;
		static const __u8 zero[sizeof(r->_pad)];

		if (r->fflags & ~P15_FF_OBJ_NEW) {
			*why = "FILE: fflags bits this record never carries";
			return -EINVAL;
		}
		if (r->seen < 3 || r->seen > 5) {
			*why = "FILE: unknown 'seen'";
			return -EINVAL;
		}
		if (!!(h->flags & P15_F_TRUNCATED) != (r->name_full != r->name_len) || r->name_full < r->name_len) {
			*why = "FILE: name_full differs from name_len without TRUNCATED, or the reverse";
			return -EINVAL;
		}
		if (r->facts_len > P15_PART_OBJFACTS_SIZE || r->name_len > P15_FILE_V1_NAME_MAX ||
		    fixed + r->facts_len + r->name_len > h->len) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
		if (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,
			       "FILE: facts is neither absent nor a whole OBJFACTS",
			       "FILE: facts present without its flag, or its flag without it", why))
			return -EINVAL;
		if (check_tail(data, fixed, (size_t)r->facts_len + r->name_len, 0, why))
			return -EINVAL;
		if (memcmp(r->_pad, zero, sizeof(zero))) {
			*why = "FILE: non-zero padding";
			return -EINVAL;
		}
		return 0;
	}
	default:
		*why = "not a file-identity record";
		return -EINVAL;
	}
	if (h->len != fixed) {
		*why = "len differs from the fixed size";
		return -EINVAL;
	}
	return 0;
}

/* FLOW (ADR-0005 rules 2, 7, 8): the same rules and wording as python/p15/records.py _flow_check.
 * Called after the common header checks. */
static int check_flow(const void *data, size_t fixed, const char **why)
{
	const struct p15_flow_v1 *r = data;
	const struct p15_hdr *h = data;
	static const __u8 zero[sizeof(r->_pad)];
	const __u32 ok = P15_FF_OBJ_NEW | P15_FF_UNREGISTERED | P15_FF_PEEK | P15_FF_VECTORED | P15_FF_START_UNKNOWN;
	const int vfs = r->kind == P15_FLOW_KIND_READ || r->kind == P15_FLOW_KIND_WRITE;

	if (r->fflags & ~ok) {
		*why = "FLOW: fflags bits this record never carries";
		return -EINVAL;
	}
	if (r->kind < 1 || r->kind > P15_FLOW_KIND_MAX || r->reason < 1 || r->reason > P15_FLOW_REASON_MAX) {
		*why = "FLOW: unknown kind or reason";
		return -EINVAL;
	}
	if (r->count < 1 || r->bytes < r->count || (r->reason == P15_FLOW_REASON_SINGLE && r->count != 1)) {
		*why = "FLOW: count 0, fewer bytes than events, or a SINGLE of count other than 1";
		return -EINVAL;
	}
	if (((r->fflags & P15_FF_PEEK) && r->kind != P15_FLOW_KIND_RECV) ||
	    ((r->fflags & (P15_FF_VECTORED | P15_FF_START_UNKNOWN)) && !vfs)) {
		*why = "FLOW: PEEK on a kind other than RECV, or VECTORED/START_UNKNOWN on a socket kind";
		return -EINVAL;
	}
	if ((r->fflags & P15_FF_OBJ_NEW) && !(r->fflags & P15_FF_UNREGISTERED)) {
		*why = "FLOW: facts on a registered open file (they travel in OPEN, FILE or FD)";
		return -EINVAL;
	}
	if (r->reason != P15_FLOW_REASON_SINGLE &&
	    !!(r->fflags & P15_FF_UNREGISTERED) != (r->reason == P15_FLOW_REASON_MAP_FULL)) {
		*why = "FLOW: UNREGISTERED without reason MAP_FULL, or MAP_FULL without UNREGISTERED";
		return -EINVAL;
	}
	if (r->facts_len > P15_PART_OBJFACTS_SIZE || fixed + r->facts_len > h->len) {
		*why = "variable field beyond len";
		return -EINVAL;
	}
	if (check_part(data, fixed, r->facts_len, r->facts_full, r->fflags & P15_FF_OBJ_NEW,
		       "FLOW: facts is neither absent nor a whole OBJFACTS",
		       "FLOW: facts present without its flag, or its flag without it", why))
		return -EINVAL;
	if (check_tail(data, fixed, r->facts_len, 0, why))
		return -EINVAL;
	if (memcmp(r->_pad, zero, sizeof(zero))) {
		*why = "FLOW: non-zero padding";
		return -EINVAL;
	}
	return 0;
}

int p15_is_file_type(__u16 type)
{
	return type == P15_T_OPEN || type == P15_T_OPEN_VERDICT || type == P15_T_BACKING || type == P15_T_CLOSE;
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
	/* kind sits at a different offset in each version */
	if (h->type == P15_T_SNAP_DONE &&
	    (h->version == 1 ? ((const struct p15_snap_done_v1 *)data)->kind : ((const struct p15_snap_done_v2 *)data)->kind) != 1 &&
	    (h->version == 1 ? ((const struct p15_snap_done_v1 *)data)->kind : ((const struct p15_snap_done_v2 *)data)->kind) != 2) {
		*why = "SNAP_DONE: unknown kind";
		return -EINVAL;
	}
	if (h->type == P15_T_SNAP_DONE && h->version == 2 && ((const struct p15_snap_done_v2 *)data)->fd_pass > 1) {
		*why = "SNAP_DONE: fd_pass is neither 0 nor 1";
		return -EINVAL;
	}
	if (p15_is_file_type(h->type) || h->type == P15_T_FD || h->type == P15_T_FILE) {
		if (check_file(data, fixed, why))
			return -EINVAL;
	} else if (h->type == P15_T_FLOW) {
		if (check_flow(data, fixed, why))
			return -EINVAL;
	} else if (h->type == P15_T_EXEC) {
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

const __u8 *p15_exec_exe_name(const struct p15_exec *r, __u16 *len)
{
	*len = r->exe_name_len;
	return (const __u8 *)(r + 1) + r->filename_len + r->argv_len;
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
	case P15_T_OPEN:       return "OPEN";
	case P15_T_OPEN_VERDICT: return "OPEN_VERDICT";
	case P15_T_BACKING:    return "BACKING";
	case P15_T_CLOSE:      return "CLOSE";
	case P15_T_FD:         return "FD";
	case P15_T_FILE_STATS: return "FILE_STATS";
	case P15_T_FLOW_STATS: return "FLOW_STATS";
	case P15_T_FILE:       return "FILE";
	case P15_T_FLOW:       return "FLOW";
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
		const struct p15_snap_done_v2 *r2 = data;
		uint32_t sid = h->version == 2 ? r2->snap_id : r->snap_id;
		int32_t err = h->version == 2 ? r2->error : r->error;
		uint16_t kind = h->version == 2 ? r2->kind : r->kind;
		int m;

		/* the u64 books before snap_id are at the same offsets in v1 and v2 */
		m = k + snprintf(buf + k, n - k, " snap=%u/%s error=%d duration=%llu tasks=%llu threads=%llu emitted=%llu "
				    "write_failed=%llu entries=%llu invalid=%llu unwritten=%llu kthreads=%llu exiting=%llu "
				    "argv_failed=%llu path_unlocked=%llu path_not_found=%llu path_failed=%llu truncated=%llu",
				    sid, kind == 1 ? "opening" : "closing", err,
				    (unsigned long long)r->duration_ns, (unsigned long long)r->tasks,
				    (unsigned long long)r->threads, (unsigned long long)r->emitted,
				    (unsigned long long)r->write_failed, (unsigned long long)r->entries,
				    (unsigned long long)r->invalid, (unsigned long long)r->unwritten,
				    (unsigned long long)r->kthreads, (unsigned long long)r->exiting,
				    (unsigned long long)r->argv_failed, (unsigned long long)r->path_unlocked,
				    (unsigned long long)r->path_not_found, (unsigned long long)r->path_failed,
				    (unsigned long long)r->truncated);
		if (h->version == 2 && r2->fd_pass && m >= 0 && (size_t)m < n)
			m += snprintf(buf + m, n - (size_t)m, " fd: error=%d duration=%llu files=%llu no_inode=%llu emitted=%llu "
				      "write_failed=%llu entries=%llu invalid=%llu unwritten=%llu known=%llu registered=%llu "
				      "map_full=%llu path_error=%llu truncated=%llu", r2->fd_error,
				      (unsigned long long)r2->fd_duration_ns, (unsigned long long)r2->fd_files,
				      (unsigned long long)r2->fd_no_inode, (unsigned long long)r2->fd_emitted,
				      (unsigned long long)r2->fd_write_failed, (unsigned long long)r2->fd_entries,
				      (unsigned long long)r2->fd_invalid, (unsigned long long)r2->fd_unwritten,
				      (unsigned long long)r2->fd_known, (unsigned long long)r2->fd_registered,
				      (unsigned long long)r2->fd_map_full, (unsigned long long)r2->fd_path_error,
				      (unsigned long long)r2->fd_truncated);
		return m;
	}
	case P15_T_OPEN: {
		const struct p15_open_v1 *r = data;
		const struct p15_part_objfacts *f = (const void *)(r + 1);
		int m;

		printable(a, sizeof(a), (const __u8 *)(r + 1) + r->facts_len, r->path_len);
		m = k + snprintf(buf + k, n - k, " fid=%llu obj=%llu fflags=0x%x f_flags=0%o f_mode=0x%x verdict=%d "
				 "path_err=%d path=\"%s\"(%u)", (unsigned long long)r->fid, (unsigned long long)r->obj,
				 r->fflags, r->f_flags, r->f_mode, r->verdict, r->path_err, a, r->path_len);
		if (r->facts_len && m >= 0 && (size_t)m < n)
			m += snprintf(buf + m, n - (size_t)m, " dev=%u:%u ino=%llu gen=%u mode=0%o magic=0x%x nlink=%u subvol=%llu "
				      "oflags=%u", f->dev >> 20, f->dev & 0xfffff, (unsigned long long)f->ino, f->gen, f->mode,
				      f->fs_magic, f->nlink, (unsigned long long)f->subvol, f->oflags);
		return m;
	}
	case P15_T_OPEN_VERDICT: {
		const struct p15_open_verdict_v1 *r = data;

		return k + snprintf(buf + k, n - k, " fid=%llu verdict=%d fflags=0x%x", (unsigned long long)r->fid,
				    r->verdict, r->fflags);
	}
	case P15_T_BACKING: {
		const struct p15_backing_v1 *r = data;

		return k + snprintf(buf + k, n - k, " fid=%llu obj=%llu user_obj=%llu fflags=0x%x f_flags=0%o f_mode=0x%x",
				    (unsigned long long)r->fid, (unsigned long long)r->obj, (unsigned long long)r->user_obj,
				    r->fflags, r->f_flags, r->f_mode);
	}
	case P15_T_CLOSE: {
		const struct p15_close_v1 *r = data;

		return k + snprintf(buf + k, n - k, " fid=%llu obj=%llu fflags=0x%x f_mode=0x%x", (unsigned long long)r->fid,
				    (unsigned long long)r->obj, r->fflags, r->f_mode);
	}
	case P15_T_FD: {
		const struct p15_fd_v1 *r = data;

		printable(a, sizeof(a), (const __u8 *)(r + 1) + r->facts_len, r->path_len);
		return k + snprintf(buf + k, n - k, " snap=%u fd=%u fid=%llu obj=%llu pos=%llu fflags=0x%x path=\"%s\"(%u)",
				    r->snap_id, r->fd, (unsigned long long)r->fid, (unsigned long long)r->obj,
				    (unsigned long long)r->pos, r->fflags, a, r->path_len);
	}
	case P15_T_FILE: {
		const struct p15_file_v1 *r = data;

		printable(a, sizeof(a), (const __u8 *)(r + 1) + r->facts_len, r->name_len);
		return k + snprintf(buf + k, n - k, " fid=%llu obj=%llu fflags=0x%x f_flags=0%o f_mode=0x%x seen=%u name=\"%s\"(%u/%u)",
				    (unsigned long long)r->fid, (unsigned long long)r->obj, r->fflags, r->f_flags, r->f_mode,
				    r->seen, a, r->name_len, r->name_full);
	}
	case P15_T_FLOW: {
		const struct p15_flow_v1 *r = data;
		static const char *const kinds[] = { "?", "READ", "WRITE", "RECV", "SEND" };

		return k + snprintf(buf + k, n - k, " %s fid=%llu obj=%llu first=%llu last=%llu bytes=%llu count=%u fflags=0x%x reason=%u",
				    kinds[r->kind <= P15_FLOW_KIND_MAX ? r->kind : 0], (unsigned long long)r->fid,
				    (unsigned long long)r->obj, (unsigned long long)r->first_ts,
				    (unsigned long long)r->last_ts, (unsigned long long)r->bytes, r->count, r->fflags, r->reason);
	}
	case P15_T_FILE_STATS: {
		const struct p15_file_stats_v1 *r = data;

		if (h->version == 2) {
			const struct p15_file_stats_v2 *s = data;

			k += snprintf(buf + k, n - k, " walked=%llu raced=%llu walk_truncated=%llu unnamed=%llu ret_backing=%llu/%llu",
				      (unsigned long long)s->walked, (unsigned long long)s->walk_raced,
				      (unsigned long long)s->walk_truncated, (unsigned long long)s->walk_unnamed,
				      (unsigned long long)s->ret_backing_emitted, (unsigned long long)s->ret_backing_lost);
			if (k < 0 || (size_t)k >= n)
				return k;
			return k + snprintf(buf + k, n - k, " opens=%llu open_lost=%llu missing=%llu verdicts=%llu backing=%llu "
					    "closes=%llu close_lost=%llu drained=%llu invalid=%llu fentry_missed=%llu "
					    "kprobe_missed=%llu files_live=%llu objs_live=%llu map_full=%llu/%llu",
					    (unsigned long long)s->open_emitted, (unsigned long long)s->open_lost,
					    (unsigned long long)s->missing_emitted, (unsigned long long)s->verdict_emitted,
					    (unsigned long long)s->backing_emitted, (unsigned long long)s->close_emitted,
					    (unsigned long long)s->close_lost, (unsigned long long)s->file_drained,
					    (unsigned long long)s->file_invalid, (unsigned long long)s->fentry_missed,
					    (unsigned long long)s->kprobe_missed, (unsigned long long)s->files_live,
					    (unsigned long long)s->objs_live, (unsigned long long)s->file_map_full,
					    (unsigned long long)s->obj_map_full);
		}

		return k + snprintf(buf + k, n - k, " opens=%llu open_lost=%llu missing=%llu verdicts=%llu backing=%llu "
				    "closes=%llu close_lost=%llu drained=%llu invalid=%llu fentry_missed=%llu kprobe_missed=%llu "
				    "files_live=%llu objs_live=%llu map_full=%llu/%llu",
				    (unsigned long long)r->open_emitted, (unsigned long long)r->open_lost,
				    (unsigned long long)r->missing_emitted, (unsigned long long)r->verdict_emitted,
				    (unsigned long long)r->backing_emitted, (unsigned long long)r->close_emitted,
				    (unsigned long long)r->close_lost, (unsigned long long)r->file_drained,
				    (unsigned long long)r->file_invalid, (unsigned long long)r->fentry_missed,
				    (unsigned long long)r->kprobe_missed, (unsigned long long)r->files_live,
				    (unsigned long long)r->objs_live, (unsigned long long)r->file_map_full,
				    (unsigned long long)r->obj_map_full);
	}
	}
	return k;
}
