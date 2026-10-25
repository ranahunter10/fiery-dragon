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

		if (e->filename_len > P15_EXEC_V1_FILENAME_MAX || e->argv_len > P15_EXEC_V1_ARGV_MAX ||
		    fixed + e->filename_len + e->argv_len > h->len) {
			*why = "variable field beyond len";
			return -EINVAL;
		}
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

int p15_rec_format(const void *data, char *buf, size_t n)
{
	const struct p15_hdr *h = data;
	char a[1100], b[300];
	int k = snprintf(buf, n, "%-6s ts=%llu tgid=%u tid=%u start=%llu flags=0x%x",
			 h->type == P15_T_FORK ? "FORK" : h->type == P15_T_EXEC ? "EXEC" :
			 h->type == P15_T_EXIT ? "EXIT" : h->type == P15_T_RENAME ? "RENAME" : "?",
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
	}
	return k;
}
