// SPDX-License-Identifier: MIT
/* See selfcheck.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "selfcheck.h"

int p15_links_add(struct p15_run *r, const struct bpf_link *link, const char *name)
{
	struct bpf_link_info info;
	__u32 len = sizeof(info);
	struct p15_link_ref *ref;
	int fd;

	if (!link)
		return 0;
	if (r->n_links >= P15_LINKS_MAX)
		return -ENOSPC;
	fd = bpf_link__fd(link);
	memset(&info, 0, sizeof(info));
	if (bpf_link_get_info_by_fd(fd, &info, &len))
		return -errno;
	ref = &r->links[r->n_links++];
	ref->fd = fd;
	ref->id = info.id;
	ref->prog_id = info.prog_id;
	snprintf(ref->name, sizeof(ref->name), "%s", name);
	return 0;
}

int p15_links_check(struct p15_run *r, struct p15_link_gone *out, int max)
{
	int found = 0;

	for (int i = 0; i < r->n_links && found < max; i++) {
		struct bpf_link_info info;
		__u32 len = sizeof(info);
		int err = 0;

		if (r->link_gone & (1ull << i))
			continue;
		if (atomic_load(&r->links_closing))
			return found;
		memset(&info, 0, sizeof(info));
		if (bpf_link_get_info_by_fd(r->links[i].fd, &info, &len))
			err = errno ? errno : EIO;
		atomic_fetch_add(&r->link_checks, 1);
		if (!err && info.id == r->links[i].id && info.prog_id == r->links[i].prog_id)
			continue;
		if (atomic_load(&r->links_closing))
			return found;                /* main began detaching while we asked: not a finding */
		r->link_gone |= 1ull << i;
		atomic_fetch_add(&r->link_missing, 1);
		out[found].index = i;
		out[found].err = err;
		found++;
	}
	return found;
}
