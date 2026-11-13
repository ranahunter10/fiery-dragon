// SPDX-License-Identifier: MIT
/*
 * The end's count of opens in flight (bpf/include/p15_file.h), on planted open-file entries: the
 * shipped object's iterator file_open_iter, loaded alone (every other program's autoload off, so
 * this runs on kernels without kprobe.session too), run over a map this test filled. It must
 * claim exactly the entries marked entered and not returned, count each once, and count nothing
 * on a second pass. Needs root. Exit 0 pass, 1 fail, 77 if the kernel refuses the load (printed
 * as SKIP: it_p15d.sh decides whether a skip is allowed).
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "counters.h"
#include "p15_file.h"
#include "p15_snap.h"   /* before file.skel.h: its .bss holds struct p15_fd_books */
#include "file.skel.h"

/* bpf/progs/file.bpf.c: struct file_ent and its state bits */
struct file_ent {
	__u64 fid, obj, inode;
	__u32 state, pad;
};
#define ST_SESSION_ENTRY (1u << 0)
#define ST_FENTRY_RAN (1u << 1)
#define ST_SESSION_RETURNED (1u << 2)
#define ST_SESSION_CLAIMED (1u << 3)

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static int quiet(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	(void)level;
	(void)fmt;
	(void)ap;
	return 0;
}

int main(void)
{
	/* what each planted entry holds, and what the iterator must leave */
	static const struct { __u32 before, after; } E[] = {
		{ ST_SESSION_ENTRY, ST_SESSION_ENTRY | ST_SESSION_CLAIMED },                 /* in flight */
		{ ST_SESSION_ENTRY, ST_SESSION_ENTRY | ST_SESSION_CLAIMED },
		{ ST_SESSION_ENTRY | ST_FENTRY_RAN, ST_SESSION_ENTRY | ST_FENTRY_RAN | ST_SESSION_CLAIMED },   /* in flight, path written */
		{ ST_SESSION_ENTRY | ST_SESSION_RETURNED, ST_SESSION_ENTRY | ST_SESSION_RETURNED },             /* returned */
		{ ST_SESSION_ENTRY | ST_FENTRY_RAN | ST_SESSION_RETURNED, ST_SESSION_ENTRY | ST_FENTRY_RAN | ST_SESSION_RETURNED },
		{ ST_SESSION_ENTRY | ST_SESSION_CLAIMED, ST_SESSION_ENTRY | ST_SESSION_CLAIMED },               /* counted already */
		{ ST_FENTRY_RAN, ST_FENTRY_RAN },                                             /* never entered a session */
		{ 0, 0 },                                                                     /* registered by a snapshot or a transfer */
	};
	enum { N = sizeof(E) / sizeof(E[0]), IN_FLIGHT = 3 };
	union bpf_iter_link_info linfo;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct p15_counters ctr;
	struct bpf_program *p;
	struct bpf_link *link;
	struct file_bpf *s;
	uint64_t sum[P15_CTR_MAX];
	int ncpu = libbpf_num_possible_cpus(), fd;

	libbpf_set_print(quiet);
	s = file_bpf__open();
	if (!s || ncpu <= 0) {
		printf("FAIL the object could not be opened\n");
		return 1;
	}
	bpf_object__for_each_program(p, s->obj)
		bpf_program__set_autoload(p, p == s->progs.file_open_iter);
	if (p15_counters_configure(s->maps.file_counters, (volatile uint32_t *)&s->rodata->file_counters_ncpu, ncpu) ||
	    p15_counters_configure(s->maps.flow_counters, (volatile uint32_t *)&s->rodata->flow_counters_ncpu, ncpu)) {
		printf("FAIL the counter maps could not be sized\n");
		return 1;
	}
	if (file_bpf__load(s)) {
		printf("SKIP (file_open_iter could not be loaded here: %s)\n", strerror(errno));
		file_bpf__destroy(s);
		return 77;
	}
	fd = bpf_map__fd(s->maps.files);
	for (unsigned i = 0; i < N; i++) {
		__u64 key = 0x1000 + 8 * i;
		struct file_ent e = { .fid = i + 1, .state = E[i].before };

		EXPECT(!bpf_map_update_elem(fd, &key, &e, BPF_NOEXIST), "an entry planted");
	}
	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = (__u32)fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(s->progs.file_open_iter, &opts);
	EXPECT(link, "the iterator's link on the open-file map");
	EXPECT(!p15_counters_map(&ctr, bpf_map__fd(s->maps.file_counters), ncpu), "the counters mapped");
	if (failures) {
		printf("test_open_iter: %d FAILED\n", failures);
		return 1;
	}
	for (int pass = 1; pass <= 2; pass++) {
		char buf[64];
		int it = bpf_iter_create(bpf_link__fd(link));
		ssize_t r;

		EXPECT(it >= 0, "an iterator made from the link");
		while ((r = read(it, buf, sizeof(buf))) > 0 || (r < 0 && errno == EINTR))
			;
		EXPECT(r == 0, "read to its end");
		close(it);
		p15_counters_sum(&ctr, sum);
		EXPECT(sum[P15_FC_SESSION_OPEN_AT_END] == IN_FLIGHT, pass == 1 ? "the opens in flight counted, and only they" :
		       "a second pass counts nothing more");
		EXPECT(sum[P15_FC_SESSION_CLAIM_RACE] == 0, "no claim given up");
		for (unsigned i = 0; i < N; i++) {
			__u64 key = 0x1000 + 8 * i;
			struct file_ent e = { 0 };

			EXPECT(!bpf_map_lookup_elem(fd, &key, &e) && e.state == E[i].after, "each entry's marks as expected");
		}
	}
	p15_counters_unmap(&ctr);
	bpf_link__destroy(link);
	file_bpf__destroy(s);
	if (failures) {
		printf("test_open_iter: %d FAILED\n", failures);
		return 1;
	}
	printf("test_open_iter: %d opens in flight claimed among %d entries, once\n", IN_FLIGHT, N);
	return 0;
}
