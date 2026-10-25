// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * rb_size: load the three record-sizing programs, exec /bin/true with an argv
 * of known length, and print the size each mode's record occupies in its ring.
 * Usage: rb_size [ARGV_BYTES]   (root). Exit 0 if all three modes delivered.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "rb_size.skel.h"

struct rec { unsigned mode, len, tgid, pad; };

static pid_t child;
static size_t got_size[3];
static unsigned got_len[3];

static int on_rec(void *ctx, void *data, size_t size)
{
	const struct rec *r = data;

	(void)ctx;
	if (size < sizeof(*r) || r->mode > 2 || (pid_t)r->tgid != child)
		return 0;
	got_size[r->mode] = size;
	got_len[r->mode] = r->len;
	return 0;
}

int main(int argc, char **argv)
{
	int want = argc > 1 ? atoi(argv[1]) : 200, st, rc = 1;
	static const char *names[] = { "fixed (reserve max)", "output (exact len)", "dynptr (exact len)" };
	struct rb_size_bpf *s = rb_size_bpf__open_and_load();
	struct ring_buffer *rb;
	char *arg;

	if (!s) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}
	if (rb_size_bpf__attach(s)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto out;
	}
	rb = ring_buffer__new(bpf_map__fd(s->maps.rb_fixed), on_rec, NULL, NULL);
	if (!rb || ring_buffer__add(rb, bpf_map__fd(s->maps.rb_output), on_rec, NULL) ||
	    ring_buffer__add(rb, bpf_map__fd(s->maps.rb_dynptr), on_rec, NULL)) {
		fprintf(stderr, "ring_buffer setup failed\n");
		goto out;
	}
	/* argv = "true" + NUL + one argument of (want - 6) bytes + NUL: want bytes in all */
	if (want < 8 || want > 4096)
		want = 200;
	arg = malloc(want - 5);
	memset(arg, 'x', want - 6);
	arg[want - 6] = 0;
	child = fork();
	if (child == 0) {
		execl("/bin/true", "true", arg, (char *)NULL);
		_exit(127);
	}
	waitpid(child, &st, 0);
	ring_buffer__poll(rb, 200);
	ring_buffer__consume(rb);
	printf("libbpf %s; child argv bytes %d\n", libbpf_version_string(), want);
	printf("%-22s %10s %14s\n", "mode", "rec len", "ring bytes");
	rc = 0;
	for (int m = 0; m < 3; m++) {
		printf("%-22s %10u %14zu\n", names[m], got_len[m], got_size[m]);
		rc |= got_size[m] == 0;
	}
	printf("%s\n", rc ? "FAIL: a mode delivered nothing" : "ok: all three modes delivered");
	ring_buffer__free(rb);
	free(arg);
out:
	rb_size_bpf__destroy(s);
	return rc;
}
