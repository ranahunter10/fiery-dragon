// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * core_smoke: load core_smoke.bpf.o through its generated skeleton, built
 * against the vendored libbpf (ADR-0002).
 *
 *   core_smoke            open and load only (the verifier judges it)
 *   core_smoke --attach   also attach, exec /bin/true once, and require that
 *                         the child's exec arrives with the child's tgid and
 *                         a non-zero leader start time
 *
 * Exit 0 on success; non-zero with a reason otherwise.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "core_smoke.skel.h"

struct smoke_event {
	unsigned long long start_ns;
	unsigned int tgid;
	unsigned int pad;
};

static pid_t child;
static int matched;
static unsigned long long matched_start;

static int on_event(void *ctx, void *data, size_t len)
{
	const struct smoke_event *e = data;

	(void)ctx;
	if (len != sizeof(*e))
		return -EINVAL;
	if ((pid_t)e->tgid == child && e->start_ns != 0) {
		matched++;
		matched_start = e->start_ns;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int attach = argc > 1 && strcmp(argv[1], "--attach") == 0;
	struct core_smoke_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err = 1, st;

	skel = core_smoke_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "open_and_load failed: %s\n", strerror(errno));
		return 1;
	}
	printf("loaded: libbpf %s\n", libbpf_version_string());
	if (!attach) {
		err = 0;
		goto out;
	}
	if (core_smoke_bpf__attach(skel)) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto out;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.smoke_rb), on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		goto out;
	}
	child = fork();
	if (child == 0) {
		execl("/bin/true", "true", (char *)NULL);
		_exit(127);
	}
	waitpid(child, &st, 0);
	for (int i = 0; i < 10 && !matched; i++)
		ring_buffer__poll(rb, 100);
	printf("child %d: matched %d, start_ns %llu; seen %llu, reserve_failed %llu\n", (int)child, matched,
	       matched_start, (unsigned long long)skel->bss->smoke_seen,
	       (unsigned long long)skel->bss->smoke_reserve_failed);
	err = matched == 1 ? 0 : 1;
out:
	ring_buffer__free(rb);
	core_smoke_bpf__destroy(skel);
	return err;
}
