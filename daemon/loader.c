// SPDX-License-Identifier: MIT
/* Loading the spine programs and the self-test (ADR-0003). See loader.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "exitcodes.h"
#include "loader.h"
#include "selftest.h"
#include "spine.skel.h"

int p15_loader_start(struct p15_loader *l, uint32_t spine_ring_bytes, char *err, size_t errlen)
{
	FILE *null;
	struct bpf_program *p;
	size_t off = 0;

	memset(l, 0, sizeof(*l));
	l->spine = spine_bpf__open();
	if (!l->spine) {
		snprintf(err, errlen, "spine: open failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	if (bpf_map__set_max_entries(l->spine->maps.spine_rb, spine_ring_bytes)) {
		snprintf(err, errlen, "spine: ring size %u refused", spine_ring_bytes);
		return P15_EXIT_CONFIG;
	}
	if (spine_bpf__load(l->spine)) {
		snprintf(err, errlen, "spine: load failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	if (spine_bpf__attach(l->spine)) {
		snprintf(err, errlen, "spine: attach failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	bpf_object__for_each_program(p, l->spine->obj) {
		int n = snprintf(l->manifest + off, sizeof(l->manifest) - off, "%s%s", off ? "," : "",
				 bpf_program__section_name(p));

		if (n < 0 || (size_t)n >= sizeof(l->manifest) - off) {
			snprintf(err, errlen, "hook manifest too long");
			return P15_EXIT_INTERNAL;
		}
		off += (size_t)n;
	}
	null = fopen("/dev/null", "w");
	l->selftest_failed = p15_selftest_run_ex(bpf_map__fd(l->spine->maps.spine_rb), null ? null : stderr,
						 &l->daemon_start_ns);
	if (null)
		fclose(null);
	if (l->selftest_failed != 0 || !l->daemon_start_ns) {
		snprintf(err, errlen, "self-test %s (%d)", l->selftest_failed < 0 ? "could not run" : "failed",
			 l->selftest_failed);
		return P15_EXIT_SELFTEST;
	}
	return 0;
}

void p15_loader_detach(struct p15_loader *l)
{
	if (l->spine)
		spine_bpf__detach(l->spine);
}

void p15_loader_free(struct p15_loader *l)
{
	spine_bpf__destroy(l->spine);
	l->spine = NULL;
}

int p15_loader_spine_rb_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_rb); }
int p15_loader_counters_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_counters); }
