// SPDX-License-Identifier: MIT
/* Loading the spine programs and the self-test (ADR-0003). See loader.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "counters.h"
#include "exitcodes.h"
#include "loader.h"
#include "selftest.h"
#include "net.skel.h"
#include "selftest_net.h"
#include "spine.skel.h"

static int manifest_add(struct p15_loader *l, struct bpf_object *o, size_t *off)
{
	struct bpf_program *p;

	bpf_object__for_each_program(p, o) {
		int n = snprintf(l->manifest + *off, sizeof(l->manifest) - *off, "%s%s", *off ? "," : "",
				 bpf_program__section_name(p));

		if (n < 0 || (size_t)n >= sizeof(l->manifest) - *off)
			return -1;
		*off += (size_t)n;
	}
	return 0;
}

int p15_loader_start(struct p15_loader *l, uint32_t spine_ring_bytes, uint32_t bulk_ring_bytes, int net,
		     char *err, size_t errlen)
{
	FILE *null;
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
	l->spine->rodata->spine_wake_bytes = spine_ring_bytes / 4;   /* ADR-0020 rule 2 */
	l->ncpu = libbpf_num_possible_cpus();
	if (l->ncpu <= 0 || p15_counters_configure(l->spine->maps.spine_counters, &l->spine->rodata->spine_counters_ncpu,
						   l->ncpu)) {
		snprintf(err, errlen, "spine: cannot size the counters for %d possible CPUs (ADR-0026)", l->ncpu);
		return P15_EXIT_LOAD;
	}
	if (spine_bpf__load(l->spine)) {
		snprintf(err, errlen, "spine: load failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	if (p15_counters_verify(l->spine->maps.spine_counters, l->ncpu)) {
		snprintf(err, errlen, "spine: the loaded counter map is not the mmapable array asked for (ADR-0026)");
		return P15_EXIT_INTERNAL;
	}
	if (net) {
		l->net = net_bpf__open();
		if (!l->net) {
			snprintf(err, errlen, "net: open failed: %s", strerror(errno));
			return P15_EXIT_LOAD;
		}
		if (bpf_map__set_max_entries(l->net->maps.bulk_rb, bulk_ring_bytes)) {
			snprintf(err, errlen, "net: bulk ring size %u refused", bulk_ring_bytes);
			return P15_EXIT_CONFIG;
		}
		l->net->rodata->bulk_wake_bytes = bulk_ring_bytes / 4;   /* ADR-0020 rule 2 */
		if (p15_counters_configure(l->net->maps.bulk_counters, &l->net->rodata->bulk_counters_ncpu, l->ncpu)) {
			snprintf(err, errlen, "net: cannot size the counters for %d possible CPUs (ADR-0026)", l->ncpu);
			return P15_EXIT_LOAD;
		}
		if (net_bpf__load(l->net)) {
			snprintf(err, errlen, "net: load failed: %s (fentry/fexit unavailable? --no-net runs without "
				 "network capture)", strerror(errno));
			return P15_EXIT_LOAD;
		}
		if (p15_counters_verify(l->net->maps.bulk_counters, l->ncpu)) {
			snprintf(err, errlen, "net: the loaded counter map is not the mmapable array asked for (ADR-0026)");
			return P15_EXIT_INTERNAL;
		}
	}
	/* Every object is loaded and its maps written before anything attaches: from the first attach
	 * on, p15d makes no map syscall (ADR-0026). Then the spine, then the network programs. */
	if (access("/sys/kernel/tracing/events/sched/sched_process_exec", F_OK)) {
		snprintf(err, errlen, "tracefs is not mounted at /sys/kernel/tracing (the spine's exec, exit and rename "
			 "hooks are classic tracepoints, ADR-0020): mount -t tracefs nodev /sys/kernel/tracing");
		return P15_EXIT_LOAD;
	}
	if (spine_bpf__attach(l->spine)) {
		snprintf(err, errlen, "spine: attach failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	l->miss_fd[1] = bpf_program__fd(l->spine->progs.spine_fork);
	l->miss_fd[2] = bpf_program__fd(l->spine->progs.spine_exec);
	l->miss_fd[3] = bpf_program__fd(l->spine->progs.spine_exit);
	l->miss_fd[4] = bpf_program__fd(l->spine->progs.spine_rename);
	if (manifest_add(l, l->spine->obj, &off)) {
		snprintf(err, errlen, "hook manifest too long");
		return P15_EXIT_INTERNAL;
	}
	if (l->net) {
		if (net_bpf__attach(l->net)) {
			snprintf(err, errlen, "net: attach failed: %s (fentry/fexit unavailable? --no-net runs without "
				 "network capture)", strerror(errno));
			return P15_EXIT_LOAD;
		}
		if (manifest_add(l, l->net->obj, &off)) {
			snprintf(err, errlen, "hook manifest too long");
			return P15_EXIT_INTERNAL;
		}
		{
			struct bpf_program *p;

			bpf_object__for_each_program(p, l->net->obj) {
				if (l->n_net_miss >= (int)(sizeof(l->net_miss_fd) / sizeof(l->net_miss_fd[0]))) {
					snprintf(err, errlen, "more network programs than net_miss_fd holds");
					return P15_EXIT_INTERNAL;
				}
				l->net_miss_fd[l->n_net_miss++] = bpf_program__fd(p);
			}
		}
	}
	null = fopen("/dev/null", "w");
	l->selftest_failed = p15_selftest_run_ex(bpf_map__fd(l->spine->maps.spine_rb), null ? null : stderr,
						 &l->daemon_start_ns, &l->spine_consumed);
	if (null)
		fclose(null);
	if (l->selftest_failed != 0 || !l->daemon_start_ns) {
		snprintf(err, errlen, "self-test %s (%d)", l->selftest_failed < 0 ? "could not run" : "failed",
			 l->selftest_failed);
		return P15_EXIT_SELFTEST;
	}
	if (l->net) {
		null = fopen("/dev/null", "w");
		l->net_selftest_failed = p15_selftest_net(bpf_map__fd(l->net->maps.bulk_rb), null ? null : stderr,
						    &l->net_consumed);
		if (null)
			fclose(null);
		if (l->net_selftest_failed != 0) {
			snprintf(err, errlen, "network self-test %s (%d)", l->net_selftest_failed < 0 ? "could not run" : "failed",
				 l->net_selftest_failed);
			return P15_EXIT_SELFTEST;
		}
	}
	return 0;
}

void p15_loader_detach(struct p15_loader *l)
{
	if (l->spine)
		spine_bpf__detach(l->spine);
	if (l->net)
		net_bpf__detach(l->net);
}

void p15_loader_free(struct p15_loader *l)
{
	spine_bpf__destroy(l->spine);
	net_bpf__destroy(l->net);
	l->spine = NULL;
	l->net = NULL;
}

int p15_loader_spine_rb_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_rb); }
int p15_loader_counters_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_counters); }
int p15_loader_bulk_rb_fd(const struct p15_loader *l) { return l->net ? bpf_map__fd(l->net->maps.bulk_rb) : -1; }
int p15_loader_bulk_counters_fd(const struct p15_loader *l) { return l->net ? bpf_map__fd(l->net->maps.bulk_counters) : -1; }
