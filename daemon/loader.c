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
#include "p15_snap.h"   /* before file.skel.h: its .bss holds struct p15_fd_books */
#include "file.skel.h"
#include "net.skel.h"
#include "p15_file.h"
#include "p15_flow.h"
#include "selftest_file.h"
#include "selftest_flow.h"
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

/* The file-identity object (ADR-0015): sized, loaded, its counter map checked. It owns the bulk ring. */
static int load_file(struct p15_loader *l, const struct p15_loader_opts *o, char *err, size_t errlen)
{
	l->file = file_bpf__open();
	if (!l->file) {
		snprintf(err, errlen, "file: open failed: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	if (bpf_map__set_max_entries(l->file->maps.bulk_rb, o->bulk_ring_bytes) ||
	    bpf_map__set_max_entries(l->file->maps.files, o->file_map_entries) ||
	    bpf_map__set_max_entries(l->file->maps.objs, o->obj_map_entries) ||
	    bpf_map__set_max_entries(l->file->maps.flow_test_tried, o->test_flow_file_fail_first ? 65536 : 1)) {
		snprintf(err, errlen, "file: bulk ring %u or map sizes %u/%u refused", o->bulk_ring_bytes, o->file_map_entries,
			 o->obj_map_entries);
		return P15_EXIT_CONFIG;
	}
	l->file->rodata->file_wake_bytes = o->bulk_ring_bytes / 4;   /* ADR-0020 rule 2 */
	if (p15_counters_configure(l->file->maps.file_counters, &l->file->rodata->file_counters_ncpu, l->ncpu) ||
	    p15_counters_configure(l->file->maps.flow_counters, &l->file->rodata->flow_counters_ncpu, l->ncpu)) {
		snprintf(err, errlen, "file: cannot size the counters for %d possible CPUs (ADR-0026)", l->ncpu);
		return P15_EXIT_LOAD;
	}
	l->file->rodata->flow_self_tgid = (__u32)getpid();   /* decision 47.1: p15d's own transfers are excluded */
	l->file->rodata->flow_test_file_fail_first = o->test_flow_file_fail_first ? 1 : 0;
	if (o->test_no_path_fentry)
		bpf_program__set_autoattach(l->file->progs.file_open_path, false);
	bpf_program__set_autoattach(l->file->progs.file_fd_iter, false);   /* the snapshot's FD pass: below */
	if (file_bpf__load(l->file)) {
		snprintf(err, errlen, "file: load failed: %s (fentry or kprobe.session unavailable? --no-files runs without "
			 "file identity)", strerror(errno));
		return P15_EXIT_LOAD;
	}
	if (p15_counters_verify(l->file->maps.file_counters, l->ncpu) ||
	    p15_counters_verify(l->file->maps.flow_counters, l->ncpu)) {
		snprintf(err, errlen, "file: a loaded counter map is not the mmapable array asked for (ADR-0026)");
		return P15_EXIT_INTERNAL;
	}
	/* The flow programs (ADR-0005) do not autoattach: they are attached after every self-test, so
	 * the file self-test's own reads and writes do not emit FLOW records the books must account
	 * for. Their fds, valid after load, are collected now for the skip counters. */
	{
		struct bpf_program *const flow[] = {
			l->file->progs.flow_read, l->file->progs.flow_write, l->file->progs.flow_readv,
			l->file->progs.flow_writev, l->file->progs.flow_send, l->file->progs.flow_recv,
		};
		for (size_t i = 0; i < sizeof(flow) / sizeof(flow[0]); i++) {
			bpf_program__set_autoattach(flow[i], false);
			l->flow_prog_fd[l->n_flow_prog++] = bpf_program__fd(flow[i]);
		}
	}
	/* The FD pass's iterator link (ADR-0015 rule 7): made now, used by every snapshot. A link, not
	 * an attach to an event: nothing runs until the snapshot creates an iterator from it. */
	l->fd_iter_link = bpf_program__attach_iter(l->file->progs.file_fd_iter, NULL);
	if (!l->fd_iter_link) {
		snprintf(err, errlen, "file: the FD pass's task_file iterator could not be made: %s", strerror(errno));
		return P15_EXIT_LOAD;
	}
	return 0;
}

int p15_loader_start(struct p15_loader *l, const struct p15_loader_opts *o, char *err, size_t errlen)
{
	FILE *null;
	size_t off = 0;
	uint32_t spine_ring_bytes = o->spine_ring_bytes, bulk_ring_bytes = o->bulk_ring_bytes;
	int net = o->net, code;

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
	if (o->files && (code = load_file(l, o, err, errlen)))
		return code;
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
		/* one bulk ring for NET and file identity (decision 19.4): the file object made it */
		if (l->file && bpf_map__reuse_fd(l->net->maps.bulk_rb, bpf_map__fd(l->file->maps.bulk_rb))) {
			snprintf(err, errlen, "net: cannot share the file object's bulk ring: %s", strerror(errno));
			return P15_EXIT_LOAD;
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
	if (l->file) {
		struct bpf_program *p;

		if (file_bpf__attach(l->file)) {
			snprintf(err, errlen, "file: attach failed: %s (--no-files runs without file identity)", strerror(errno));
			return P15_EXIT_LOAD;
		}
		if (manifest_add(l, l->file->obj, &off)) {
			snprintf(err, errlen, "hook manifest too long");
			return P15_EXIT_INTERNAL;
		}
		l->file_fentry_fd = o->test_no_path_fentry ? 0 : bpf_program__fd(l->file->progs.file_open_path);
		bpf_object__for_each_program(p, l->file->obj) {
			if (p == l->file->progs.file_open_path || p == l->file->progs.file_fd_iter)
				continue;   /* the fentry's skips are located, not lost; the iterator runs on demand */
			if (!bpf_program__autoattach(p))
				continue;   /* the flow programs: attached after the self-tests, their skips in flow_prog_fd */
			if (l->n_file_kprobe >= (int)(sizeof(l->file_kprobe_fd) / sizeof(l->file_kprobe_fd[0]))) {
				snprintf(err, errlen, "more file programs than file_kprobe_fd holds");
				return P15_EXIT_INTERNAL;
			}
			l->file_kprobe_fd[l->n_file_kprobe++] = bpf_program__fd(p);
		}
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
	if (l->file) {
		unsigned long long fc = 0, nc = 0;

		char *text = NULL;
		size_t text_len = 0;
		FILE *mem = open_memstream(&text, &text_len);

		l->file_selftest_failed = p15_selftest_file(bpf_map__fd(l->file->maps.bulk_rb), o->test_no_path_fentry,
							    mem ? mem : stderr, &fc, &nc);
		if (mem)
			fclose(mem);
		/* a failed self-test says which check failed: without that the failure cannot be diagnosed */
		if (l->file_selftest_failed != 0 && text)
			fputs(text, stderr);
		free(text);
		l->file_consumed += fc;
		l->net_consumed += nc;
		if (l->file_selftest_failed != 0) {
			snprintf(err, errlen, "file self-test %s (%d)", l->file_selftest_failed < 0 ? "could not run" : "failed",
				 l->file_selftest_failed);
			return P15_EXIT_SELFTEST;
		}
	}
	if (l->net) {
		unsigned long long nc = 0, fc = 0;

		null = fopen("/dev/null", "w");
		l->net_selftest_failed = p15_selftest_net(bpf_map__fd(l->net->maps.bulk_rb), null ? null : stderr, &nc, &fc);
		if (null)
			fclose(null);
		l->net_consumed += nc;
		l->file_consumed += fc;
		if (l->net_selftest_failed != 0) {
			snprintf(err, errlen, "network self-test %s (%d)", l->net_selftest_failed < 0 ? "could not run" : "failed",
				 l->net_selftest_failed);
			return P15_EXIT_SELFTEST;
		}
	}
	/* Now the flow programs (ADR-0005): the self-tests are done, so from here a transfer is a real
	 * one the books account for. Attached last so a verifier or attach failure is reported before
	 * p15d claims the capture is up, then checked by their own self-test (selftest_flow.h).
	 * Opt-in with --flow until a full --flow matrix passes on the VM (STATE decision waiting 25);
	 * the programs still load with the object, so the verifier checks them whether or not they
	 * attach. */
	if (l->file && o->flow) {
		/* The socket tracepoints first (Dragon's review F-11): a vfs session counts a socket's
		 * read() or write() as owned by the socket and leaves it to the tracepoint, so the
		 * tracepoints must already be attached when the first vfs session is. */
		struct bpf_program *const flow[] = {
			l->file->progs.flow_send, l->file->progs.flow_recv, l->file->progs.flow_read,
			l->file->progs.flow_write, l->file->progs.flow_readv, l->file->progs.flow_writev,
		};
		for (size_t i = 0; i < sizeof(flow) / sizeof(flow[0]); i++) {
			struct bpf_link *lk = bpf_program__attach(flow[i]);

			if (!lk) {
				snprintf(err, errlen, "file: flow program %s attach failed: %s",
					 bpf_program__name(flow[i]), strerror(errno));
				return P15_EXIT_LOAD;
			}
			l->flow_links[l->n_flow_links++] = lk;
		}
		{
			unsigned long long flc = 0, fc = 0, nc = 0;
			char *text = NULL;
			size_t text_len = 0;
			FILE *mem = open_memstream(&text, &text_len);

			l->flow_selftest_failed = p15_selftest_flow(bpf_map__fd(l->file->maps.bulk_rb),
								    o->test_flow_file_fail_first, mem ? mem : stderr, &flc,
								    &fc, &nc);
			if (mem)
				fclose(mem);
			if (l->flow_selftest_failed != 0 && text)
				fputs(text, stderr);   /* which check failed: needed to diagnose it */
			free(text);
			l->flow_consumed += flc;
			l->file_consumed += fc;
			l->net_consumed += nc;
			if (l->flow_selftest_failed != 0) {
				snprintf(err, errlen, "flow self-test %s (%d)",
					 l->flow_selftest_failed < 0 ? "could not run" : "failed", l->flow_selftest_failed);
				return P15_EXIT_SELFTEST;
			}
		}
	}
	/* The self-tests threw away every record they took, facts included (the flow self-test's FILE
	 * records too): a new facts epoch makes the programs write each object's facts again, into the
	 * WAL this time (file.bpf.c, E-0151). The .data map is mapped: this is a store, not a system
	 * call (ADR-0026). */
	if (l->file)
		l->file->data->facts_epoch++;
	return 0;
}

void p15_loader_detach(struct p15_loader *l)
{
	if (l->spine)
		spine_bpf__detach(l->spine);
	if (l->net)
		net_bpf__detach(l->net);
	/* the flow programs were attached by hand (ADR-0005), the socket tracepoints first: destroyed in
	 * reverse, so the tracepoints outlast the vfs sessions that leave socket calls to them (F-11) */
	for (int i = l->n_flow_links - 1; i >= 0; i--)
		bpf_link__destroy(l->flow_links[i]);
	l->n_flow_links = 0;
	if (l->file)
		file_bpf__detach(l->file);
}

void p15_loader_free(struct p15_loader *l)
{
	spine_bpf__destroy(l->spine);
	net_bpf__destroy(l->net);
	bpf_link__destroy(l->fd_iter_link);
	l->fd_iter_link = NULL;
	file_bpf__destroy(l->file);
	l->spine = NULL;
	l->net = NULL;
	l->file = NULL;
}

int p15_loader_spine_rb_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_rb); }
int p15_loader_counters_fd(const struct p15_loader *l) { return bpf_map__fd(l->spine->maps.spine_counters); }
int p15_loader_bulk_rb_fd(const struct p15_loader *l)
{
	return l->file ? bpf_map__fd(l->file->maps.bulk_rb) : l->net ? bpf_map__fd(l->net->maps.bulk_rb) : -1;
}
int p15_loader_file_counters_fd(const struct p15_loader *l) { return l->file ? bpf_map__fd(l->file->maps.file_counters) : -1; }
int p15_loader_flow_counters_fd(const struct p15_loader *l) { return l->file ? bpf_map__fd(l->file->maps.flow_counters) : -1; }
int p15_loader_bulk_counters_fd(const struct p15_loader *l) { return l->net ? bpf_map__fd(l->net->maps.bulk_counters) : -1; }
