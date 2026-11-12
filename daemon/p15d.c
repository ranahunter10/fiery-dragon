// SPDX-License-Identifier: MIT
/*
 * p15d: the capture daemon (Phase 1 step 4b; ADR-0006, 0007, 0017, 0019). Wiring only:
 *   config -> load + attach + self-test -> the snapshot iterator -> run directory and WAL (its
 *   first segment opens with a process snapshot, as every later one does: ADR-0007 rule 3) ->
 *   writer thread -> drain loop on this thread (SCHED_FIFO 1) -> on stop: the closing snapshot
 *   while the hooks are attached (ADR-0023 rule 1), detach, empty the rings, join the writer
 *   (final STATS, invariant, END) -> exit with the run's code (exitcodes.h).
 *
 *   p15d --wal-dir /var/lib/p15 [--duration S] [--textfile PATH] [...]   (root)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "config.h"
#include "crc32c.h"
#include "drain.h"
#include "exitcodes.h"
#include "loader.h"
#include "p15_records.h"
#include "run.h"
#include "snapshot.h"
#include "wal.h"
#include "writer.h"

#ifndef P15_GIT_COMMIT
#define P15_GIT_COMMIT "unknown"
#endif
#ifndef P15_BPFTOOL_VERSION
#define P15_BPFTOOL_VERSION "unknown"
#endif

static struct p15_run run;
static struct p15_snapshot snap;   /* ~18 KiB of read buffer: not on the stack */

static int take_closing(void *ctx, struct p15w *w)
{
	return p15_snapshot_take(ctx, P15_SNAP_CLOSING, w);
}

static void on_signal(int sig)
{
	atomic_store(&run.stop_signal, sig);
	atomic_store(&run.stop, 1);
}

__attribute__((format(printf, 2, 0)))
static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	return level == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, ap);
}

/* One structured log line on stderr (ADR-0019 G4.3): level, code, message. */
static void logline(const char *level, const char *code, const char *msg)
{
	fprintf(stderr, "p15d level=%s code=%s msg=\"%s\"\n", level, code, msg);
}

static int read_line(const char *path, char *out, size_t n)
{
	FILE *f = fopen(path, "r");

	if (!f)
		return -1;
	if (!fgets(out, (int)n, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	out[strcspn(out, "\n")] = '\0';
	return 0;
}

/* Raise the drain (this thread) to SCHED_FIFO 1; else nice -10; the outcome goes in the header. */
static const char *raise_priority(int want_rt)
{
	struct sched_param sp = { .sched_priority = 1 };

	if (!want_rt)
		return "normal (--no-rt)";
	if (!pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp))
		return "SCHED_FIFO 1";
	if (!setpriority(PRIO_PROCESS, 0, -10))
		return "nice -10 (SCHED_FIFO refused)";
	return "normal (SCHED_FIFO and nice refused)";
}

/*
 * The stop's watchdog fired (E-0162): the writer made no progress for --stop-stall-s while p15d
 * waited for it. The BPF programs are detached, the error is logged, and p15d exits without
 * waiting: the writer still holds the WAL, so nothing it uses is freed, and END is not written
 * (a reader says the run did not stop in order). A stop that cannot finish is never a silent wait.
 */
static int stuck(struct p15_run *r, struct p15_loader *l, const char *phase)
{
	char msg[256];

	p15_loader_detach(l);
	snprintf(msg, sizeof(msg), "the writer made no progress for %u s during %s; exiting without END "
		 "(the WAL is valid up to its last synced batch)", r->cfg.stop_stall_s, phase);
	logline("error", "stuck", msg);
	return P15_EXIT_STUCK;
}

int main(int argc, char **argv)
{
	static char run_dir[4096], err[300], boot_id[64], host[256], tz[64], run_id[96], ring_b[24], bulk_b[24], cut[8] = "0";
	static char cfg_vals[24][24];
	struct p15w_kv meta[40];
	struct p15_loader ld;
	struct p15_drain d;
	struct p15_writer w;
	struct p15w_opts wo;
	struct utsname u;
	struct sigaction sa;
	pthread_t wt;
	const char *sched;
	size_t nm = 0;
	uint64_t end_ns = 0;
	int rc, code, poll_ms;

	if (p15_config_parse(&run.cfg, argc, argv, err, sizeof(err))) {
		logline("error", "usage", err);
		p15_config_usage(stderr);
		return P15_EXIT_USAGE;
	}
	run.q.efd = -1;
	run.tgid = (uint32_t)getpid();
	run.spine_ring_bytes = run.cfg.spine_ring_kb * 1024u;
	libbpf_set_print(print_libbpf);

	run.bulk_ring_bytes = run.cfg.bulk_ring_kb * 1024u;
	run.net = run.cfg.net;
	run.files = run.cfg.files;
	/* The snapshot object first: loading it writes its .bss with a map update, which holds
	 * bpf_prog_active while preemptible, so it must happen before any program is attached. From
	 * the spine's attach on, p15d makes no map syscall (ADR-0026). */
	code = p15_snapshot_init(&snap, &run, err, sizeof(err));
	if (code) {
		logline("error", "load", err);
		p15_snapshot_free(&snap);
		return code;
	}
	{
		struct p15_loader_opts lo = {
			.spine_ring_bytes = run.spine_ring_bytes, .bulk_ring_bytes = run.bulk_ring_bytes, .net = run.net,
			.files = run.files, .test_no_path_fentry = run.cfg.test_no_path_fentry,
			.file_map_entries = run.cfg.file_map_entries, .obj_map_entries = run.cfg.obj_map_entries,
		};

		code = p15_loader_start(&ld, &lo, err, sizeof(err));
	}
	if (code) {
		logline("error", "load", err);
		p15_loader_free(&ld);
		p15_snapshot_free(&snap);
		return code;
	}
	run.start_ns = ld.daemon_start_ns;
	for (int t = 0; t < P15_SPINE_TYPES; t++)
		run.miss_fd[t] = ld.miss_fd[t];
	for (int i = 0; i < ld.n_net_miss; i++)
		run.net_miss_fd[i] = ld.net_miss_fd[i];
	run.n_net_miss = ld.n_net_miss;
	run.spine_selftest_consumed = ld.spine_consumed;
	run.net_selftest_consumed = ld.net_consumed;
	run.file_selftest_consumed = ld.file_consumed;
	run.file_fentry_fd = ld.file_fentry_fd;
	for (int i = 0; i < ld.n_file_kprobe; i++)
		run.file_kprobe_fd[i] = ld.file_kprobe_fd[i];
	run.n_file_kprobe = ld.n_file_kprobe;
	for (int i = 0; i < ld.n_flow_prog; i++)
		run.flow_prog_fd[i] = ld.flow_prog_fd[i];
	run.n_flow_prog = ld.n_flow_prog;
	sched = raise_priority(run.cfg.realtime);

	/* the run directory: <wal-dir>/<UTC time>-<boot id prefix> (ADR-0007 rule 1) */
	if (read_line("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id)) || gethostname(host, sizeof(host)) ||
	    uname(&u)) {
		logline("error", "oserr", "cannot read boot_id, hostname or uname");
		p15_loader_free(&ld);
		return P15_EXIT_OSERR;
	}
	{
		time_t t = time(NULL);
		struct tm g;

		gmtime_r(&t, &g);
		strftime(run_id, sizeof(run_id), "%Y%m%dT%H%M%SZ", &g);
		snprintf(run_id + strlen(run_id), sizeof(run_id) - strlen(run_id), "-%.8s", boot_id);
	}
	snprintf(run_dir, sizeof(run_dir), "%s/%s", run.cfg.wal_root, run_id);
	if (mkdir(run.cfg.wal_root, 0750) && errno != EEXIST) {
		logline("error", "io", "cannot create --wal-dir");
		p15_loader_free(&ld);
		return P15_EXIT_IO;
	}
	if (mkdir(run_dir, 0750)) {
		logline("error", "io", "cannot create the run directory (exists, or no permission)");
		p15_loader_free(&ld);
		return P15_EXIT_IO;
	}
	tzset();
	snprintf(tz, sizeof(tz), "%s", getenv("TZ") ? getenv("TZ") : tzname[0]);
	snprintf(ring_b, sizeof(ring_b), "%u", run.spine_ring_bytes);
	snprintf(bulk_b, sizeof(bulk_b), "%u", run.bulk_ring_bytes);
#define KV(k, v) do { meta[nm].key = (k); meta[nm].value = (v); nm++; } while (0)
	KV("run.id", run_id);
	KV("boot_id", boot_id);
	KV("hostname", host);
	KV("kernel.release", u.release);
	KV("schema.hash", P15_SCHEMA_HASH);
	KV("daemon.commit", P15_GIT_COMMIT);
	KV("libbpf.version", libbpf_version_string());
	KV("bpftool.version", P15_BPFTOOL_VERSION);
	KV("hooks.manifest", ld.manifest);
	KV("selftest.result", run.net && run.files ? "pass (spine, files, net)" : run.net ? "pass (spine, net)"
			      : run.files ? "pass (spine, files)" : "pass (spine)");
	KV("ring.spine.bytes", ring_b);
	KV("ring.bulk.bytes", run.net || run.files ? bulk_b : "0 (--no-net --no-files: no bulk capture)");
	KV("tz", tz);
	KV("drain.sched", sched);
	KV("recovered.bytes_cut", cut);
#undef KV
	nm += p15_config_meta(&run.cfg, meta + nm, cfg_vals, sizeof(meta) / sizeof(meta[0]) - nm);

	memset(&wo, 0, sizeof(wo));
	wo.dir = run_dir;
	wo.max_bytes = (uint64_t)run.cfg.rotate_mb << 20;
	wo.max_ns = (uint64_t)run.cfg.rotate_s * 1000000000ull;
	wo.sync_ns = (uint64_t)run.cfg.sync_ms * 1000000ull;
	wo.meta = meta;
	wo.nmeta = nm;
	p15_snapshot_set_fd(&snap, ld.file, ld.fd_iter_link);   /* NULL, NULL with --no-files */
	if (run.cfg.start_pause_ms) {
		/* TEST ONLY (config.test_start_pause_ms in the header): the window between the self-tests and
		 * the first opening snapshot, where only the loader's facts epoch keeps an object's facts
		 * (E-0151, E-0161) */
		fprintf(stderr, "p15d level=info code=test_pause ms=%u\n", run.cfg.start_pause_ms);
		usleep(run.cfg.start_pause_ms * 1000u);
	}
	wo.on_open = p15_snapshot_on_open;
	wo.on_open_ctx = &snap;
	memset(&w, 0, sizeof(w));
	w.run = &run;
	w.closing = take_closing;
	w.closing_ctx = &snap;
	rc = p15w_open(&w.wal, &wo);
	if (rc) {
		logline("error", "io", "cannot open the first WAL segment");
		p15_loader_free(&ld);
		return P15_EXIT_IO;
	}
	if (p15q_init(&run.q, run.cfg.queue_batches, run.cfg.batch_kb * 1024u) ||
	    p15_drain_init(&d, &run, p15_loader_spine_rb_fd(&ld), p15_loader_counters_fd(&ld), p15_loader_bulk_rb_fd(&ld),
			   p15_loader_bulk_counters_fd(&ld), p15_loader_file_counters_fd(&ld),
			   p15_loader_flow_counters_fd(&ld))) {
		logline("error", "oserr", "cannot allocate the queue or the drain");
		return P15_EXIT_OSERR;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;            /* no SA_RESTART: a signal ends the current poll */
	if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL)) {
		logline("error", "oserr", "cannot install signal handlers");
		return P15_EXIT_OSERR;
	}
	if (pthread_create(&wt, NULL, p15_writer_main, &w)) {
		logline("error", "oserr", "cannot start the writer thread");
		return P15_EXIT_OSERR;
	}	pthread_setname_np(wt, "p15d-writer");   /* per-thread CPU in /proc (bench/idle_cost) */

	fprintf(stderr, "p15d level=info code=start run_dir=%s sched=\"%s\" spine_ring=%u net=%s files=%s crc32c=%s\n", run_dir,
		sched, run.spine_ring_bytes, run.net ? "on" : "off (--no-net)",
		run.files ? (run.cfg.test_no_path_fentry ? "on (TEST: no path fentry)" : "on") : "off (--no-files)",
		p15_crc32c_impl());
	if (run.cfg.duration_s)
		end_ns = p15_mono_ns() + (uint64_t)run.cfg.duration_s * 1000000000ull;

	poll_ms = P15_POLL_MIN_MS;
	while (!atomic_load(&run.stop) && (!end_ns || p15_mono_ns() < end_ns)) {
		if (p15_drain_poll(&d, poll_ms))   /* ADR-0020 rule 2, ADR-0030: high-water wake-ups, an adaptive timer */
			p15_fail(&run, P15_EXIT_INTERNAL, "drain: poll or counter read failed");
		poll_ms = p15_poll_next(poll_ms, d.last_taken, d.queue_full_now, (int)run.cfg.poll_max_ms);
		if (run.cfg.drain_pause_ms)
			usleep(run.cfg.drain_pause_ms * 1000u);   /* TEST ONLY: config.test_drain_pause_ms in the header */
	}

	/* ADR-0023 rule 1: the closing snapshot, while the hooks are attached, so a process that starts
	 * or ends during it is in the snapshot, in an event, or both. The writer takes it (it owns the
	 * WAL); this thread keeps draining meanwhile. Not on the fatal path: END then says 0. */
	if (!atomic_load(&run.fatal_code)) {
		struct p15_watch wd = { 0 };

		atomic_store(&run.closing_req, P15_CLOSING_ASKED);
		p15q_kick(&run.q);
		while (atomic_load(&run.closing_req) != P15_CLOSING_DONE && !atomic_load(&run.fatal_code)) {
			if (p15_drain_poll(&d, 10))
				p15_fail(&run, P15_EXIT_INTERNAL, "drain: poll or counter read failed");
			if (p15_writer_stalled(&run, &wd, p15_mono_ns()))
				return stuck(&run, &ld, "the closing snapshot");
		}
	}
	p15_loader_detach(&ld);
	rc = p15_drain_finish(&d);
	if (rc == -ETIMEDOUT)
		return stuck(&run, &ld, "the final drain");
	if (rc)
		p15_fail(&run, P15_EXIT_INTERNAL, "drain: final emptying failed");
	{
		struct p15_watch wd = { 0 };

		/* the writer writes END and closes the WAL; wait for it as long as it moves (E-0162) */
		while (!atomic_load(&run.writer_exited)) {
			if (p15_writer_stalled(&run, &wd, p15_mono_ns()))
				return stuck(&run, &ld, "END and the WAL's close");
			usleep(10000);
		}
	}
	pthread_join(wt, NULL);
	if (w.close_rc)
		p15_fail(&run, P15_EXIT_IO, "WAL close failed");
	code = p15_run_exit_code(&run);
	fprintf(stderr, "p15d level=info code=end exit=%d state=%d invariant=%d reason=\"%s\"\n", code,
		atomic_load(&run.state), atomic_load(&run.invariant),
		atomic_load(&run.reason_set) ? run.reason : "stop requested");
	p15_drain_free(&d);
	p15q_free(&run.q);
	p15_snapshot_free(&snap);
	p15_loader_free(&ld);
	return code;
}
