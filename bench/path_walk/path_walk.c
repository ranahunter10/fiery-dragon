// SPDX-License-Identifier: MIT
/*
 * path_walk: drive path_walk.bpf.c (root). Gate 2 of STATE decision 28.
 *
 *   path_walk DIR ROUNDS N
 *
 * The harness moves into a mount namespace of its own (every mount it makes is private and gone at
 * exit), pins itself to one CPU, and:
 *   1. opens one file per case below and prints, for each, what bpf_d_path and the walk returned;
 *   2. opens and renames concurrently: a thread renames a directory back and forth while the main
 *      thread opens files beneath it, N times; every sample whose walk is not flagged must equal
 *      bpf_d_path (a path built across a rename and not flagged is the failure this case looks for);
 *   3. ROUNDS timing rounds of N open+close each, of a short and of a deep path, with the samples
 *      not sent: bpf_d_path and the walk in the fentry, the walk in the kprobe.session.
 * Output: "case", "race" and "time" lines; summarize.py makes the report. Exit 0 if every case ran.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "path_walk.skel.h"
#include "p15_dpath.h"

#define BUF (P15_DP_BUF + 256)

struct pw_sample {   /* path_walk.bpf.c's */
	__u32 dpath_len;
	__s32 dpath_rc;
	__u32 walk_len;
	__u32 walk_flags;
	__u32 moved, pad;
	__u64 dpath_ns, walk_ns;
	char dpath[BUF];
	char walk[BUF];
};

static struct path_walk_bpf *S;
static struct ring_buffer *RB;
/* A case's samples: every open the case causes (an overlay open opens its real file too, E-0196). */
#define KEEP 4
static struct pw_sample kept[KEEP];
static int got;

static int on_sample(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size >= sizeof(kept[0])) {
		if (got < KEEP)
			memcpy(&kept[got], data, sizeof(kept[0]));
		got++;
	}
	return 0;
}

static void esc(const char *s, unsigned n, FILE *f)
{
	for (unsigned i = 0; i < n && s[i]; i++)
		fputc(s[i] == ' ' ? '_' : (s[i] < 33 || s[i] > 126 ? '?' : s[i]), f);
}

/* Is the walk's answer the kernel's? Equal strings; or a flag that says why not; or not comparable,
 * because the tree moved between bpf_d_path and the walk (each may then be right for its instant). */
static const char *verdict(const struct pw_sample *r)
{
	int eq = r->dpath_rc > 0 && r->dpath_len == r->walk_len && !memcmp(r->dpath, r->walk, r->walk_len);

	if (eq)
		return "equal";
	/* a name the walk wrote for a d_dname filesystem (SYNTH) must be equal: DNAME explains only no name */
	if ((r->walk_flags & (P15_DP_TRUNCATED | P15_DP_RACED | P15_DP_NO_ROOT)) ||
	    ((r->walk_flags & P15_DP_DNAME) && !(r->walk_flags & P15_DP_SYNTH)))
		return "flagged";
	if (r->dpath_rc <= 0)
		return "dpath_failed";
	if (r->moved)
		return "moved";
	return "MISMATCH";
}

/* The rest of a case or sample line, after its prefix. */
static void put_sample(const struct pw_sample *r, const char *v)
{
	printf(" verdict=%s flags=0x%x dpath_rc=%d dpath_len=%u walk_len=%u dpath=", v, r->walk_flags, r->dpath_rc,
	       r->dpath_len, r->walk_len);
	esc(r->dpath, r->dpath_len, stdout);
	printf(" walk=");
	esc(r->walk, r->walk_len, stdout);
	printf("\n");
}

static int rank(const char *v)
{
	return !strcmp(v, "equal") ? 0 : !strcmp(v, "flagged") ? 1 : 2;
}

/* Open path (flags) once with the samples on. One case line: the first sample's strings, the worst
 * verdict of all its samples, and how many; then one sample line per further sample (at most KEEP).
 * An open the file's ->open refuses still has its sample (a socket: security_file_open ran first). */
static int one(const char *name, const char *path, int oflags)
{
	const char *worst = "equal";
	int fd, err = 0;

	ring_buffer__consume(RB);
	got = 0;
	S->bss->emit = 1;
	fd = open(path, oflags | O_CLOEXEC);
	if (fd < 0)
		err = errno;
	else
		close(fd);
	ring_buffer__consume(RB);
	S->bss->emit = 0;
	if (!got) {
		if (err)
			printf("case %s open_failed errno=%d\n", name, err);
		else
			printf("case %s no_sample\n", name);
		return -1;
	}
	for (int k = 0; k < got && k < KEEP; k++) {
		const char *v = verdict(&kept[k]);

		if (rank(v) > rank(worst))
			worst = v;
	}
	printf("case %s samples=%d open_errno=%d", name, got, err);
	put_sample(&kept[0], worst);
	for (int k = 1; k < got && k < KEEP; k++) {
		printf("sample %s %d", name, k);
		put_sample(&kept[k], verdict(&kept[k]));
	}
	return 0;
}

static void mkdir_p(const char *p)
{
	char b[8192];

	snprintf(b, sizeof(b), "%s", p);
	for (char *c = b + 1; *c; c++)
		if (*c == '/') {
			*c = 0;
			mkdir(b, 0755);
			*c = '/';
		}
	mkdir(b, 0755);
}

static void touch(const char *p)
{
	int fd = open(p, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);

	if (fd >= 0)
		close(fd);
}

static int sh(const char *cmd)
{
	int rc = system(cmd);

	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* ---- the rename race ---- */
static atomic_int stop_race;
static char race_a[4096], race_b[4096];

static void *renamer(void *arg)
{
	long n = 0;

	cpu_set_t set;

	(void)arg;
	CPU_ZERO(&set);
	CPU_SET(0, &set);   /* another CPU than the opener's: a rename can land inside a walk */
	sched_setaffinity(0, sizeof(set), &set);
	while (!atomic_load(&stop_race)) {
		if (rename(race_a, race_b) == 0)
			rename(race_b, race_a);
		n++;
	}
	return (void *)n;
}

struct race_books {
	long samples, equal, flagged, moved, raced, retried, mismatch, dpath_failed, open_failed;
};

static int race_sample(void *ctx, void *data, size_t size)
{
	struct race_books *b = ctx;
	const struct pw_sample *r = data;
	const char *v;

	if (size < sizeof(*r))
		return 0;
	b->samples++;
	if (r->walk_flags & P15_DP_RACED)
		b->raced++;
	if (r->walk_flags & P15_DP_RETRIED)
		b->retried++;
	v = verdict(r);
	if (!strcmp(v, "equal"))
		b->equal++;
	else if (!strcmp(v, "flagged"))
		b->flagged++;
	else if (!strcmp(v, "dpath_failed"))
		b->dpath_failed++;
	else if (!strcmp(v, "moved"))
		b->moved++;
	else {
		if (b->mismatch < 5) {
			printf("race_mismatch flags=0x%x dpath=", r->walk_flags);
			esc(r->dpath, r->dpath_len, stdout);
			printf(" walk=");
			esc(r->walk, r->walk_len, stdout);
			printf("\n");
		}
		b->mismatch++;
	}
	return 0;
}

static void race(const char *dir, long n)
{
	struct race_books b = { 0 };
	struct ring_buffer *rr;
	char pa[8192], pb[8192];
	pthread_t th;
	void *renames;

	snprintf(race_a, sizeof(race_a), "%s/race/a", dir);
	snprintf(race_b, sizeof(race_b), "%s/race/b", dir);
	snprintf(pa, sizeof(pa), "%s/x/y/f", race_a);
	snprintf(pb, sizeof(pb), "%s/x/y/f", race_b);
	mkdir_p(pa);
	rmdir(pa);
	touch(pa);
	rr = ring_buffer__new(bpf_map__fd(S->maps.rb), race_sample, &b, NULL);
	if (!rr) {
		printf("race setup_failed\n");
		return;
	}
	S->bss->emit = 1;
	atomic_store(&stop_race, 0);
	pthread_create(&th, NULL, renamer, NULL);
	for (long i = 0; i < n; i++) {
		int fd = open(pa, O_RDONLY | O_CLOEXEC);

		if (fd < 0)
			fd = open(pb, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			b.open_failed++;
		else
			close(fd);
		if ((i & 255) == 255)
			ring_buffer__consume(rr);
	}
	atomic_store(&stop_race, 1);
	pthread_join(th, &renames);
	ring_buffer__consume(rr);
	ring_buffer__free(rr);
	printf("race opens=%ld renames=%ld samples=%ld equal=%ld flagged=%ld moved=%ld raced=%ld retried=%ld mismatch=%ld "
	       "dpath_failed=%ld open_failed=%ld\n",
	       n, (long)renames, b.samples, b.equal, b.flagged, b.moved, b.raced, b.retried, b.mismatch, b.dpath_failed,
	       b.open_failed);
}

/* ---- timing ---- */
static void timing(const char *label, const char *path, long rounds, long n)
{
	S->bss->emit = 0;
	for (long r = -1; r < rounds; r++) {
		__u64 fr0 = S->bss->f_runs, fd0 = S->bss->f_dpath_ns, fw0 = S->bss->f_walk_ns;
		__u64 kr0 = S->bss->k_runs, kw0 = S->bss->k_walk_ns;

		for (long i = 0; i < n; i++) {
			int fd = open(path, O_RDONLY | O_CLOEXEC);

			if (fd >= 0)
				close(fd);
			/* A discarded ring record keeps its space until a reader passes it (E-0195): read the
			 * ring as the opens go, or the fentry finds it full and stops (f_lost). */
			if ((i & 127) == 127)
				ring_buffer__consume(RB);
		}
		ring_buffer__consume(RB);
		printf("time round=%ld path=%s fentry_runs=%llu dpath_ns=%llu walk_fentry_ns=%llu kprobe_runs=%llu "
		       "walk_kprobe_ns=%llu\n",
		       r, label, (unsigned long long)(S->bss->f_runs - fr0), (unsigned long long)(S->bss->f_dpath_ns - fd0),
		       (unsigned long long)(S->bss->f_walk_ns - fw0), (unsigned long long)(S->bss->k_runs - kr0),
		       (unsigned long long)(S->bss->k_walk_ns - kw0));
	}
}

int main(int argc, char **argv)
{
	char d[512], p[8192], q[8192], cmd[16384];
	long rounds, n;
	cpu_set_t set;
	int fd, pfd[2], rc = 0;

	if (argc != 4) {
		fprintf(stderr, "usage: path_walk DIR ROUNDS N\n");
		return 2;
	}
	if (strlen(argv[1]) >= sizeof(d) || strpbrk(argv[1], " '\"$`\\;&|<>")) {
		fprintf(stderr, "path_walk: DIR must be under %zu bytes, without spaces or shell characters\n", sizeof(d));
		return 2;
	}
	rounds = atol(argv[2]);
	n = atol(argv[3]);
	if (rounds < 1 || n < 1) {
		fprintf(stderr, "path_walk: ROUNDS and N must be at least 1\n");
		return 2;
	}
	if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		fprintf(stderr, "path_walk: a private mount namespace: %s\n", strerror(errno));
		return 1;
	}
	CPU_ZERO(&set);
	CPU_SET(sysconf(_SC_NPROCESSORS_ONLN) - 1, &set);
	sched_setaffinity(0, sizeof(set), &set);
	snprintf(d, sizeof(d), "%s", argv[1]);
	mkdir_p(d);
	S = path_walk_bpf__open_and_load();
	if (!S) {
		fprintf(stderr, "path_walk: load failed: %s\n", strerror(errno));
		return 1;
	}
	S->bss->target_tgid = (unsigned)getpid();
	if (path_walk_bpf__attach(S)) {
		fprintf(stderr, "path_walk: attach failed: %s\n", strerror(errno));
		return 1;
	}
	RB = ring_buffer__new(bpf_map__fd(S->maps.rb), on_sample, NULL, NULL);
	if (!RB)
		return 1;
	printf("config dir=%s rounds=%ld n=%ld kallsyms_rename_lock=%d kallsyms_mount_lock=%d\n", d, rounds, n,
	       !sh("grep -qw rename_lock /proc/kallsyms"), !sh("grep -qw mount_lock /proc/kallsyms"));

	/* ---- 1. the cases ---- */
	snprintf(p, sizeof(p), "%s/plain/a/b/c", d);
	mkdir_p(p);
	snprintf(p, sizeof(p), "%s/plain/a/b/c/file", d);
	touch(p);
	rc |= one("plain", p, O_RDONLY);
	rc |= one("root", "/", O_RDONLY | O_DIRECTORY);
	rc |= one("dir", d, O_RDONLY | O_DIRECTORY);
	rc |= one("proc", "/proc/self/status", O_RDONLY);
	rc |= one("sysfs", "/sys/kernel/mm/transparent_hugepage/enabled", O_RDONLY);
	rc |= one("devtmpfs", "/dev/null", O_RDONLY);
	{
		/* 40 components: within the walk's 64 */
		int o = snprintf(p, sizeof(p), "%s/deep", d);

		for (int i = 0; i < 40; i++)
			o += snprintf(p + o, sizeof(p) - o, "/d%02d", i);
		mkdir_p(p);
		snprintf(p + o, sizeof(p) - o, "/file");
		touch(p);
		rc |= one("deep40", p, O_RDONLY);
		/* 70: beyond it, so the walk must say it cut the path */
		for (int i = 40; i < 70; i++)
			o += snprintf(p + o, sizeof(p) - o, "/d%02d", i);
		mkdir_p(p);
		snprintf(p + o, sizeof(p) - o, "/file");
		touch(p);
		rc |= one("deep70", p, O_RDONLY);
	}
	{
		/* names of 255 bytes, eight of them: about 2 KiB */
		char nm[256];
		int o = snprintf(p, sizeof(p), "%s/long", d);

		memset(nm, 'n', 255);
		nm[255] = 0;
		for (int i = 0; i < 8; i++)
			o += snprintf(p + o, sizeof(p) - o, "/%s", nm);
		mkdir_p(p);
		snprintf(p + o, sizeof(p) - o, "/file");
		touch(p);
		rc |= one("longnames", p, O_RDONLY);
	}
	/* tmpfs, a bind mount, and an overlay, in this namespace only */
	snprintf(p, sizeof(p), "%s/tmpfs", d);
	mkdir_p(p);
	if (!mount("tmpfs", p, "tmpfs", 0, "size=1m")) {
		snprintf(q, sizeof(q), "%s/tmpfs/sub", d);
		mkdir_p(q);
		snprintf(q, sizeof(q), "%s/tmpfs/sub/file", d);
		touch(q);
		rc |= one("tmpfs", q, O_RDONLY);
	} else {
		printf("case tmpfs mount_failed errno=%d\n", errno);
	}
	snprintf(p, sizeof(p), "%s/plain/a", d);
	snprintf(q, sizeof(q), "%s/bound", d);
	mkdir_p(q);
	if (!mount(p, q, NULL, MS_BIND, NULL)) {
		snprintf(q, sizeof(q), "%s/bound/b/c/file", d);
		rc |= one("bind", q, O_RDONLY);
	} else {
		printf("case bind mount_failed errno=%d\n", errno);
	}
	snprintf(cmd, sizeof(cmd), "mkdir -p %s/ovl/l %s/ovl/u %s/ovl/w %s/ovl/m && echo x > %s/ovl/l/low && "
		 "mount -t overlay overlay -o lowerdir=%s/ovl/l,upperdir=%s/ovl/u,workdir=%s/ovl/w %s/ovl/m",
		 d, d, d, d, d, d, d, d, d);
	if (!sh(cmd)) {
		snprintf(q, sizeof(q), "%s/ovl/m/low", d);
		rc |= one("overlay", q, O_RDONLY);
	} else {
		printf("case overlay mount_failed\n");
	}
	/* deleted: reopened through /proc after the unlink */
	snprintf(p, sizeof(p), "%s/gone", d);
	touch(p);
	fd = open(p, O_RDONLY | O_CLOEXEC);
	unlink(p);
	snprintf(q, sizeof(q), "/proc/self/fd/%d", fd);
	rc |= one("deleted", q, O_RDONLY);
	close(fd);
	fd = memfd_create("p15memfd", MFD_CLOEXEC);
	snprintf(q, sizeof(q), "/proc/self/fd/%d", fd);
	rc |= one("memfd", q, O_RDONLY);
	close(fd);
	if (!pipe(pfd)) {
		snprintf(q, sizeof(q), "/proc/self/fd/%d", pfd[0]);
		rc |= one("pipe", q, O_RDONLY | O_NONBLOCK);
		close(pfd[0]);
		close(pfd[1]);
	}
	/* a socket: sock_no_open refuses the reopen with ENXIO, after security_file_open ran */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd >= 0) {
		snprintf(q, sizeof(q), "/proc/self/fd/%d", fd);
		rc |= one("socket", q, O_RDONLY);
		close(fd);
	} else {
		printf("case socket open_failed errno=%d\n", errno);
	}
	/* an anonymous inode */
	fd = eventfd(0, EFD_CLOEXEC);
	if (fd >= 0) {
		snprintf(q, sizeof(q), "/proc/self/fd/%d", fd);
		rc |= one("eventfd", q, O_RDONLY);
		close(fd);
	} else {
		printf("case eventfd open_failed errno=%d\n", errno);
	}
	fflush(stdout);
	/* chroot, in a child: the root the walk stops at is the task's own (the bss is a shared mapping) */
	{
		pid_t c = fork();

		if (c == 0) {
			snprintf(p, sizeof(p), "%s/plain", d);
			S->bss->target_tgid = (unsigned)getpid();
			if (chroot(p) || chdir("/")) {
				printf("case chroot chroot_failed errno=%d\n", errno);
				fflush(stdout); /* _exit does not flush stdio */
				_exit(1);
			}
			int r = one("chroot", "/a/b/c/file", O_RDONLY);

			fflush(stdout);
			_exit(r ? 1 : 0);
		}
		waitpid(c, &fd, 0);
		S->bss->target_tgid = (unsigned)getpid();
		fflush(stdout);
	}

	/* ---- 2. the rename race ---- */
	race(d, n);

	/* ---- 3. timing ---- */
	snprintf(p, sizeof(p), "%s/plain/a/b/c/file", d);
	timing("short", p, rounds, n);
	{
		int o = snprintf(p, sizeof(p), "%s/deep", d);

		for (int i = 0; i < 20; i++)
			o += snprintf(p + o, sizeof(p) - o, "/d%02d", i);
		snprintf(p + o, sizeof(p) - o, "/f20");
		touch(p);
		timing("deep20", p, rounds, n);
	}
	printf("end lost=%llu kprobe_flags=0x%llx\n", (unsigned long long)S->bss->f_lost,
	       (unsigned long long)S->bss->k_flags_or);
	ring_buffer__free(RB);
	path_walk_bpf__destroy(S);
	return rc ? 1 : 0;
}
