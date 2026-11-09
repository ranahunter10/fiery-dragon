// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * sliceb_probe: the step 2a dry run (ADR-0015, STATE decision 19). Loads sliceb_probe.bpf.c,
 * makes known file operations from this process, and checks every record and counter against
 * what the operations did and what stat(2), statfs(2) and FS_IOC_GETVERSION report.
 *
 * Usage: sliceb_probe [--overlay] [--btrfs DIR]   (root)
 *   --overlay     also mount an overlay under the probe's directory and check BACKING
 *   --btrfs DIR   also open a file in DIR (on btrfs) and check the subvolume or SUBVOL_UNKNOWN
 * Works in a fresh directory under /var/tmp, removed at the end. Exit 0 only if every check passes.
 * Reads its counters with bpf() map lookups: the ADR-0026 rule (no map syscall once attached) is
 * for p15d, whose syscalls must not make the kernel skip other tasks' programs; here only the
 * probe's own events are counted, and it makes no file operation during a lookup.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/fs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sliceb_probe.h"
#include "sliceb_probe.skel.h"

#define DEPTH 22          /* directories of NAMELEN characters: a path longer than PATH_MAX */
#define NAMELEN 200
/* Read the iterator in pieces of this size, as p15d reads the process snapshot (bpf/include/p15_snap.h):
 * the kernel's iterator buffer is 32 KiB, and a row it cannot take is refused (counted) and shown
 * again after the next copy to the reader. 16 KiB + the largest row (sizeof(struct sbp_rec)) fits,
 * so no row is refused. A first CI run read 64 KiB at a time and saw one refusal. */
#define READ_CHUNK (16u << 10)

static struct sliceb_probe_bpf *skel;
static struct ring_buffer *rb;
static struct sbp_rec *recs;
static int nrec, caprec, nchecks, nfailed;

static int on_rec(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (nrec == caprec) {
		int ncap = caprec ? 2 * caprec : 64;
		struct sbp_rec *n = realloc(recs, (size_t)ncap * sizeof(*n));

		if (!n)
			return -ENOMEM;
		recs = n;
		caprec = ncap;
	}
	memset(&recs[nrec], 0, sizeof(recs[nrec]));
	memcpy(&recs[nrec], data, size < sizeof(recs[nrec]) ? size : sizeof(recs[nrec]));
	nrec++;
	return 0;
}

static void consume(void)
{
	if (ring_buffer__consume(rb) < 0)
		printf("  warn ring_buffer__consume failed: %s\n", strerror(errno));
}

__attribute__((format(printf, 2, 3))) static int check(int ok, const char *fmt, ...)
{
	va_list ap;

	printf("  %-4s ", ok ? "ok" : "FAIL");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	nchecks++;
	nfailed += !ok;
	return ok;
}

static void read_hits(uint64_t h[H_N])
{
	int fd = bpf_map__fd(skel->maps.hits);

	for (uint32_t k = 0; k < H_N; k++)
		if (bpf_map_lookup_elem(fd, &k, &h[k]))
			h[k] = UINT64_MAX;
}

static uint64_t delta(const uint64_t a[H_N], const uint64_t b[H_N], int k)
{
	return b[k] - a[k];
}

static int path_is(const struct sbp_rec *r, const char *p)
{
	size_t n = strlen(p);

	return r->path_len == n && !memcmp(r->path, p, n);
}

static const char *tname(int t)
{
	static const char *n[] = { "?", "OPEN", "VERDICT", "BACKING", "CLOSE", "FD" };

	return t > 0 && t <= SBP_FD ? n[t] : "?";
}

static void show(const struct sbp_rec *r)
{
	printf("    rec %-7s len=%-4u fflags=0x%03x tgid=%u fid=%llu obj=%llu obj2=%llu fd=%u verdict=%d err=%d "
	       "f_flags=0%o f_mode=0x%x dev=%u:%u ino=%llu gen=%u mode=0%o magic=0x%x nlink=%u subvol=%llu path=%.*s%s\n",
	       tname(r->type), r->len, r->fflags, r->tgid, (unsigned long long)r->fid, (unsigned long long)r->obj,
	       (unsigned long long)r->obj2, r->fd, r->verdict, r->path_err, r->f_flags, r->f_mode, r->facts.dev >> 20,
	       r->facts.dev & 0xfffff, (unsigned long long)r->facts.ino, r->facts.gen, r->facts.mode, r->facts.fs_magic,
	       r->facts.nlink, (unsigned long long)r->facts.subvol, r->path_len > 96 ? 96 : (int)r->path_len, r->path,
	       r->path_len > 96 ? "..." : "");
}

/* The n-th record (from 0) of type t from index `from` on whose path is p (NULL: any path). */
static const struct sbp_rec *find_path(int from, int t, const char *p, int n)
{
	for (int i = from; i < nrec; i++)
		if (recs[i].type == t && (!p || path_is(&recs[i], p)) && n-- == 0)
			return &recs[i];
	return NULL;
}

static const struct sbp_rec *find_fid(int from, int t, uint64_t fid)
{
	for (int i = from; i < nrec; i++)
		if (recs[i].type == t && recs[i].fid == fid)
			return &recs[i];
	return NULL;
}

static int dev_is(uint32_t kdev, dev_t d)
{
	return (kdev >> 20) == major(d) && (kdev & 0xfffff) == minor(d);
}

/* The facts against stat(2): ino, dev, mode, nlink. */
static void check_facts(const struct sbp_facts *f, const struct stat *st, const char *what)
{
	check(f->ino == st->st_ino && dev_is(f->dev, st->st_dev) && f->mode == st->st_mode && f->nlink == st->st_nlink,
	      "%s: facts match stat (ino %llu/%llu, dev %u:%u/%u:%u, mode 0%o/0%o, nlink %u/%llu)", what,
	      (unsigned long long)f->ino, (unsigned long long)st->st_ino, f->dev >> 20, f->dev & 0xfffff,
	      major(st->st_dev), minor(st->st_dev), f->mode, st->st_mode, f->nlink, (unsigned long long)st->st_nlink);
}

static int write_file(const char *p, const char *s)
{
	int fd = open(p, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0640);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, s, strlen(s));
	close(fd);
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

/* ---- the cases ---- */

static char base[] = "/var/tmp/p15-sbp-XXXXXX";
static char rbase[4096], f1[4200];
static int fd1 = -1;
static struct stat st1;
static struct sbp_rec t1_ro;   /* the O_RDONLY OPEN of f1, kept for the FD and PATH_MISSING cases */

static void case_open(void)
{
	uint64_t h0[H_N], h1[H_N];
	const struct sbp_rec *a, *b, *c;
	struct statfs sf;
	int mark = nrec, gen = 0, have_gen;

	printf("case open: create f1, close it, open it read-only and keep it open\n");
	read_hits(h0);
	if (!check(write_file(f1, "sliceb probe\n") == 0, "create f1"))
		return;
	fd1 = open(f1, O_RDONLY | O_CLOEXEC);
	if (!check(fd1 >= 0 && !fstat(fd1, &st1) && !fstatfs(fd1, &sf), "open f1 read-only"))
		return;
	have_gen = ioctl(fd1, FS_IOC_GETVERSION, &gen) == 0;
	consume();
	read_hits(h1);
	a = find_path(mark, SBP_OPEN, f1, 0);
	b = find_path(mark, SBP_OPEN, f1, 1);
	if (!check(a && b, "two OPEN records with f1's path"))
		return;
	t1_ro = *b;
	check(!(a->fflags & (SBP_F_PATH_MISSING | SBP_F_FULL_SIZE | SBP_F_TRUNCATED | SBP_F_PATH_ERROR)) &&
		      !(b->fflags & (SBP_F_PATH_MISSING | SBP_F_FULL_SIZE | SBP_F_TRUNCATED | SBP_F_PATH_ERROR)),
	      "both written by the fentry from a claimed slot, full path");
	check(a->len == SBP_FIXED + a->path_len, "OPEN has its exact size (%u = %u + %u)", a->len, SBP_FIXED, a->path_len);
	check(a->obj && a->obj == b->obj, "one object for both opens (obj %llu)", (unsigned long long)a->obj);
	check(a->fid && b->fid && a->fid != b->fid, "two open-file ids (%llu, %llu)", (unsigned long long)a->fid,
	      (unsigned long long)b->fid);
	check((a->fflags & SBP_F_OBJ_NEW) && !(b->fflags & SBP_F_OBJ_NEW), "OBJ_NEW on the first record only");
	check_facts(&b->facts, &st1, "f1");
	check(b->facts.fs_magic == (uint32_t)sf.f_type, "fs_magic 0x%x = statfs f_type 0x%x", b->facts.fs_magic,
	      (unsigned)sf.f_type);
	if (have_gen)
		check(b->facts.gen == (uint32_t)gen, "gen %u = FS_IOC_GETVERSION %u", b->facts.gen, (unsigned)gen);
	else
		printf("  info gen not checked: FS_IOC_GETVERSION failed (%s)\n", strerror(errno));
	check((a->f_flags & O_ACCMODE) == O_WRONLY && (b->f_flags & O_ACCMODE) == O_RDONLY,
	      "f_flags access modes (0%o, 0%o)", a->f_flags, b->f_flags);
	check(b->f_mode & SBP_FMODE_OPENED ? 0 : 1, "f_mode at security_file_open has no FMODE_OPENED yet (0x%x)",
	      b->f_mode);
	c = find_fid(mark, SBP_CLOSE, a->fid);
	check(c && !(c->fflags & SBP_F_NEVER_OPENED) && c->obj == a->obj, "CLOSE for the first open, opened");
	check(delta(h0, h1, H_FENTRY_RUNS) == 2 && delta(h0, h1, H_SESSION_ENTRY) == 2 &&
		      delta(h0, h1, H_SESSION_RETURN) == 2,
	      "fentry, session entry and return each ran twice (%llu, %llu, %llu)",
	      (unsigned long long)delta(h0, h1, H_FENTRY_RUNS), (unsigned long long)delta(h0, h1, H_SESSION_ENTRY),
	      (unsigned long long)delta(h0, h1, H_SESSION_RETURN));
	check(delta(h0, h1, H_COMMON) == 2 && delta(h0, h1, H_MISSING) == 0 && delta(h0, h1, H_VERDICT) == 0,
	      "the session return wrote nothing (common case twice)");
}

static void case_claim_fail(void)
{
	uint64_t h0[H_N], h1[H_N];
	const struct sbp_rec *r;
	int mark = nrec, fd;

	printf("case claim_fail: no scratch slot, so the full-size record\n");
	read_hits(h0);
	skel->bss->force_claim_fail = 1;
	fd = open(f1, O_RDONLY | O_CLOEXEC);
	skel->bss->force_claim_fail = 0;
	if (!check(fd >= 0, "open f1"))
		return;
	close(fd);
	consume();
	read_hits(h1);
	r = find_path(mark, SBP_OPEN, f1, 0);
	check(r && (r->fflags & SBP_F_FULL_SIZE) && r->len == sizeof(struct sbp_rec),
	      "OPEN written full size with its path (len %u)", r ? r->len : 0);
	check(delta(h0, h1, H_CLAIM_FAILED) == 1, "claim_failed counted once");
	check(r && find_fid(mark, SBP_CLOSE, r->fid), "its CLOSE");
}

static int dirs[DEPTH + 1];

static void case_deep(void)
{
	char name[NAMELEN + 1];
	const struct sbp_rec *r;
	int mark = nrec, fd, i, ok = 1;

	printf("case deep: a file %d directories of %d characters deep (path > PATH_MAX)\n", DEPTH, NAMELEN);
	memset(name, 'd', NAMELEN);
	name[NAMELEN] = 0;
	dirs[0] = open(rbase, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	for (i = 1; i <= DEPTH && ok; i++)
		ok = dirs[i - 1] >= 0 && !mkdirat(dirs[i - 1], name, 0700) &&
		     (dirs[i] = openat(dirs[i - 1], name, O_DIRECTORY | O_RDONLY | O_CLOEXEC)) >= 0;
	if (!check(ok, "build the directory chain"))
		return;
	fd = openat(dirs[DEPTH], "deep-file", O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	if (!check(fd >= 0, "create the deep file"))
		return;
	close(fd);
	consume();
	r = find_path(mark, SBP_OPEN, "deep-file", 0);
	check(r && (r->fflags & SBP_F_TRUNCATED) && !(r->fflags & SBP_F_PATH_ERROR),
	      "OPEN flagged TRUNCATED with the dentry name");
}

static void deep_cleanup(void)
{
	char name[NAMELEN + 1];

	memset(name, 'd', NAMELEN);
	name[NAMELEN] = 0;
	if (dirs[DEPTH] >= 0)
		unlinkat(dirs[DEPTH], "deep-file", 0);
	for (int i = DEPTH; i >= 1; i--) {
		if (dirs[i] >= 0)
			close(dirs[i]);
		if (dirs[i - 1] >= 0)
			unlinkat(dirs[i - 1], name, AT_REMOVEDIR);
	}
	if (dirs[0] >= 0)
		close(dirs[0]);
}

static void case_fifo(void)
{
	char fifo[4200];
	const struct sbp_rec *o, *c;
	int mark = nrec, fd;

	printf("case fifo: open O_WRONLY|O_NONBLOCK with no reader fails in ->open (ENXIO)\n");
	snprintf(fifo, sizeof(fifo), "%s/fifo", rbase);
	if (!check(!mkfifo(fifo, 0600), "mkfifo"))
		return;
	fd = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	check(fd < 0 && errno == ENXIO, "the open fails with ENXIO");
	if (fd >= 0)
		close(fd);
	consume();
	o = find_path(mark, SBP_OPEN, fifo, 0);
	c = o ? find_fid(mark, SBP_CLOSE, o->fid) : NULL;
	check(o != NULL, "OPEN written (security_file_open passed)");
	check(c && (c->fflags & SBP_F_NEVER_OPENED), "CLOSE flagged NEVER_OPENED");
	check(!find_path(mark, SBP_VERDICT, NULL, 0), "no OPEN_VERDICT (the LSM allowed it)");
	unlink(fifo);
}

static void case_fd_pass(void)
{
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo = { 0 };
	uint64_t h0[H_N], h1[H_N];
	struct bpf_link *link;
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int ifd, rows = 0, row1 = 0, std_ok = 1, anon = 0, anon_other = 0;
	uint64_t anon_obj = 0;

	printf("case fd_pass: iter/task_file over this process\n");
	linfo.task.pid = (uint32_t)getpid();
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	read_hits(h0);
	link = bpf_program__attach_iter(skel->progs.sbp_fd_iter, &opts);
	if (!check(link != NULL, "attach the iterator"))
		return;
	ifd = bpf_iter_create(bpf_link__fd(link));
	if (!check(ifd >= 0, "create the iterator")) {
		bpf_link__destroy(link);
		return;
	}
	for (;;) {
		ssize_t n;

		if (cap - len < READ_CHUNK) {
			char *nb = realloc(buf, cap + 4 * READ_CHUNK);

			if (!nb)
				break;
			buf = nb;
			cap += 4 * READ_CHUNK;
		}
		n = read(ifd, buf + len, READ_CHUNK);
		if (n <= 0) {
			check(n == 0, "read the iterator to its end (%s)", n < 0 ? strerror(errno) : "ok");
			break;
		}
		len += (size_t)n;
	}
	close(ifd);
	bpf_link__destroy(link);
	read_hits(h1);
	{
		int seen[3] = { 0, 0, 0 };

		for (size_t off = 0; off + SBP_FIXED <= len;) {
			struct sbp_rec r;

			memset(&r, 0, sizeof(r));
			memcpy(&r, buf + off, SBP_FIXED);
			if (r.len < SBP_FIXED || off + r.len > len) {
				check(0, "FD row at offset %zu frames (len %u)", off, r.len);
				break;
			}
			memcpy(&r, buf + off, r.len);
			off += r.len;
			rows++;
			show(&r);
			if (r.fd < 3)
				seen[r.fd] = 1;
			if (r.facts.fs_magic == ANON_INODE_MAGIC) {
				anon++;
				if (!anon_obj)
					anon_obj = r.obj;
				else if (r.obj != anon_obj)
					anon_other++;
			}
			if ((int)r.fd == fd1) {
				row1 = 1;
				check(path_is(&r, f1), "fd %d row has f1's path", fd1);
				check(r.fid == t1_ro.fid && r.obj == t1_ro.obj,
				      "fd %d row keeps the OPEN's ids (fid %llu, obj %llu)", fd1, (unsigned long long)r.fid,
				      (unsigned long long)r.obj);
				check_facts(&r.facts, &st1, "fd row");
			}
		}
		for (int fd = 0; fd < 3; fd++)
			if (fcntl(fd, F_GETFD) != -1 && !seen[fd])
				std_ok = 0;
	}
	free(buf);
	printf("  info anonymous-inode descriptors %d: %d share object %llu, %d have another (the kernel's shared "
	       "anon inode names no single file)\n", anon, anon - anon_other, (unsigned long long)anon_obj, anon_other);
	check(row1, "a row for fd %d", fd1);
	check(std_ok, "a row for every open standard stream");
	check((uint64_t)rows == delta(h0, h1, H_FD_ROWS) && delta(h0, h1, H_FD_WRITE_FAILED) == 0,
	      "rows read %d = rows written %llu, none refused", rows, (unsigned long long)delta(h0, h1, H_FD_ROWS));
	check(delta(h0, h1, H_FD_DUP) >= 1, "the already registered file counted as a duplicate (%llu)",
	      (unsigned long long)delta(h0, h1, H_FD_DUP));
}

static void case_inode_free(void)
{
	uint64_t h0[H_N], h1[H_N];
	char f2[4200];

	printf("case inode_free: create, close and unlink f2\n");
	snprintf(f2, sizeof(f2), "%s/f2", rbase);
	if (!check(write_file(f2, "x") == 0, "create f2"))
		return;
	consume();
	read_hits(h0);
	check(!unlink(f2), "unlink f2");
	read_hits(h1);
	check(delta(h0, h1, H_INODE_FREE_HIT) >= 1, "security_inode_free deleted its object entry (%llu)",
	      (unsigned long long)delta(h0, h1, H_INODE_FREE_HIT));
}

static void case_overlay(void)
{
	char lower[4200], upper[4200], work[4200], merged[4200], lx[4300], mx[4300], opts[17000];
	const struct sbp_rec *o, *k;
	struct stat stl;
	int mark, fd;
	char c;

	printf("case overlay: open a lower file through an overlay mount\n");
	snprintf(lower, sizeof(lower), "%s/lower", rbase);
	snprintf(upper, sizeof(upper), "%s/upper", rbase);
	snprintf(work, sizeof(work), "%s/work", rbase);
	snprintf(merged, sizeof(merged), "%s/merged", rbase);
	snprintf(lx, sizeof(lx), "%s/x", lower);
	snprintf(mx, sizeof(mx), "%s/x", merged);
	snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);
	if (!check(!mkdir(lower, 0700) && !mkdir(upper, 0700) && !mkdir(work, 0700) && !mkdir(merged, 0700) &&
			   !write_file(lx, "lower\n") && !stat(lx, &stl),
		   "overlay directories and lower/x"))
		return;
	if (mount("overlay", merged, "overlay", 0, opts)) {
		check(0, "mount the overlay (%s)", strerror(errno));
		goto rm;
	}
	check(1, "mount the overlay");
	mark = nrec;
	fd = open(mx, O_RDONLY | O_CLOEXEC);
	if (check(fd >= 0, "open merged/x") && read(fd, &c, 1) != 1)
		check(0, "read merged/x");
	consume();
	o = find_path(mark, SBP_OPEN, mx, 0);
	k = find_path(mark, SBP_BACKING, NULL, 0);
	check(o && o->facts.fs_magic == SBP_OVERLAY_MAGIC, "OPEN of merged/x on overlayfs");
	if (check(k != NULL, "a BACKING record")) {
		check(o && k->obj2 == o->obj, "BACKING names the overlay file's object (%llu)",
		      (unsigned long long)k->obj2);
		check(k->facts2.fs_magic == SBP_OVERLAY_MAGIC, "its overlay facts are overlayfs's");
		check_facts(&k->facts, &stl, "BACKING's real object vs lower/x");
		check(k->fid && (!o || k->fid != o->fid), "the backing file has its own open-file id");
	}
	if (fd >= 0)
		close(fd);
	consume();
	check(o && find_fid(mark, SBP_CLOSE, o->fid) && k && find_fid(mark, SBP_CLOSE, k->fid),
	      "CLOSE for the overlay file and the backing file");
	if (umount2(merged, 0))
		check(0, "umount the overlay (%s)", strerror(errno));
rm:
	unlink(lx);
	rmdir(lower);
	{
		char wd[4300];

		snprintf(wd, sizeof(wd), "%s/work", work);
		rmdir(wd);
	}
	rmdir(work);
	rmdir(upper);
	rmdir(merged);
}

static void case_btrfs(const char *dir)
{
	char p[4200];
	const struct sbp_rec *r;
	int mark = nrec, fd;

	printf("case btrfs: a file in %s; btrfs BTF at load: %s\n", dir, skel->bss->btrfs_btf ? "yes" : "unknown yet");
	snprintf(p, sizeof(p), "%s/p15-sbp-btrfs", dir);
	fd = open(p, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
	if (!check(fd >= 0, "create %s", p))
		return;
	consume();
	r = find_path(mark, SBP_OPEN, p, 0);
	if (check(r && r->facts.fs_magic == SBP_BTRFS_MAGIC, "OPEN on btrfs")) {
		if (skel->bss->btrfs_btf) {
#ifdef STATX_SUBVOL
			struct statx sx;

			if (check(!statx(fd, "", AT_EMPTY_PATH, STATX_SUBVOL, &sx) && (sx.stx_mask & STATX_SUBVOL),
				  "statx STATX_SUBVOL"))
				check(r->facts.subvol == sx.stx_subvol && !(r->fflags & SBP_F_SUBVOL_UNKNOWN),
				      "subvol %llu = stx_subvol %llu", (unsigned long long)r->facts.subvol,
				      (unsigned long long)sx.stx_subvol);
#else
			printf("  info subvol %llu read; not compared: these headers have no STATX_SUBVOL\n",
			       (unsigned long long)r->facts.subvol);
#endif
		} else {
			check(r->fflags & SBP_F_SUBVOL_UNKNOWN, "btrfs BTF absent at load: SUBVOL_UNKNOWN");
		}
	}
	close(fd);
	unlink(p);
}

static void case_path_missing(void)
{
	uint64_t h0[H_N], h1[H_N];
	const struct sbp_rec *r;
	int mark = nrec, fd;

	printf("case path_missing: the fentry detached, the session return writes the OPEN\n");
	bpf_link__destroy(skel->links.sbp_open_fentry);
	skel->links.sbp_open_fentry = NULL;
	read_hits(h0);
	fd = open(f1, O_RDONLY | O_CLOEXEC);
	if (!check(fd >= 0, "open f1"))
		return;
	close(fd);
	consume();
	read_hits(h1);
	r = NULL;
	for (int i = mark; i < nrec && !r; i++)
		if (recs[i].type == SBP_OPEN)
			r = &recs[i];
	if (!check(r != NULL, "an OPEN record"))
		return;
	check((r->fflags & SBP_F_PATH_MISSING) && r->path_len == 0 && r->len == SBP_FIXED,
	      "flagged PATH_MISSING, no path, fixed size");
	check(r->obj == t1_ro.obj && !(r->fflags & SBP_F_OBJ_NEW), "the known object, without its facts again");
	check(r->fid && r->fid != t1_ro.fid && r->verdict == 0, "a new open-file id, verdict 0");
	check(delta(h0, h1, H_MISSING) == 1 && delta(h0, h1, H_FENTRY_RUNS) == 0, "missing counted once, no fentry run");
	check(find_fid(mark, SBP_CLOSE, r->fid) != NULL, "its CLOSE");
}

static void books(void)
{
	static const struct {
		int k;
		const char *name;
	} zero[] = {
		{ H_NOCOOKIE, "nocookie" },         { H_RET_NO_ENTRY, "ret_no_entry" },
		{ H_RESERVE_FAILED, "reserve_failed" }, { H_OUTPUT_FAILED, "output_failed" },
		{ H_PATH_ERROR, "path_error" },     { H_FILE_MAP_FULL, "file_map_full" },
		{ H_OBJ_MAP_FULL, "obj_map_full" }, { H_FILE_STALE, "file_stale" },
		{ H_OBJ_STALE, "obj_stale" },       { H_FACTS_DUP, "facts_dup" },
		{ H_CLOSE_LOST, "close_lost" },     { H_FD_WRITE_FAILED, "fd_write_failed" },
	};
	uint64_t h[H_N];
	int opens = 0, backings = 0, closes = 0;
	struct bpf_program *p;

	printf("books\n");
	read_hits(h);
	for (size_t i = 0; i < sizeof(zero) / sizeof(zero[0]); i++)
		check(h[zero[i].k] == 0, "%s = %llu", zero[i].name, (unsigned long long)h[zero[i].k]);
	check(h[H_SESSION_ENTRY] == h[H_SESSION_RETURN], "session entries %llu = returns %llu",
	      (unsigned long long)h[H_SESSION_ENTRY], (unsigned long long)h[H_SESSION_RETURN]);
	for (int i = 0; i < nrec; i++) {
		opens += recs[i].type == SBP_OPEN;
		backings += recs[i].type == SBP_BACKING;
		closes += recs[i].type == SBP_CLOSE;
	}
	check((uint64_t)opens == h[H_OPEN_EMITTED] + h[H_MISSING], "OPEN records %d = emitted %llu + missing %llu",
	      opens, (unsigned long long)h[H_OPEN_EMITTED], (unsigned long long)h[H_MISSING]);
	check((uint64_t)backings == h[H_BACKING_EMITTED], "BACKING records %d = emitted %llu", backings,
	      (unsigned long long)h[H_BACKING_EMITTED]);
	check((uint64_t)closes == h[H_CLOSE], "CLOSE records %d = written %llu", closes, (unsigned long long)h[H_CLOSE]);
	printf("  info session entry first %llu, fentry first %llu, file races %llu, obj races %llu, "
	       "unregistered frees (system-wide) %llu, inode frees hit %llu\n",
	       (unsigned long long)h[H_SESSION_FIRST], (unsigned long long)h[H_FENTRY_FIRST],
	       (unsigned long long)h[H_FILE_RACE], (unsigned long long)h[H_OBJ_RACE],
	       (unsigned long long)h[H_FREE_UNREGISTERED], (unsigned long long)h[H_INODE_FREE_HIT]);
	bpf_object__for_each_program(p, skel->obj) {
		struct bpf_prog_info info;
		uint32_t il = sizeof(info);

		memset(&info, 0, sizeof(info));
		if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &il))
			check(0, "%s: prog info (%s)", bpf_program__name(p), strerror(errno));
		else
			check(info.recursion_misses == 0, "%s: recursion_misses %llu", bpf_program__name(p),
			      (unsigned long long)info.recursion_misses);
	}
}

int main(int argc, char **argv)
{
	const char *btrfs = NULL;
	int overlay = 0, err;
	struct utsname u;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--overlay"))
			overlay = 1;
		else if (!strcmp(argv[i], "--btrfs") && i + 1 < argc)
			btrfs = argv[++i];
		else {
			fprintf(stderr, "usage: %s [--overlay] [--btrfs DIR]\n", argv[0]);
			return 2;
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (int i = 0; i <= DEPTH; i++)
		dirs[i] = -1;
	uname(&u);
	printf("sliceb_probe v1 kernel %s overlay %d btrfs %s\n", u.release, overlay, btrfs ? btrfs : "-");
	skel = sliceb_probe_bpf__open();
	if (!skel) {
		printf("FAIL open: %s\n", strerror(errno));
		return 1;
	}
	skel->rodata->harness_tgid = (uint32_t)getpid();
	bpf_program__set_autoattach(skel->progs.sbp_fd_iter, false);
	err = sliceb_probe_bpf__load(skel);
	if (!check(!err, "load (verifier accepted every program)"))
		goto out;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ring), on_rec, NULL, NULL);
	if (!check(rb != NULL, "ring buffer"))
		goto out;
	err = sliceb_probe_bpf__attach(skel);
	if (!check(!err, "attach fentry, kprobe.session and the two kprobe.multi frees (%s)", strerror(-err)))
		goto out;
	if (!check(mkdtemp(base) && realpath(base, rbase), "work directory under /var/tmp"))
		goto out;
	snprintf(f1, sizeof(f1), "%s/f1", rbase);

	case_open();
	case_claim_fail();
	case_deep();
	case_fifo();
	case_fd_pass();
	case_inode_free();
	if (overlay)
		case_overlay();
	if (btrfs)
		case_btrfs(btrfs);
	case_path_missing();
	consume();
	printf("records\n");
	for (int i = 0; i < nrec; i++)
		show(&recs[i]);
	books();

	if (fd1 >= 0)
		close(fd1);
	unlink(f1);
	deep_cleanup();
	rmdir(rbase);
out:
	ring_buffer__free(rb);
	sliceb_probe_bpf__destroy(skel);
	free(recs);
	printf("sliceb_probe: %d checks, %d failed\n", nchecks, nfailed);
	return nfailed || !nchecks ? 1 : 0;
}
