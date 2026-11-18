// SPDX-License-Identifier: MIT
/* The data-flow self-test (ADR-0005, ADR-0003). See selftest_flow.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "p15_flow.h"
#include "p15_records.h"
#include "records.h"
#include "selftest_flow.h"

#define MAXR 64
#define TRIES 3
#define N_FILE 4321        /* the write and the read of the new file */
#define N_VEC_A 40         /* the writev and the readv: two pieces */
#define N_VEC_B 37
#define N_PIPE 1234
#define N_SOCK 555
#define N_FLOWS 8          /* one FLOW per transfer above, and no other */

struct coll {
	unsigned char r[MAXR][P15_OPEN_MAX_SIZE];   /* the child's FLOW, FILE and file-identity records */
	int n, other, invalid, overflow;
	unsigned child;
	unsigned long long flow, file, net;         /* records taken from the ring, by books */
};

static struct coll c;   /* 270 KiB: not on the stack */

static int on_rec(void *ctx, void *data, size_t size)
{
	const struct p15_hdr *h = data;
	int flow = h->type == P15_T_FLOW || h->type == P15_T_FILE;
	const char *why;

	(void)ctx;
	if (flow)
		c.flow++;
	else if (p15_is_file_type(h->type))
		c.file++;
	else {
		c.net++;                    /* NET records of the shared ring: on the NET books */
		return 0;
	}
	if (p15_rec_check(data, size, &why)) {
		c.invalid++;
		return 0;
	}
	if (!c.child || h->tgid != c.child) {
		c.other++;                  /* someone else's transfers during the test: ignored */
		return 0;
	}
	if (c.n < MAXR)
		memcpy(c.r[c.n++], data, h->len);
	else
		c.overflow++;
	return 0;
}

static int check(FILE *log, int ok, const char *what)
{
	fprintf(log, "  %-4s flow: %s\n", ok ? "ok" : "FAIL", what);
	return !ok;
}

/* The transfers, in a child: p15d's own are excluded from capture. Returns 0, or the step that
 * did not move its whole count. */
static int child_io(const char *path)
{
	static char buf[N_FILE], back[N_FILE];
	struct iovec w[2], r[2];
	int fd, p[2], sv[2];

	memset(buf, 'f', sizeof(buf));
	prctl(PR_SET_NAME, "p15d-flowtest");
	fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		return 2;
	if (write(fd, buf, N_FILE) != N_FILE)
		return 3;
	if (lseek(fd, 0, SEEK_SET) != 0 || read(fd, back, N_FILE) != N_FILE)
		return 4;
	w[0] = (struct iovec){ buf, N_VEC_A };
	w[1] = (struct iovec){ buf, N_VEC_B };
	if (writev(fd, w, 2) != N_VEC_A + N_VEC_B)
		return 5;
	r[0] = (struct iovec){ back, N_VEC_A };
	r[1] = (struct iovec){ back + N_VEC_A, N_VEC_B };
	if (lseek(fd, N_FILE, SEEK_SET) != N_FILE || readv(fd, r, 2) != N_VEC_A + N_VEC_B)
		return 6;
	if (pipe2(p, O_CLOEXEC) || write(p[1], buf, N_PIPE) != N_PIPE || read(p[0], back, N_PIPE) != N_PIPE)
		return 7;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) || send(sv[0], buf, N_SOCK, 0) != N_SOCK ||
	    recv(sv[1], back, N_SOCK, MSG_WAITALL) != N_SOCK)
		return 8;
	return 0;
}

static const struct p15_flow *flow_rec(int i)
{
	const struct p15_hdr *h = (const void *)c.r[i];

	return h->type == P15_T_FLOW ? (const void *)h : NULL;
}

/* The only FLOW of kind and bytes (and VECTORED or not); NULL if none or several. */
static const struct p15_flow *one_flow(__u16 kind, __u64 bytes, int vectored, int *n)
{
	const struct p15_flow *hit = NULL;

	*n = 0;
	for (int i = 0; i < c.n; i++) {
		const struct p15_flow *r = flow_rec(i);

		if (r && r->kind == kind && r->bytes == bytes && !!(r->fflags & P15_FF_VECTORED) == vectored) {
			hit = r;
			(*n)++;
		}
	}
	return *n == 1 ? hit : NULL;
}

static int n_flows(void)
{
	int n = 0;

	for (int i = 0; i < c.n; i++)
		n += flow_rec(i) != NULL;
	return n;
}

static const struct p15_file *file_of(__u64 fid)
{
	for (int i = 0; i < c.n; i++) {
		const struct p15_file *r = (const void *)c.r[i];

		if (r->h.type == P15_T_FILE && r->fid == fid)
			return r;
	}
	return NULL;
}

/* The OPEN of path (the regular file is registered at its open, not at its first transfer). */
static const struct p15_open *open_of(const char *path)
{
	for (int i = 0; i < c.n; i++) {
		const struct p15_open *r = (const void *)c.r[i];
		const char *p = (const char *)(r + 1) + r->facts_len;

		if (r->h.type == P15_T_OPEN && r->path_len == strlen(path) && !memcmp(p, path, r->path_len))
			return r;
	}
	return NULL;
}

static int timed(const struct p15_flow *r)
{
	return r && r->first_ts && r->first_ts <= r->last_ts && r->count == 1 && !(r->fflags & P15_FF_START_UNKNOWN);
}

static void drain_ring(struct ring_buffer *rb, int ms)
{
	for (int i = 0; i < ms / 20; i++) {
		ring_buffer__poll(rb, 20);
		ring_buffer__consume(rb);   /* records don't wake the reader below the high-water mark (ADR-0020) */
		if (n_flows() >= N_FLOWS)
			break;
	}
	ring_buffer__consume(rb);
}

/* One try: run the child, collect its records, check them. Returns failed checks, or -errno. */
static int try_once(struct ring_buffer *rb, const char *path, int lost_first, FILE *log)
{
	const struct p15_flow *fw, *fr, *vw, *vr, *pw, *pr, *ss, *sr;
	const struct p15_open *op;
	int failed = 0, st = 0, k[8];
	pid_t pid;

	ring_buffer__consume(rb);           /* records from before the try: on the books, not examined */
	c.n = c.other = c.invalid = c.overflow = 0;
	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0)
		_exit(child_io(path));           /* exit-ok: self-test child */
	c.child = (unsigned)pid;
	if (waitpid(pid, &st, 0) != pid)
		return -errno;
	if (!WIFEXITED(st) || WEXITSTATUS(st)) {
		fprintf(log, "selftest flow: the child's step %d did not move its whole count\n",
			WIFEXITED(st) ? WEXITSTATUS(st) : -1);
		return -EIO;
	}
	drain_ring(rb, 2000);
	fprintf(log, "selftest flow: child %u: %d own records (%d FLOW), %d of other processes, %d invalid\n", c.child,
		c.n, n_flows(), c.other, c.invalid);
	failed += check(log, c.invalid == 0 && c.overflow == 0, "every record passes the checks");
	failed += check(log, n_flows() == N_FLOWS, "exactly one FLOW per transfer, eight in all");
	fw = one_flow(P15_FLOWK_WRITE, N_FILE, 0, &k[0]);
	fr = one_flow(P15_FLOWK_READ, N_FILE, 0, &k[1]);
	vw = one_flow(P15_FLOWK_WRITE, N_VEC_A + N_VEC_B, 1, &k[2]);
	vr = one_flow(P15_FLOWK_READ, N_VEC_A + N_VEC_B, 1, &k[3]);
	pw = one_flow(P15_FLOWK_WRITE, N_PIPE, 0, &k[4]);
	pr = one_flow(P15_FLOWK_READ, N_PIPE, 0, &k[5]);
	ss = one_flow(P15_FLOWK_SEND, N_SOCK, 0, &k[6]);
	sr = one_flow(P15_FLOWK_RECV, N_SOCK, 0, &k[7]);
	failed += check(log, fw && fr && timed(fw) && timed(fr),
			"the file's write and read: one FLOW each with its bytes, its start before its end");
	failed += check(log, vw && vr && timed(vw) && timed(vr) && vw->fid == fw->fid && vr->fid == fw->fid,
			"the writev and the readv: VECTORED, on the same open file");
	op = open_of(path);
	failed += check(log, op && fw && op->fid == fw->fid && fr && fr->fid == fw->fid,
			"the file's FLOWs name the open-file id of its OPEN");
	failed += check(log, pw && pr && timed(pw) && timed(pr) && pw->fid != pr->fid,
			"the pipe's write and read: one FLOW each, on its two ends");
	failed += check(log, ss && sr && ss->fid != sr->fid && ss->first_ts == ss->last_ts && sr->first_ts == sr->last_ts,
			"the socketpair's send and receive: SEND and RECV, one each, instants, on its two ends");
	if (lost_first) {
		fprintf(log, "  --   flow: FILE records not checked: --test-flow-file-fail-first plants their loss\n");
		return failed;
	}
	failed += check(log, pw && pr && file_of(pw->fid) && file_of(pr->fid) && file_of(pw->fid)->seen == P15_SEEN_IO &&
				     file_of(pr->fid)->seen == P15_SEEN_IO,
			"a FILE for each pipe end, first seen at I/O");
	failed += check(log, ss && sr && file_of(ss->fid) && file_of(sr->fid) && file_of(ss->fid)->seen == P15_SEEN_NET &&
				     file_of(sr->fid)->seen == P15_SEEN_NET,
			"a FILE for each socket, first seen on the network");
	failed += check(log, fw && !file_of(fw->fid), "no FILE for the regular file: its OPEN registered it");
	return failed;
}

int p15_selftest_flow(int bulk_rb_fd, int lost_first, FILE *log, unsigned long long *flow_consumed,
		      unsigned long long *file_consumed, unsigned long long *net_consumed)
{
	char dir[] = "/tmp/p15d-flowtest-XXXXXX", rdir[PATH_MAX], path[PATH_MAX + 16];
	struct ring_buffer *rb;
	int rc = 0, made = 0;

	memset(&c, 0, sizeof(c));
	rb = ring_buffer__new(bulk_rb_fd, on_rec, NULL, NULL);
	if (!rb)
		return -errno;
	if (!mkdtemp(dir) || !realpath(dir, rdir)) {
		rc = -errno;
		goto out;
	}
	made = 1;
	/* A FLOW can be missed when the kernel skips a program (counted in flow_missed); a busy host
	 * at start-up should not stop the daemon, so a failed try is repeated, up to TRIES. */
	for (int t = 0; t < TRIES; t++) {
		snprintf(path, sizeof(path), "%s/f-%d", rdir, t);
		rc = try_once(rb, path, lost_first, log);
		unlink(path);
		if (rc <= 0)
			break;
		fprintf(log, "selftest flow: try %d: %d checks failed%s\n", t, rc, t + 1 < TRIES ? "; again" : "");
	}
	drain_ring(rb, 200);                 /* the child's CLOSE records, written as its files were freed */
out:
	if (made)
		rmdir(dir);
	ring_buffer__free(rb);
	*flow_consumed = c.flow;
	*file_consumed = c.file;
	*net_consumed = c.net;
	return rc;
}
