// SPDX-License-Identifier: MIT
/* See canary.h. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "canary.h"
#include "p15_file.h"

#define CANARY_EXEC_FAILED 127

/* The canary process. Between fork and exec the child calls only async-signal-safe functions:
 * p15d has other threads. Its nonce is formatted before the fork. */
static pid_t real_spawn(struct p15_canary_state *c, int with_io)
{
	char nonce[32];
	pid_t pid;

	snprintf(nonce, sizeof(nonce), "%llu", (unsigned long long)c->n);
	pid = fork();
	if (pid)
		return pid;
	if (with_io) {
		int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

		if (fd >= 0 && write(fd, "c", 1) < 0)
			fd = -1;     /* a failed write shows as a missing FLOW: nothing to do here */
	}
	execl("/bin/true", "fd-canary", nonce, (char *)NULL);
	_exit(CANARY_EXEC_FAILED);   /* exit-ok: the canary child, exec failed */
}

static int real_reap(pid_t pid, int *exec_failed)
{
	int st = 0;
	pid_t r = waitpid(pid, &st, WNOHANG);

	if (r == 0)
		return 0;
	*exec_failed = r == pid && WIFEXITED(st) && WEXITSTATUS(st) == CANARY_EXEC_FAILED;
	return 1;                    /* reaped, or no longer ours to reap (r < 0) */
}

void p15_canary_init(struct p15_canary_state *c, struct p15_run *run, unsigned interval_s, unsigned want, unsigned blind,
		     uint64_t now_mono_ns)
{
	memset(c, 0, sizeof(*c));
	c->run = run;
	c->interval_ns = (uint64_t)interval_s * 1000000000ull;
	c->want = P15_CANARY_FORK | P15_CANARY_EXEC | P15_CANARY_EXIT | (want & (P15_CANARY_FILES | P15_CANARY_FLOW));
	c->blind = blind;
	c->next_ns = now_mono_ns + c->interval_ns;
}

void p15_canary_see(struct p15_canary_state *c, const struct p15_hdr *h)
{
	unsigned bit = 0;

	if (!c->pid)
		return;
	switch (h->type) {
	case P15_T_FORK: {
		const struct p15_fork *f = (const struct p15_fork *)h;

		if (h->len >= sizeof(*f) && f->child_tgid == (uint32_t)c->pid && f->child_tid == (uint32_t)c->pid)
			bit = P15_CANARY_FORK;
		break;
	}
	case P15_T_EXEC:
		if (h->tgid == (uint32_t)c->pid)
			bit = P15_CANARY_EXEC;
		break;
	case P15_T_EXIT:
		if (h->tgid == (uint32_t)c->pid)
			bit = P15_CANARY_EXIT;
		break;
	case P15_T_OPEN:
		if (h->tgid == (uint32_t)c->pid)
			bit = P15_CANARY_OPEN;
		break;
	case P15_T_FLOW:
		if (h->tgid == (uint32_t)c->pid)
			bit = P15_CANARY_FLOW;
		break;
	default:
		break;
	}
	c->seen |= bit & ~c->blind;
}

static const char *const KIND[] = { "", "records missing", "records late" };

/* Publish one failed canary to the writer (run.h's canary fields, under their sequence): it
 * writes the CANARY_MISS record. */
static void publish_bad(struct p15_canary_state *c, unsigned kind, uint64_t late_ns)
{
	struct p15_run *r = c->run;

	atomic_fetch_add(&r->canary_seq, 1);            /* odd: being written */
	atomic_store(&r->canary_bad_kind, kind);
	atomic_store(&r->canary_bad_n, c->n);
	atomic_store(&r->canary_bad_pid, (uint32_t)c->pid);
	atomic_store(&r->canary_bad_want, c->cur_want);
	atomic_store(&r->canary_bad_seen, c->seen & c->cur_want);
	atomic_store(&r->canary_bad_spawn_ns, c->spawn_boot_ns);
	atomic_store(&r->canary_bad_late_ms, (uint32_t)(late_ns / 1000000ull));
	atomic_fetch_add(kind == P15_CANARY_MISS_KIND_LATE ? &r->canary_late : &r->canary_missed, 1);
	atomic_fetch_add(&r->canary_seq, 1);            /* even: complete */
}

/* kind 0: everything seen in time. */
static void finish(struct p15_canary_state *c, unsigned kind, uint64_t late_ns)
{
	if (kind) {
		char msg[200];

		snprintf(msg, sizeof(msg), "canary %llu (pid %d): %s, mask 0x%x of 0x%x, %llu ms after its deadline "
			 "(1 FORK, 2 EXEC, 4 EXIT, 8 OPEN, 16 FLOW, 32 open session ran, 64 file free ran)",
			 (unsigned long long)c->n, (int)c->pid, KIND[kind],
			 kind == P15_CANARY_MISS_KIND_LATE ? c->cur_want : c->cur_want & ~c->seen, c->cur_want,
			 (unsigned long long)(late_ns / 1000000ull));
		fprintf(stderr, "p15d level=error code=canary_miss msg=\"%s\"\n", msg);
		p15_run_set_state(c->run, P15_RUN_DEGRADED, msg);
		publish_bad(c, kind, late_ns);
	}
	atomic_fetch_add(&c->run->canary_runs, 1);
	c->pid = 0;
}

static uint64_t ctr(struct p15_canary_state *c, unsigned slot)
{
	return atomic_load(&c->run->filec[slot]);
}

void p15_canary_tick(struct p15_canary_state *c, uint64_t now, int took)
{
	if (!c->interval_ns)
		return;
	if (c->pid) {
		int exec_failed = 0;

		if (!c->reaped && (c->reap ? c->reap : real_reap)(c->pid, &exec_failed)) {
			c->reaped = 1;
			if (exec_failed) {
				/* /bin/true could not be run: its EXEC cannot arrive, and that is not blindness */
				c->cur_want &= ~P15_CANARY_EXEC;
				atomic_fetch_add(&c->run->canary_exec_failed, 1);
			}
		}
		/* the two programs that write nothing for a clean open: did they run at all since the start */
		if (ctr(c, P15_FC_SESSION_ENTRY) != c->base_session)
			c->seen |= P15_CANARY_SESSION & ~c->blind;
		if (ctr(c, P15_FC_FREE_RUN) != c->base_free)
			c->seen |= P15_CANARY_FREE & ~c->blind;
		if (now - c->last_poll_ns > P15_CANARY_STALL_NS) {
			c->deadline_ns = now + P15_CANARY_DEADLINE_NS;   /* the guest stood still: start the second again */
			atomic_fetch_add(&c->run->canary_stalled, 1);
		}
		c->last_poll_ns = now;
		c->polls++;
		if (!c->all_seen_ns && (c->seen & c->cur_want) == c->cur_want)
			c->all_seen_ns = now;
		if (c->all_seen_ns && c->reaped)
			finish(c, c->all_seen_ns > c->deadline_ns ? P15_CANARY_MISS_KIND_LATE : 0,
			       c->all_seen_ns > c->deadline_ns ? c->all_seen_ns - c->deadline_ns : 0);
		else if (!c->all_seen_ns && now >= c->deadline_ns && c->polls >= P15_CANARY_POLLS && !took &&
			 (c->reaped || now >= c->deadline_ns + 10 * P15_CANARY_DEADLINE_NS))
			finish(c, P15_CANARY_MISS_KIND_RECORD, now - c->deadline_ns);   /* unreaped for 10 s more: judged anyway, so it cannot hang */
		return;
	}
	if (c->stopped || now < c->next_ns)
		return;
	c->next_ns = now + c->interval_ns;
	c->n++;
	c->cur_want = c->want;
	c->seen = 0;
	c->polls = 0;
	c->reaped = 0;
	c->all_seen_ns = 0;
	c->base_session = ctr(c, P15_FC_SESSION_ENTRY);
	c->base_free = ctr(c, P15_FC_FREE_RUN);
	c->spawn_boot_ns = p15_boot_ns();
	c->spawn_ns = now;
	c->deadline_ns = now + P15_CANARY_DEADLINE_NS;
	c->last_poll_ns = now;
	c->pid = (c->spawn ? c->spawn : real_spawn)(c, (c->want & (P15_CANARY_FILES | P15_CANARY_FLOW)) != 0);
	if (c->pid <= 0) {
		c->pid = 0;
		atomic_fetch_add(&c->run->canary_spawn_failed, 1);
		fprintf(stderr, "p15d level=warn code=canary_spawn msg=\"the canary could not be started: %s\"\n",
			strerror(errno));
	}
}

void p15_canary_stop(struct p15_canary_state *c)
{
	c->stopped = 1;
	if (c->pid) {
		atomic_fetch_add(&c->run->canary_unfinished, 1);
		c->pid = 0;
	}
}
