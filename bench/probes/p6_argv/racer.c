// SPDX-License-Identifier: MIT
/*
 * p6-racer: exec /bin/echo with an argument that another thread may be
 * rewriting at the same moment (phase-0 probe P6).
 *
 * Each trial forks a child. The child fills a 16-byte argument with 'A',
 * optionally starts a thread that keeps flipping its bytes between 'A' and
 * 'B', then calls execve("/bin/echo", {"echo", arg}). The kernel copies the
 * argument at some instant during execve; echo prints exactly what the
 * kernel copied. The parent reads that through a pipe and prints
 *
 *     TRUTH <child pid> <what echo printed> <echo's exit status>
 *
 * A tracer that reads the argument from user memory at syscall entry reads
 * it at a different instant, so with --race it can see something else.
 *
 * Usage: p6-racer TRIALS [--race]
 *
 * argv[0] is "echo" (4 bytes + NUL) on purpose: argv.bt reads argv[1] at
 * mm->arg_start + 5.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARGLEN 16

static char arg[ARGLEN + 1];
static atomic_int started;

static void *flip(void *unused)
{
	volatile char *v = arg;

	(void)unused;
	atomic_store(&started, 1);
	for (;;)
		for (int i = 0; i < ARGLEN; i++)
			v[i] = v[i] == 'A' ? 'B' : 'A';
	return NULL;
}

static void child(int race, int wfd)
{
	char *argv[] = { "echo", arg, NULL };
	char *envp[] = { NULL };
	pthread_t t;

	memset(arg, 'A', ARGLEN);
	arg[ARGLEN] = '\0';
	if (dup2(wfd, STDOUT_FILENO) < 0)
		_exit(120);
	if (race) {
		if (pthread_create(&t, NULL, flip, NULL))
			_exit(121);
		while (!atomic_load(&started))
			;
	}
	execve("/bin/echo", argv, envp);
	_exit(122);
}

int main(int argc, char **argv)
{
	int trials, race;

	if (argc < 2 || (trials = atoi(argv[1])) <= 0) {
		fprintf(stderr, "usage: %s TRIALS [--race]\n", argv[0]);
		return 2;
	}
	race = argc > 2 && strcmp(argv[2], "--race") == 0;
	setvbuf(stdout, NULL, _IOLBF, 0);

	for (int i = 0; i < trials; i++) {
		char buf[64];
		size_t len = 0;
		ssize_t n;
		int p[2], st;
		pid_t pid;

		if (pipe(p) < 0) {
			perror("pipe");
			return 1;
		}
		pid = fork();
		if (pid < 0) {
			perror("fork");
			return 1;
		}
		if (pid == 0) {
			close(p[0]);
			child(race, p[1]);
		}
		close(p[1]);
		while (len < sizeof(buf) - 1 && (n = read(p[0], buf + len, sizeof(buf) - 1 - len)) > 0)
			len += (size_t)n;
		close(p[0]);
		buf[len] = '\0';
		buf[strcspn(buf, "\n")] = '\0';
		if (waitpid(pid, &st, 0) < 0) {
			perror("waitpid");
			return 1;
		}
		printf("TRUTH %d %s %d\n", (int)pid, len ? buf : "-", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
	}
	return 0;
}
