// SPDX-License-Identifier: MIT
/*
 * p8-compat: file I/O and exec through the 32-bit (compat) syscall ABI,
 * so compat.bt can check what the capture hooks see (phase-0 probe P8).
 *
 * Built twice by run.py:
 *  - 64-bit (p8-compat64): one native read, then the same kind of work
 *    through "int $0x80", the i386 entry, from a 64-bit process. Needs no
 *    32-bit libraries. Pointers passed to int $0x80 are truncated to
 *    32 bits, so all its buffers live in a MAP_32BIT mapping.
 *  - 32-bit (p8-compat32, gcc -m32 -static): an i386 program whose libc
 *    syscalls enter through the vDSO (sysenter or syscall), a different
 *    compat entry stub. Needs gcc-multilib; run.py records a skip if absent.
 *
 * Every operation uses a distinct byte count, so a vfs_read/vfs_write
 * return value identifies the operation. The program prints one line per
 * operation with what the kernel returned:
 *
 *     OP <name> <abi> <syscall nr> <return value>
 *
 * and finally execs /bin/true (also through the compat ABI), so the probe
 * can check how a compat execve looks at raw_syscalls and sched_process_exec.
 *
 * Usage: p8-compatNN WORKDIR
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* i386 syscall numbers (arch/x86/entry/syscalls/syscall_32.tbl, v7.0) */
#define NR32_READ 3
#define NR32_WRITE 4
#define NR32_OPEN 5
#define NR32_CLOSE 6
#define NR32_EXECVE 11

#define SZ_NATIVE_READ 1111
#define SZ_COMPAT_READ 2222
#define SZ_COMPAT_WRITE 3333
#define SRC_SIZE 4096

#if defined(__x86_64__)
#define ABI "int80"
static long sys32(long nr, long a, long b, long c)
{
	long ret;

	/* The kernel clears r8-r11 on a 64-bit int $0x80, so declare them clobbered. */
	__asm__ volatile("int $0x80"
			 : "=a"(ret)
			 : "a"(nr), "b"(a), "c"(b), "d"(c)
			 : "memory", "r8", "r9", "r10", "r11");
	return ret;
}
#elif defined(__i386__)
#define ABI "i386"
#include <sys/syscall.h>
static long sys32(long nr, long a, long b, long c)
{
	return syscall(nr, a, b, c); /* libc: the vDSO entry, not int $0x80 */
}
#else
#error "x86 only"
#endif

/* 64 KiB below 4 GiB: everything handed to the compat ABI lives here. */
static char *low;

static char *low_str(size_t off, const char *s)
{
	return strcpy(low + off, s);
}

int main(int argc, char **argv)
{
	char path_src[512], path_dst[512];
	char *buf, *lsrc, *ldst;
	uint32_t *xargv, *xenvp;
	long fd, r;
	int nfd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s WORKDIR\n", argv[0]);
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	snprintf(path_src, sizeof(path_src), "%s/p8-src.dat", argv[1]);
	snprintf(path_dst, sizeof(path_dst), "%s/p8-dst.dat", argv[1]);

#if defined(__x86_64__)
	low = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
#else
	low = mmap(NULL, 1 << 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
	if (low == MAP_FAILED || (uintptr_t)low + (1 << 16) > 0xffffffffu) {
		perror("low mmap");
		return 1;
	}
	buf = low + 0x1000; /* 8 KiB of data buffer */

	/* The source file, written natively so its content is known. */
	memset(buf, 'p', SRC_SIZE);
	nfd = open(path_src, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (nfd < 0 || write(nfd, buf, SRC_SIZE) != SRC_SIZE || close(nfd) < 0) {
		perror("prepare source");
		return 1;
	}

	/* 1. Native read (64-bit build) or libc read (32-bit build). */
	nfd = open(path_src, O_RDONLY);
	r = read(nfd, buf, SZ_NATIVE_READ);
	printf("OP native_read %s %d %ld\n", sizeof(long) == 8 ? "x64" : "i386", sizeof(long) == 8 ? 0 : NR32_READ, r);
	close(nfd);

	/* 2. Compat open + read + close. */
	lsrc = low_str(0x100, path_src);
	fd = sys32(NR32_OPEN, (long)(uintptr_t)lsrc, O_RDONLY, 0);
	printf("OP compat_open %s %d %ld\n", ABI, NR32_OPEN, fd);
	r = sys32(NR32_READ, fd, (long)(uintptr_t)buf, SZ_COMPAT_READ);
	printf("OP compat_read %s %d %ld\n", ABI, NR32_READ, r);
	sys32(NR32_CLOSE, fd, 0, 0);

	/* 3. Compat open for writing + write + close. */
	ldst = low_str(0x400, path_dst);
	fd = sys32(NR32_OPEN, (long)(uintptr_t)ldst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	printf("OP compat_open_w %s %d %ld\n", ABI, NR32_OPEN, fd);
	r = sys32(NR32_WRITE, fd, (long)(uintptr_t)buf, SZ_COMPAT_WRITE);
	printf("OP compat_write %s %d %ld\n", ABI, NR32_WRITE, r);
	sys32(NR32_CLOSE, fd, 0, 0);

	/* 4. Compat execve of /bin/true: argv and envp are arrays of 32-bit pointers. */
	xargv = (uint32_t *)(low + 0x800);
	xenvp = xargv + 2;
	xargv[0] = (uint32_t)(uintptr_t)low_str(0x900, "true");
	xargv[1] = 0;
	xenvp[0] = 0;
	printf("OP compat_execve %s %d pending\n", ABI, NR32_EXECVE);
	r = sys32(NR32_EXECVE, (long)(uintptr_t)low_str(0xa00, "/bin/true"), (long)(uintptr_t)xargv,
		  (long)(uintptr_t)xenvp);
	printf("OP compat_execve_failed %s %d %ld\n", ABI, NR32_EXECVE, r);
	return 1;
}
