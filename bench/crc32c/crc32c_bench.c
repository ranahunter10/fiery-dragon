// SPDX-License-Identifier: MIT
/*
 * What p15d's CRC32C costs per byte, by implementation (E-0215: the table version was a third of
 * p15d's samples). Checksums batches of SIZE bytes, ROUNDS times each way, and prints the median
 * ns per byte of each, with the speed-up. Both must give the same CRC, or it exits 1.
 *
 *     build/crc32c_bench [SIZE] [ROUNDS]          (defaults 4096 and 9; about 64 MiB per round)
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "crc32c.h"

static double now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e9 + t.tv_nsec;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	size_t size = argc > 1 ? strtoul(argv[1], NULL, 10) : 4096;
	int rounds = argc > 2 ? atoi(argv[2]) : 9;
	size_t reps, total;
	unsigned char *buf;
	double t_tab[64], t_cpu[64];
	uint32_t c_tab = 0, c_cpu = 0, x = 0x9E3779B9u;

	if (size < 8 || size > (1u << 24) || rounds < 1 || rounds > 64) {
		fprintf(stderr, "usage: crc32c_bench [SIZE 8..16777216] [ROUNDS 1..64]\n");
		return 2;
	}
	reps = (64u << 20) / size;
	total = reps * size;
	if (!(buf = malloc(size)))
		return 2;
	for (size_t i = 0; i < size; i++) {
		x ^= x << 13, x ^= x >> 17, x ^= x << 5;
		buf[i] = (unsigned char)x;
	}
	for (int r = 0; r < rounds; r++) {
		double t0 = now_ns();

		for (size_t i = 0; i < reps; i++)
			c_tab = p15_crc32c_table(c_tab, buf, size);
		double t1 = now_ns();

		for (size_t i = 0; i < reps; i++)
			c_cpu = p15_crc32c(c_cpu, buf, size);
		double t2 = now_ns();

		t_tab[r] = (t1 - t0) / total;
		t_cpu[r] = (t2 - t1) / total;
	}
	qsort(t_tab, rounds, sizeof(double), cmp);
	qsort(t_cpu, rounds, sizeof(double), cmp);
	printf("crc32c size=%zu rounds=%d bytes_per_round=%zu impl=%s\n", size, rounds, total, p15_crc32c_impl());
	printf("table   %.4f ns per byte (median; %.4f to %.4f)\n", t_tab[rounds / 2], t_tab[0], t_tab[rounds - 1]);
	printf("%-7s %.4f ns per byte (median; %.4f to %.4f)\n", p15_crc32c_impl(), t_cpu[rounds / 2], t_cpu[0],
	       t_cpu[rounds - 1]);
	printf("speed-up %.1fx; same crc: %s\n", t_tab[rounds / 2] / t_cpu[rounds / 2], c_tab == c_cpu ? "yes" : "NO");
	free(buf);
	return c_tab == c_cpu ? 0 : 1;
}
