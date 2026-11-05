// SPDX-License-Identifier: MIT
/*
 * p15w-inspect: check and summarise a P15W run directory or segment files (ADR-0007
 * "tools/wal-inspect"). Every segment is scanned with the reader's rules, every record is
 * checked with p15_rec_check, and the run's END record is reported.
 *
 *   p15w-inspect RUN_DIR | SEGMENT...      [-v: also print every record]
 * Exit 0 if every segment is valid to its end, every record passes, and an END is present;
 * 1 otherwise; 2 on bad usage.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "p15_records.h"
#include "records.h"
#include "wal.h"

static unsigned long long by_type[64], bad_records, ring_recs[P15W_NRINGS];
static int problems, have_end, verbose;
static struct p15_end last_end;
static char end_reason[300];

static unsigned char *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	unsigned char *b;
	long sz;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
		fclose(f);
		return NULL;
	}
	b = malloc(sz ? (size_t)sz : 1);
	if (b && fread(b, 1, (size_t)sz, f) != (size_t)sz) {
		free(b);
		b = NULL;
	}
	fclose(f);
	*n = (size_t)sz;
	return b;
}

static void records(const unsigned char *p, uint32_t len, unsigned ring)
{
	uint32_t off = 0;

	while (off + 32 <= len) {
		const struct p15_hdr *h = (const void *)(p + off);
		const char *why;
		char line[1700];

		if (h->len < 32 || off + h->len > len)
			break;
		if (p15_rec_check(h, h->len, &why)) {
			bad_records++;
			printf("  record at +%u: INVALID (%s)\n", off, why);
		} else {
			by_type[h->type < 64 ? h->type : 0]++;
			ring_recs[ring]++;
			if (h->type == P15_T_END) {
				const struct p15_end *e = (const void *)h;

				have_end = 1;
				last_end = *e;
				snprintf(end_reason, sizeof(end_reason), "%.*s", (int)e->reason_len,
					 (const char *)(e + 1));
			}
			if (verbose) {
				p15_rec_format(h, line, sizeof(line));
				printf("    [%u] %s\n", ring, line);
			}
		}
		off += h->len;
	}
}

static void segment(const char *path)
{
	size_t n;
	unsigned char *b = slurp(path, &n);
	struct p15w_scan s;
	char v[160];
	static const char *const keys[] = { "run.id", "kernel.release", "schema.hash", "hooks.manifest", "drain.sched" };

	if (!b) {
		printf("%s: cannot read\n", path);
		problems++;
		return;
	}
	if (p15w_scan_buf(b, n, &s)) {
		printf("%s: header invalid (%s)\n", path, s.stop);
		problems++;
		free(b);
		return;
	}
	printf("%s: segment %u, %zu bytes, %llu batches, %llu records%s%s\n", path, s.segment_index, n,
	       (unsigned long long)s.batches, (unsigned long long)s.records, s.stop ? ", STOP: " : ", valid to the end",
	       s.stop ? s.stop : "");
	if (s.stop)
		problems++;
	if (s.segment_index == 0)
		for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
			if (!p15w_header_get(b, n, keys[i], v, sizeof(v)))
				printf("  %s = %s\n", keys[i], v);
	for (uint64_t off = s.header_len; off + P15W_BATCH_HDR_LEN <= s.good_end;) {
		uint32_t plen, ring;

		memcpy(&plen, b + off + 12, 4);
		ring = (uint32_t)b[off + 4] | (uint32_t)b[off + 5] << 8;
		records(b + off + P15W_BATCH_HDR_LEN, plen, ring < P15W_NRINGS ? ring : 0);
		off += P15W_BATCH_HDR_LEN + plen;
	}
	free(b);
}

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

int main(int argc, char **argv)
{
	int first = 1;

	if (argc > 1 && !strcmp(argv[1], "-v")) {
		verbose = 1;
		first = 2;
	}
	if (argc <= first) {
		fprintf(stderr, "usage: p15w-inspect [-v] RUN_DIR | SEGMENT...\n");
		return 2;
	}
	for (int a = first; a < argc; a++) {
		struct stat st;

		if (!stat(argv[a], &st) && S_ISDIR(st.st_mode)) {
			DIR *dir = opendir(argv[a]);
			struct dirent *e;
			char *names[4096];
			int k = 0;

			while (dir && (e = readdir(dir)) && k < 4096)
				if (!strncmp(e->d_name, "seg-", 4))
					if (asprintf(&names[k], "%s/%s", argv[a], e->d_name) > 0)
						k++;
			if (dir)
				closedir(dir);
			qsort(names, (size_t)k, sizeof(names[0]), cmp);
			for (int i = 0; i < k; i++) {
				segment(names[i]);
				free(names[i]);
			}
		} else {
			segment(argv[a]);
		}
	}
	printf("records: spine %llu, bulk %llu, daemon %llu; invalid %llu\n", ring_recs[P15W_RING_SPINE],
	       ring_recs[P15W_RING_BULK], ring_recs[P15W_RING_DAEMON], bad_records);
	for (int t = 1; t < 64; t++)
		if (by_type[t])
			printf("  %-10s %llu\n", p15_type_name((unsigned)t), by_type[t]);
	if (have_end)
		printf("END: exit %u, state %u, invariant %u, signal %u, reason \"%s\"\n", last_end.exit_code,
		       last_end.run_state, last_end.invariant, last_end.signal, end_reason);
	else
		printf("END: none (the run did not stop in order, or the WAL is cut)\n");
	return problems || bad_records || !have_end ? 1 : 0;
}
