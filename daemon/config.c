// SPDX-License-Identifier: MIT
/* Strict command-line configuration for p15d (ADR-0019 G1). See config.h. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "p15_records.h"

struct opt {
	const char *flag;
	size_t off;          /* offsetof the uint32_t field */
	uint32_t lo, hi, def;
	int pow2;
};

#define U32(f) offsetof(struct p15_config, f)
static const struct opt OPTS[] = {
	{ "--duration",            U32(duration_s),     0,   86400 * 30, 0,    0 },
	{ "--stats-ms",            U32(stats_ms),       100, 60000,      1000, 0 },
	{ "--sync-ms",             U32(sync_ms),        10,  60000,      1000, 0 },
	{ "--rotate-mb",           U32(rotate_mb),      1,   4096,       64,   0 },
	{ "--rotate-s",            U32(rotate_s),       1,   3600,       60,   0 },
	{ "--spine-ring-kb",       U32(spine_ring_kb),  4,   262144,     4096, 1 },
	{ "--bulk-ring-kb",        U32(bulk_ring_kb),   4,   262144,     4096, 1 },
	{ "--queue-batches",       U32(queue_batches),  4,   1024,       16,   0 },   /* STATE decision 46: 16 x 1 MiB, */
	{ "--batch-kb",            U32(batch_kb),       16,  4096,       1024, 0 },   /* the same 16 MiB (E-0220, E-0223) */
	{ "--test-drain-pause-ms", U32(drain_pause_ms), 0,   10000,      0,    0 },
	{ "--file-map-entries",    U32(file_map_entries), 1024, 4194304, 65536,  0 },
	{ "--obj-map-entries",     U32(obj_map_entries),  1024, 4194304, 131072, 0 },
	{ "--test-start-pause-ms", U32(start_pause_ms),   0,    10000,   0,      0 },
	{ "--stop-stall-s",        U32(stop_stall_s),     1,    3600,    30,     0 },
	{ "--test-writer-stall-ms", U32(writer_stall_ms), 0,    600000,  0,      0 },
	{ "--test-writer-batch-ms", U32(writer_batch_ms), 0,    10000,   0,      0 },
	{ "--poll-max-ms",         U32(poll_max_ms),      10,   1000,    200,    0 },   /* ADR-0030 */
	{ "--flow-stop-wait-ms",   U32(flow_stop_wait_ms), 0,   10000,   200,    0 },
	{ "--test-flow-cut-pause-ms", U32(flow_cut_pause_ms), 0, 10000,  0,      0 },
	{ "--test-barrier-fail",   U32(barrier_fail),     0,    1,       0,      0 },
};
#define NOPTS (sizeof(OPTS) / sizeof(OPTS[0]))

/* The smallest batch (--batch-kb's minimum above) must take the largest record of the schema: the
 * drain reads a ring only when its batch has that much room (p15_drain_room, E-0173). */
_Static_assert(16 * 1024 >= P15_RECORD_MAX_SIZE, "--batch-kb's minimum is smaller than the largest record");

void p15_config_usage(FILE *f)
{
	fprintf(f, "usage: p15d --wal-dir DIR [--textfile PATH] [--no-rt] [--no-net] [--no-files] [--flow] [--test-no-path-fentry] [--test-flow-file-fail-first]");
	for (size_t i = 0; i < NOPTS; i++)
		fprintf(f, " [%s N]", OPTS[i].flag);
	fprintf(f, "\n");
}

static int parse_u32(const char *s, uint32_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !*s || *s == '-' || *s == '+')
		return -1;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end || v > UINT32_MAX)
		return -1;
	*out = (uint32_t)v;
	return 0;
}

int p15_config_parse(struct p15_config *c, int argc, char **argv, char *err, size_t errlen)
{
	memset(c, 0, sizeof(*c));
	c->realtime = 1;
	c->net = 1;
	c->files = 1;
	for (size_t i = 0; i < NOPTS; i++)
		*(uint32_t *)((char *)c + OPTS[i].off) = OPTS[i].def;
	for (int a = 1; a < argc; a++) {
		const char *f = argv[a];
		size_t i;

		if (!strcmp(f, "--no-rt")) {
			c->realtime = 0;
			continue;
		}
		if (!strcmp(f, "--no-net")) {
			c->net = 0;
			continue;
		}
		if (!strcmp(f, "--no-files")) {
			c->files = 0;
			continue;
		}
		if (!strcmp(f, "--flow")) {
			c->flow = 1;
			continue;
		}
		if (!strcmp(f, "--test-no-path-fentry")) {
			c->test_no_path_fentry = 1;
			continue;
		}
		if (!strcmp(f, "--test-flow-file-fail-first")) {
			c->test_flow_file_fail_first = 1;
			continue;
		}
		if (!strcmp(f, "--wal-dir") || !strcmp(f, "--textfile")) {
			if (a + 1 >= argc || !argv[a + 1][0]) {
				snprintf(err, errlen, "%s needs a value", f);
				return -EINVAL;
			}
			if (!strcmp(f, "--wal-dir"))
				c->wal_root = argv[++a];
			else
				c->textfile = argv[++a];
			continue;
		}
		for (i = 0; i < NOPTS && strcmp(f, OPTS[i].flag); i++)
			;
		if (i == NOPTS) {
			snprintf(err, errlen, "unknown argument '%s'", f);
			return -EINVAL;
		}
		{
			uint32_t v;

			if (a + 1 >= argc || parse_u32(argv[a + 1], &v)) {
				snprintf(err, errlen, "%s needs a non-negative integer", f);
				return -EINVAL;
			}
			if (v < OPTS[i].lo || v > OPTS[i].hi || (OPTS[i].pow2 && (v & (v - 1)))) {
				snprintf(err, errlen, "%s %u out of range %u..%u%s", f, v, OPTS[i].lo, OPTS[i].hi,
					 OPTS[i].pow2 ? ", power of 2" : "");
				return -EINVAL;
			}
			*(uint32_t *)((char *)c + OPTS[i].off) = v;
			a++;
		}
	}
	if (!c->wal_root) {
		snprintf(err, errlen, "--wal-dir is required");
		return -EINVAL;
	}
	if ((uint64_t)c->batch_kb * 1024 > (uint64_t)c->rotate_mb * 1024 * 1024) {
		snprintf(err, errlen, "--batch-kb %u is larger than --rotate-mb %u", c->batch_kb, c->rotate_mb);
		return -EINVAL;
	}
	if (c->flow && !c->files) {
		snprintf(err, errlen, "--flow needs file identity: do not pass --no-files with it (ADR-0005)");
		return -EINVAL;
	}
	if (c->test_flow_file_fail_first && !c->flow) {
		snprintf(err, errlen, "--test-flow-file-fail-first needs --flow");
		return -EINVAL;
	}
	return 0;
}

size_t p15_config_meta(const struct p15_config *c, struct p15w_kv *kv, char (*vals)[24], size_t max)
{
	static const char *const keys[NOPTS] = {
		"config.duration_s", "config.stats_ms", "config.sync_ms", "config.rotate_mb", "config.rotate_s",
		"config.spine_ring_kb", "config.bulk_ring_kb", "config.queue_batches", "config.batch_kb",
		"config.test_drain_pause_ms", "config.file_map_entries", "config.obj_map_entries",
		"config.test_start_pause_ms", "config.stop_stall_s", "config.test_writer_stall_ms",
		"config.test_writer_batch_ms", "config.poll_max_ms", "config.flow_stop_wait_ms",
		"config.test_flow_cut_pause_ms", "config.test_barrier_fail",
	};
	size_t n = 0;

	for (size_t i = 0; i < NOPTS && n < max; i++, n++) {
		snprintf(vals[n], 24, "%u", *(const uint32_t *)((const char *)c + OPTS[i].off));
		kv[n].key = keys[i];
		kv[n].value = vals[n];
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->realtime ? "yes" : "no");
		kv[n].key = "config.realtime";
		kv[n].value = vals[n];
		n++;
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->net ? "yes" : "no");
		kv[n].key = "config.net";
		kv[n].value = vals[n];
		n++;
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->files ? "yes" : "no");
		kv[n].key = "config.files";
		kv[n].value = vals[n];
		n++;
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->flow ? "yes" : "no");
		kv[n].key = "config.flow";
		kv[n].value = vals[n];
		n++;
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->test_no_path_fentry ? "yes" : "no");
		kv[n].key = "config.test_no_path_fentry";
		kv[n].value = vals[n];
		n++;
	}
	if (n < max) {
		snprintf(vals[n], 24, "%s", c->test_flow_file_fail_first ? "yes" : "no");
		kv[n].key = "config.test_flow_file_fail_first";
		kv[n].value = vals[n];
		n++;
	}
	return n;
}
