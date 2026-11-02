// SPDX-License-Identifier: MIT
/* Strict command-line configuration for p15d (ADR-0019 G1). See config.h. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

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
	{ "--queue-batches",       U32(queue_batches),  4,   1024,       64,   0 },
	{ "--batch-kb",            U32(batch_kb),       16,  4096,       256,  0 },
	{ "--test-drain-pause-ms", U32(drain_pause_ms), 0,   10000,      0,    0 },
};
#define NOPTS (sizeof(OPTS) / sizeof(OPTS[0]))

void p15_config_usage(FILE *f)
{
	fprintf(f, "usage: p15d --wal-dir DIR [--textfile PATH] [--no-rt]");
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
	for (size_t i = 0; i < NOPTS; i++)
		*(uint32_t *)((char *)c + OPTS[i].off) = OPTS[i].def;
	for (int a = 1; a < argc; a++) {
		const char *f = argv[a];
		size_t i;

		if (!strcmp(f, "--no-rt")) {
			c->realtime = 0;
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
	return 0;
}

size_t p15_config_meta(const struct p15_config *c, struct p15w_kv *kv, char (*vals)[24], size_t max)
{
	static const char *const keys[NOPTS] = {
		"config.duration_s", "config.stats_ms", "config.sync_ms", "config.rotate_mb", "config.rotate_s",
		"config.spine_ring_kb", "config.bulk_ring_kb", "config.queue_batches", "config.batch_kb",
		"config.test_drain_pause_ms",
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
	return n;
}
