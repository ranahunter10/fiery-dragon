// SPDX-License-Identifier: MIT
/* Unit tests for p15d's strict configuration parser (daemon/config.c, ADR-0019 G1). */
#include <string.h>

#include "config.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

static int parse(struct p15_config *c, char *err, int n, ...);

#include <stdarg.h>
static int parse(struct p15_config *c, char *err, int n, ...)
{
	char *argv[32] = { "p15d" };
	va_list ap;

	va_start(ap, n);
	for (int i = 0; i < n; i++)
		argv[i + 1] = va_arg(ap, char *);
	va_end(ap);
	err[0] = 0;
	return p15_config_parse(c, n + 1, argv, err, 200);
}

int main(void)
{
	struct p15_config c;
	char err[200];
	struct p15w_kv kv[16];
	char vals[16][24];
	size_t n;

	EXPECT(parse(&c, err, 0) != 0 && strstr(err, "--wal-dir"), "--wal-dir is required");
	EXPECT(parse(&c, err, 2, "--wal-dir", "/tmp/x") == 0, "minimal");
	EXPECT(c.stats_ms == 1000 && c.sync_ms == 1000 && c.rotate_mb == 64 && c.rotate_s == 60 &&
	       c.spine_ring_kb == 4096 && c.queue_batches == 64 && c.batch_kb == 256 && c.realtime == 1 &&
	       c.duration_s == 0 && !c.textfile && c.net == 1, "defaults (ADR-0006, ADR-0007, ADR-0017)");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--bogus") != 0 && strstr(err, "unknown"), "unknown flag refused");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--stats-ms", "99") != 0 && strstr(err, "out of range"), "below range");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--stats-ms", "60001") != 0, "above range");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--stats-ms", "1e3") != 0, "not an integer");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--stats-ms", "-5") != 0, "negative");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--stats-ms", "") != 0, "empty");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--stats-ms") != 0, "missing value");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--spine-ring-kb", "48") != 0 && strstr(err, "power of 2"), "ring not a power of 2");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--spine-ring-kb", "64") == 0 && c.spine_ring_kb == 64, "ring 64 KiB");
	EXPECT(parse(&c, err, 6, "--wal-dir", "/tmp/x", "--rotate-mb", "1", "--batch-kb", "2048") != 0, "batch larger than a segment");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--no-rt") == 0 && c.realtime == 0, "--no-rt");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--textfile") != 0, "--textfile needs a value");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--textfile", "/tmp/p.prom") == 0 && !strcmp(c.textfile, "/tmp/p.prom"), "--textfile");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--duration", "5") == 0 && c.duration_s == 5, "--duration");
	n = p15_config_meta(&c, kv, vals, 16);
	EXPECT(n == 12, "every setting echoed");
	EXPECT(!strcmp(kv[0].key, "config.duration_s") && !strcmp(kv[0].value, "5"), "echo carries the value");
	EXPECT(!strcmp(kv[n - 2].key, "config.realtime") && !strcmp(kv[n - 2].value, "yes"), "realtime echoed");
	EXPECT(!strcmp(kv[n - 1].key, "config.net") && !strcmp(kv[n - 1].value, "yes"), "net echoed");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--no-net") == 0 && c.net == 0, "--no-net");
	EXPECT(p15_config_meta(&c, kv, vals, 3) == 3, "bounded by the caller's array");
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
