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
	struct p15w_kv kv[32];
	char vals[32][24];
	size_t n;

	EXPECT(parse(&c, err, 0) != 0 && strstr(err, "--wal-dir"), "--wal-dir is required");
	EXPECT(parse(&c, err, 2, "--wal-dir", "/tmp/x") == 0, "minimal");
	EXPECT(c.stats_ms == 1000 && c.sync_ms == 1000 && c.rotate_mb == 64 && c.rotate_s == 60 &&
	       c.spine_ring_kb == 4096 && c.queue_batches == 16 && c.batch_kb == 1024 && c.realtime == 1 &&
	       c.duration_s == 0 && !c.textfile && c.net == 1 && c.poll_max_ms == 200, "defaults (ADR-0006, ADR-0007, ADR-0017)");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--poll-max-ms", "9") != 0 &&
	       parse(&c, err, 4, "--wal-dir", "/tmp/x", "--poll-max-ms", "1001") != 0 &&
	       parse(&c, err, 4, "--wal-dir", "/tmp/x", "--poll-max-ms", "200") == 0 && c.poll_max_ms == 200, "--poll-max-ms 10..1000");
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
	EXPECT(parse(&c, err, 2, "--wal-dir", "/tmp/x") == 0 && c.flow == 0, "flow off by default (ADR-0005)");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--flow") == 0 && c.flow == 1, "--flow turns data flow on");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--flow", "--no-files") != 0 && strstr(err, "--flow needs file identity"),
	       "--flow with --no-files refused");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--textfile") != 0, "--textfile needs a value");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--textfile", "/tmp/p.prom") == 0 && !strcmp(c.textfile, "/tmp/p.prom"), "--textfile");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--duration", "5") == 0 && c.duration_s == 5, "--duration");
	n = p15_config_meta(&c, kv, vals, 32);
	EXPECT(n == 26, "every setting echoed");
	EXPECT(!strcmp(kv[17].key, "config.flow_stop_wait_ms") && !strcmp(kv[17].value, "200") &&
	       !strcmp(kv[18].key, "config.test_flow_cut_pause_ms") && !strcmp(kv[18].value, "0") &&
	       !strcmp(kv[19].key, "config.test_barrier_fail") && !strcmp(kv[19].value, "0"),
	       "the end's wait and its two test switches echoed, with their defaults");
	EXPECT(!strcmp(kv[16].key, "config.poll_max_ms") && !strcmp(kv[16].value, "200"), "the poll maximum echoed, its default 200 (ADR-0030)");
	EXPECT(!strcmp(kv[0].key, "config.duration_s") && !strcmp(kv[0].value, "5"), "echo carries the value");
	EXPECT(!strcmp(kv[10].key, "config.file_map_entries") && !strcmp(kv[10].value, "65536") &&
	       !strcmp(kv[11].key, "config.obj_map_entries") && !strcmp(kv[11].value, "131072"),
	       "map sizes echoed with their defaults (decision 19.6)");
	EXPECT(!strcmp(kv[n - 6].key, "config.realtime") && !strcmp(kv[n - 6].value, "yes"), "realtime echoed");
	EXPECT(!strcmp(kv[n - 5].key, "config.net") && !strcmp(kv[n - 5].value, "yes"), "net echoed");
	EXPECT(!strcmp(kv[n - 4].key, "config.files") && !strcmp(kv[n - 4].value, "yes"), "files echoed");
	EXPECT(!strcmp(kv[n - 3].key, "config.flow") && !strcmp(kv[n - 3].value, "no"), "flow echoed, off by default (ADR-0005)");
	EXPECT(!strcmp(kv[n - 2].key, "config.test_no_path_fentry") && !strcmp(kv[n - 2].value, "no"), "test switch echoed");
	EXPECT(!strcmp(kv[n - 1].key, "config.test_flow_file_fail_first") && !strcmp(kv[n - 1].value, "no"),
	       "the lost-FILE test switch echoed, off by default");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--no-net") == 0 && c.net == 0, "--no-net");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--no-files") == 0 && c.files == 0 && c.net == 1, "--no-files");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--test-no-path-fentry") == 0 && c.test_no_path_fentry == 1,
	       "--test-no-path-fentry");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--flow", "--test-flow-file-fail-first") == 0 &&
	       c.test_flow_file_fail_first == 1, "--test-flow-file-fail-first with --flow");
	EXPECT(parse(&c, err, 3, "--wal-dir", "/tmp/x", "--test-flow-file-fail-first") != 0,
	       "--test-flow-file-fail-first without --flow refused");
	EXPECT(parse(&c, err, 4, "--wal-dir", "/tmp/x", "--obj-map-entries", "512") != 0, "object map below 1024 refused");
	EXPECT(p15_config_meta(&c, kv, vals, 3) == 3, "bounded by the caller's array");
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
