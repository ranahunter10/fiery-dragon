/* SPDX-License-Identifier: MIT */
/*
 * p15d's configuration: command-line flags only, parsed strictly (ADR-0019 G1). An unknown
 * flag, a missing value or an out-of-range value is refused; the effective configuration is
 * echoed into every WAL segment header (p15_config_meta).
 */
#ifndef P15_CONFIG_H
#define P15_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "compiler.h"
#include "wal.h"

struct p15_config {
	const char *wal_root;        /* --wal-dir DIR: the run directory is created under it (required) */
	const char *textfile;        /* --textfile PATH: Prometheus text file, rewritten every stats interval */
	uint32_t duration_s;         /* --duration S: stop after S seconds; 0 = until SIGTERM/SIGINT */
	uint32_t stats_ms;           /* --stats-ms: STATS interval, 100..60000 */
	uint32_t sync_ms;            /* --sync-ms: fdatasync interval, 10..60000 (ADR-0007 rule 6) */
	uint32_t rotate_mb;          /* --rotate-mb: segment size, 1..4096 (ADR-0007 rule 1) */
	uint32_t rotate_s;           /* --rotate-s: segment age, 1..3600 */
	uint32_t spine_ring_kb;      /* --spine-ring-kb: power of 2, 4..262144 (ADR-0006, ADR-0017 layer 5) */
	uint32_t bulk_ring_kb;       /* --bulk-ring-kb: power of 2, 4..262144 (ADR-0004 rule 4) */
	uint32_t queue_batches;      /* --queue-batches: 4..1024 (ADR-0017 layer 2) */
	uint32_t batch_kb;           /* --batch-kb: 16..4096 */
	int realtime;                /* --no-rt clears it: the drain asks for SCHED_FIFO 1 (ADR-0017 layer 3) */
	int net;                     /* --no-net clears it: load the ADR-0004 network-intent programs */
	int files;                   /* --no-files clears it: load the ADR-0015 file-identity programs */
	uint32_t file_map_entries;   /* --file-map-entries: open-file map size (decision 19.6, E-0142) */
	uint32_t obj_map_entries;    /* --obj-map-entries: object map size */
	int test_no_path_fentry;     /* --test-no-path-fentry: TEST ONLY, leave the path fentry unattached */
	uint32_t start_pause_ms;     /* --test-start-pause-ms: TEST ONLY, wait after the load-time self-tests,
				      * before the WAL opens (E-0161) */
	uint32_t drain_pause_ms;     /* --test-drain-pause-ms: TEST ONLY, sleep after each poll to force overflow */
	uint32_t stop_stall_s;       /* --stop-stall-s: the stop gives up when the writer makes no progress for this
				      * long (E-0162) */
	uint32_t writer_stall_ms;    /* --test-writer-stall-ms: TEST ONLY, the writer sleeps this long before the
				      * closing snapshot */
	uint32_t writer_batch_ms;    /* --test-writer-batch-ms: TEST ONLY, the writer sleeps this long after each
				      * batch, so the queue fills (E-0173) */
};

/* Fill c from argv. Returns 0, or -EINVAL with a one-line reason in err (exit USAGE/CONFIG). */
P15_MUST_CHECK int p15_config_parse(struct p15_config *c, int argc, char **argv, char *err, size_t errlen);

/* The effective configuration as WAL header metadata (keys config.*). Returns the count written (<= max). */
size_t p15_config_meta(const struct p15_config *c, struct p15w_kv *kv, char (*vals)[24], size_t max);

void p15_config_usage(FILE *f);

#endif
