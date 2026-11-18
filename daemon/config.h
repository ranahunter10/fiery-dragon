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

#include "p15_file.h"   /* P15_FILE_MAP_DEFAULT */

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
	int flow;                    /* --flow sets it: attach the ADR-0005 data-flow programs (needs files); default off until step 2b part 3 is complete */
	uint32_t file_map_entries;   /* --file-map-entries: open-file map size (decision 19.6, E-0142). Not given, it is 0
				      * after the parse, and p15d sets it from the host (p15_file_map_auto) before the load */
	uint32_t obj_map_entries;    /* --obj-map-entries: object map size */
	int test_no_path_fentry;     /* --test-no-path-fentry: TEST ONLY, leave the path fentry unattached */
	int test_flow_file_fail_first; /* --test-flow-file-fail-first: TEST ONLY (needs --flow), the first FILE record
					* of every file is lost as a full ring would lose it, so its retry is tested */
	uint32_t start_pause_ms;     /* --test-start-pause-ms: TEST ONLY, wait after the load-time self-tests,
				      * before the WAL opens (E-0161) */
	uint32_t drain_pause_ms;     /* --test-drain-pause-ms: TEST ONLY, sleep after each poll to force overflow */
	uint32_t stop_stall_s;       /* --stop-stall-s: the stop gives up when the writer makes no progress for this
				      * long (E-0162) */
	uint32_t writer_stall_ms;    /* --test-writer-stall-ms: TEST ONLY, the writer sleeps this long before the
				      * closing snapshot */
	uint32_t writer_batch_ms;    /* --test-writer-batch-ms: TEST ONLY, the writer sleeps this long after each
				      * batch, so the queue fills (E-0173) */
	uint32_t flow_stop_wait_ms;  /* --flow-stop-wait-ms: at the end, how long the flow programs' short calls get
				      * to return and be recorded before the open ones are counted (p15_flow.h) */
	uint32_t flow_cut_pause_ms;  /* --test-flow-cut-pause-ms: TEST ONLY, wait between the count of open calls
				      * and the detach, so a test can release one in that window */
	uint32_t barrier_fail;       /* --test-barrier-fail 1: TEST ONLY, the grace-period barrier reports failure */
	uint32_t open_end_mode;      /* --test-open-end-mode 1|2: TEST ONLY, what the open session does for the opens of */
	uint32_t open_end_tgid;      /* --test-open-end-tgid: ... this process (bpf/include/p15_file.h P15_TEST_OPEN_*) */
	uint32_t canary_s;           /* --canary-s: the canary's interval (ADR-0019 G4.4; canary.h); 0, the default until a
				      * matrix has run with it on, is off */
	uint32_t canary_blind;       /* --test-canary-blind MASK: TEST ONLY, these of the canary's records are never
				      * marked seen, as if their program had stopped (P15_CANARY_* bits) */
	uint32_t link_close;         /* --test-link-close N: TEST ONLY, after the start p15d closes the fd of its Nth link
				      * (1-based, the self-check's order), as something acting inside p15d would */
	uint32_t wal_space_low_mb;   /* --wal-space-low-mb: below this much free space the bulk ring is shed (space.h);
				      * 0, the default, is the smaller of 512 MiB and 10 % of the filesystem */
	uint32_t wal_space_reserve_mb; /* --wal-space-reserve-mb: below this the spine is shed too; 0: the smaller of
					* 64 MiB and 2 % (at least 4 MiB) */
	uint32_t wal_space_guard;    /* --wal-space-guard 0: off (every ring written until the disk refuses) */
	uint32_t poll_max_ms;        /* --poll-max-ms: the drain's longest poll timeout, 10..1000, default 200; 10 ms
				      * after a poll that took records, doubled after each empty one (ADR-0030) */
};

/* Fill c from argv. Returns 0, or -EINVAL with a one-line reason in err (exit USAGE/CONFIG). */
P15_MUST_CHECK int p15_config_parse(struct p15_config *c, int argc, char **argv, char *err, size_t errlen);

/* The effective configuration as WAL header metadata (keys config.*). Returns the count written (<= max). */
/* The open-file map's size when --file-map-entries is not given (decision 103; the design
 * review's F-04): P15_FILE_MAP_HEADROOM times the files open on the host now, never fewer than
 * P15_FILE_MAP_DEFAULT (the fixed size this replaces), never more than the option's maximum, and
 * never more than 1/P15_FILE_MAP_MEM_DIV of the host's memory at P15_FILE_MAP_ENTRY_BYTES an entry
 * (104 bytes measured for this key and value in a preallocated hash, E-0309). Below the floor the
 * memory limit does not apply. */
#define P15_FILE_MAP_HEADROOM 4u
#define P15_FILE_MAP_MEM_DIV 128u
#define P15_FILE_MAP_ENTRY_BYTES 104u
#define P15_FILE_MAP_MAX 4194304u
uint32_t p15_file_map_auto(uint64_t files_now, uint64_t mem_total_bytes);
size_t p15_config_meta(const struct p15_config *c, struct p15w_kv *kv, char (*vals)[24], size_t max);

void p15_config_usage(FILE *f);

#endif
