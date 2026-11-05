/* SPDX-License-Identifier: MIT */
/*
 * The daemon's exit codes: the only values p15d may exit with (ADR-0019 G2.2).
 *
 * One table, one meaning per code. The values follow sysexits(3) where one
 * fits, so a code means the same thing to systemd and to a person reading
 * `systemctl status`. Codes 1 and 2 are left to the C runtime and the shell.
 * Every code is covered by a test (daemon/tests/test_exitcodes.c checks the
 * table; the p15d tests provoke each code).
 *
 *   X(name, value, meaning)
 */
#ifndef P15_EXITCODES_H
#define P15_EXITCODES_H

#define P15_EXIT_CODES(X)                                                                         \
	X(OK,        0,  "orderly stop; the run is valid (RUNNING at the end)")                       \
	X(DEGRADED,  3,  "orderly stop; the run is DEGRADED (counted bulk loss or a canary miss)")    \
	X(INVALID,   4,  "orderly stop; the run is INVALID (spine loss, invariant broken, I/O error)")\
	X(USAGE,     64, "bad command line (EX_USAGE)")                                               \
	X(CONFIG,    78, "configuration rejected: unknown key, bad value, out of range (EX_CONFIG)")  \
	X(LOAD,      69, "BPF programs could not be opened, loaded or attached (EX_UNAVAILABLE)")     \
	X(SELFTEST,  65, "the load-time self-test failed (ADR-0003); the run did not start")          \
	X(IO,        74, "a WAL or output file could not be created, written or synced (EX_IOERR)")   \
	X(OSERR,     71, "a system resource failed: memory, threads, signals, timers (EX_OSERR)")     \
	X(INTERNAL,  70, "an internal consistency check failed; a bug (EX_SOFTWARE)")

enum p15_exit {
#define P15_X_ENUM(name, value, doc) P15_EXIT_##name = value,
	P15_EXIT_CODES(P15_X_ENUM)
#undef P15_X_ENUM
};

#endif
