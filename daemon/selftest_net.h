/* SPDX-License-Identifier: MIT */
/*
 * Load-time self-test of the network-intent programs (ADR-0004 rule 6, ADR-0003). p15d itself
 * makes a loopback TCP bind/listen/connect/accept and a UDP connect; the NET records attributed
 * to its own tgid, and only those, must match exactly: endpoints, verdicts, and the accept's
 * peer_cookie equal to the listener's cookie.
 */
#ifndef P15_SELFTEST_NET_H
#define P15_SELFTEST_NET_H

#include <stdio.h>

#include "compiler.h"

/* Returns the number of failed checks, or -errno if the test could not be run. *consumed: every
 * record the test took from the ring, its own and anyone else's (the run's books count them). */
P15_MUST_CHECK int p15_selftest_net(int bulk_rb_fd, FILE *log, unsigned long long *consumed);

#endif
