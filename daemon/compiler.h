/* SPDX-License-Identifier: MIT */
/*
 * Compiler attributes shared by the daemon (ADR-0019 G2).
 *
 * P15_MUST_CHECK marks every fallible function: it returns 0 or -errno, and a
 * caller that ignores the result gets a warning, which -Werror turns into a
 * build failure. Note that GCC does not accept a (void) cast as "checked":
 * the result must really be used.
 */
#ifndef P15_COMPILER_H
#define P15_COMPILER_H

#define P15_MUST_CHECK __attribute__((warn_unused_result))

#endif
