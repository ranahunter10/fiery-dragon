/* SPDX-License-Identifier: MIT */
/* Checking and printing records (ADR-0008 rule 5: never read past len). */
#ifndef P15_DAEMON_RECORDS_H
#define P15_DAEMON_RECORDS_H

#include <stddef.h>
#include <linux/types.h>
#include "p15_records.h"
#include "compiler.h"

/*
 * Check that `size` bytes at `data` hold one well-formed record of a known
 * type and version: header present, len <= size, len a multiple of 8,
 * len == the fixed size for a fixed-size type; for EXEC and END, every variable field
 * inside len, len exactly the fields' padded size (EXEC: unless READ_FAILED) and every
 * byte after the fields zero.
 * Returns 0, or -EINVAL with *why set to a static reason.
 */
P15_MUST_CHECK int p15_rec_check(const void *data, size_t size, const char **why);

/* "FORK", "EXEC", ..., or "?" for a type this build does not know. */
const char *p15_type_name(__u16 type);

/* One line of text for a checked record. Returns the length written (snprintf rules). */
int p15_rec_format(const void *data, char *buf, size_t n);

/* Pointer to a variable-length field's bytes and its length (EXEC only for now). */
const __u8 *p15_exec_filename(const struct p15_exec *r, __u16 *len);
const __u8 *p15_exec_argv(const struct p15_exec *r, __u16 *len);

#endif
