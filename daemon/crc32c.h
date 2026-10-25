/* SPDX-License-Identifier: MIT */
/* CRC32C (Castagnoli, CRC-32/ISCSI): the checksum of WAL batches (docs/formats/p15w-v1.md). */
#ifndef P15_CRC32C_H
#define P15_CRC32C_H

#include <stddef.h>
#include <stdint.h>

/*
 * Continue a CRC32C over `n` bytes. Start with crc = 0; the result of one call
 * can be passed to the next to checksum data in pieces.
 * p15_crc32c(0, "123456789", 9) == 0xE3069283.
 */
uint32_t p15_crc32c(uint32_t crc, const void *data, size_t n);

#endif
