// SPDX-License-Identifier: MIT
/*
 * Table-driven CRC32C, one byte per step. Simple and portable; at the WAL's
 * disk budget (about 21 MB/s, ADR-0007) its cost is small. A faster version
 * (SSE4.2 crc32 instruction, slicing) waits for a measurement that asks for it.
 */
#include "crc32c.h"

static uint32_t table[256];
static int table_ready;

static void build_table(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;

		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0x82F63B78u & (0u - (c & 1)));
		table[i] = c;
	}
	table_ready = 1;
}

uint32_t p15_crc32c(uint32_t crc, const void *data, size_t n)
{
	const uint8_t *p = data;

	if (!table_ready)
		build_table();
	crc = ~crc;
	while (n--)
		crc = table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return ~crc;
}
