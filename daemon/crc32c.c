// SPDX-License-Identifier: MIT
/*
 * CRC32C (Castagnoli). Two implementations of one function:
 *  - the x86-64 SSE4.2 `crc32` instruction, 8 bytes per step, used when the CPU has it;
 *  - a table, one byte per step, for other CPUs, and as the reference the tests compare with.
 * The choice is made once, before main (a constructor), so no thread races to make it.
 * Why: p15d's profile on the VM gave the table version 32.6 % of p15d's samples while it captured
 * an open+close workload (E-0215): every WAL batch is checksummed twice (payload and header).
 */
#include "crc32c.h"

#include <string.h>

#if defined(__x86_64__)
#include <nmmintrin.h>
#endif

static uint32_t table[256];
static int use_hw;

__attribute__((constructor)) static void crc32c_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;

		for (int k = 0; k < 8; k++)
			c = (c >> 1) ^ (0x82F63B78u & (0u - (c & 1)));
		table[i] = c;
	}
#if defined(__x86_64__)
	__builtin_cpu_init();
	use_hw = __builtin_cpu_supports("sse4.2");
#endif
}

uint32_t p15_crc32c_table(uint32_t crc, const void *data, size_t n)
{
	const uint8_t *p = data;

	crc = ~crc;
	while (n--)
		crc = table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return ~crc;
}

#if defined(__x86_64__)
__attribute__((target("sse4.2"))) static uint32_t crc_hw(uint32_t crc, const uint8_t *p, size_t n)
{
	uint64_t c = ~crc;

	while (n && ((uintptr_t)p & 7)) {   /* to an 8-byte boundary */
		c = _mm_crc32_u8((uint32_t)c, *p++);
		n--;
	}
	while (n >= 8) {
		uint64_t v;

		memcpy(&v, p, 8);
		c = _mm_crc32_u64(c, v);
		p += 8;
		n -= 8;
	}
	while (n--)
		c = _mm_crc32_u8((uint32_t)c, *p++);
	return ~(uint32_t)c;
}
#endif

uint32_t p15_crc32c(uint32_t crc, const void *data, size_t n)
{
#if defined(__x86_64__)
	if (use_hw)
		return crc_hw(crc, data, n);
#endif
	return p15_crc32c_table(crc, data, n);
}

const char *p15_crc32c_impl(void)
{
	return use_hw ? "sse4.2" : "table";
}
