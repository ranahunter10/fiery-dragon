// SPDX-License-Identifier: MIT
/*
 * The exit-code table (daemon/exitcodes.h, ADR-0019 G2.2): every code is
 * distinct, documented, and outside the values the runtime and the shell use
 * (1, 2, 126 and above). Run: make test-c
 */
#include <stdio.h>
#include <string.h>

#include "exitcodes.h"

static int failures;

#define EXPECT(cond, msg) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); failures++; } } while (0)

struct row {
	const char *name;
	int value;
	const char *doc;
};

static const struct row rows[] = {
#define P15_X_ROW(name, value, doc) { #name, value, doc },
	P15_EXIT_CODES(P15_X_ROW)
#undef P15_X_ROW
};

int main(void)
{
	size_t n = sizeof(rows) / sizeof(rows[0]);

	EXPECT(n == 10, "ten codes in the table");
	EXPECT(rows[0].value == 0 && !strcmp(rows[0].name, "OK"), "OK is 0 and first");
	for (size_t i = 0; i < n; i++) {
		char what[96];

		snprintf(what, sizeof(what), "%s: value %d in 0, 3..125", rows[i].name, rows[i].value);
		EXPECT(rows[i].value == 0 || (rows[i].value >= 3 && rows[i].value <= 125), what);
		snprintf(what, sizeof(what), "%s: documented", rows[i].name);
		EXPECT(strlen(rows[i].doc) >= 10, what);
		for (size_t j = 0; j < i; j++) {
			snprintf(what, sizeof(what), "%s and %s: distinct values", rows[i].name, rows[j].name);
			EXPECT(rows[i].value != rows[j].value, what);
		}
	}
	EXPECT(P15_EXIT_INVALID != P15_EXIT_OK && P15_EXIT_DEGRADED != P15_EXIT_OK, "run states map to codes");
	printf("%s: %d failures\n", __FILE__, failures);
	return failures != 0;
}
