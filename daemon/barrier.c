// SPDX-License-Identifier: MIT
/* See barrier.h. */
#include <errno.h>
#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "barrier.h"

int p15_barrier(int test_fail)
{
	if (test_fail)
		return -ENOSYS;
	if (syscall(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0))
		return -errno;
	return 0;
}
