# P6 argv at exec: 2026-10-25T01:19:39+00:00

- kernel 7.0.0-38-generic; bpftrace v0.25.0; gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0; git 240b7df6fadc; 1000 trials per mode

| mode | trials | kernel copied all-'A' | ENTER = truth | EXEC = truth | missing / empty | usable |
|---|---:|---:|---:|---:|---|---|
| control | 1000 | 1000 | 1000 (100.0 %) | 1000 (100.0 %) | ENTER 0 / 0; EXEC 0 / 0 | yes |
| race | 1000 | 93 | 45 (4.5 %) | 1000 (100.0 %) | ENTER 0 / 0; EXEC 0 / 0 | yes |

ENTER = read from the caller's memory at syscall entry (raw_syscalls, id 59). EXEC = read from the new program's stack at sched_process_exec. Truth = what /bin/echo printed, i.e. what the kernel actually copied.
