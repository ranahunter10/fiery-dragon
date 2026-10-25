# P8 compat ABI: 2026-10-25T01:20:06+00:00

- kernel 7.0.0-38-generic; bpftrace v0.25.0; gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0; git 240b7df6fadc; IA32 config: CONFIG_IA32_EMULATION=y, # CONFIG_IA32_EMULATION_DEFAULT_DISABLED is not set

**Variant 32-bit SKIPPED:** build failed (/usr/include/features-time64.h:20:10: fatal error: bits/wordsize.h: No such file or directory); full output in build-32.log

## Variant 64-bit (int $0x80 from a 64-bit process)

| operation | record | fields required | seen |
|---|---|---|---:|
| native_read | SYS | id=0, compat=0 | 2 |
| native_read | VFS_READ | ret=1111, compat=0 | 1 |
| compat_open | SYS | id=5, compat=1 | **0** |
| compat_open | OPEN | ret=0, compat=1, name=p8-src.dat | **0** |
| compat_read | SYS | id=3, compat=1 | **0** |
| compat_read | VFS_READ | ret=2222, compat=1 | **0** |
| compat_open_w | SYS | id=5, compat=1 | **0** |
| compat_open_w | OPEN | ret=0, compat=1, name=p8-dst.dat | **0** |
| compat_write | SYS | id=4, compat=1 | **0** |
| compat_write | VFS_WRITE | ret=3333, compat=1 | **0** |
| compat_execve | SYS | id=11, compat=1 | **0** |
| compat_execve | EXEC | name=/bin/true | 1 |

- program results: {'native_read': '1111', 'compat_open': '3', 'compat_read': '2222', 'compat_open_w': '3', 'compat_write': '3333', 'compat_execve': 'pending'}
- syscall ids seen with TS_COMPAT set: [3, 4, 5, 6, 11]; with an x86_64 table: read would read as close; write would read as stat; open would read as fstat; close would read as lstat; execve would read as munmap
- execve ids 59/322 seen: 0; TS_COMPAT at sched_process_exec: [0]
- 74 records; 0 unknown lines; 3 preamble lines
