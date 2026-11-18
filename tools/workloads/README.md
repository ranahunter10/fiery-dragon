# Real workloads and attack scenarios, checked against an independent witness

`run.sh` captures each scenario with p15d (`--flow`, network on) **and** runs it under
`strace -f -yy`, then `compare.py` measures how much of what strace saw is in p15d's graph.
strace watches through ptrace, a mechanism p15d does not share, so a fact strace saw and the
graph lacks is a miss of the capture or the graph, not a shared blind spot. Attack scenarios also
write their own ground truth (`manifest.json`): what they did, in their own words, checked with
the graph's forward walk (`p15.graph.track`) and its detection rules (`p15.graph.rules`).

    sudo P15_PYTHON=$HOME/p15venv/bin/python tools/workloads/run.sh OUT [SCENARIO...]
    sudo P15_PYTHON=$HOME/p15venv/bin/python tools/workloads/cost.sh OUT [ROUNDS] [SCENARIO...]

## Scenarios (`scenarios/`)

| | What it does | Trace |
|---|---|---|
| w1-build | libbpf compiled with make -j3 (about 100 processes: make, cc, cc1, as, ar) | full |
| w2-git | shallow clone of this repo over file://, log, status, grep | light |
| w3-web | python3 threading http.server, 30 curl downloads 10 at a time, sha256-checked | full |
| w4-archive | docs copied, tar+gzip, checksummed, unpacked and compared | full |
| w5-python | SQLite, 20,000 rows in a transaction, queried; compileall of a copy of python/ | full |
| w6-pipeline | find, xargs, cat, tr, sort, uniq, head joined by pipes | full |
| a1-exfil | stager download, chmod, run (dropper); fake key sent to a catcher with bash /dev/tcp | full |
| a2-revshell | a shell whose stdin/stdout is a socket to a controller; the controller's commands run | full |
| a3-fileless | a program run from a memfd; a program run from a file unlinked while open | full |
| a4-masquerade | a copy of sleep dropped as .X11/kworker and run; prctl rename to kworker/0:1; a cron line | full |
| a5-staged | documents tarred into a hidden archive, the archive sent by another process (two hops) | full |
| a6-scan | 20 refused connects and one accepted, by bash /dev/tcp | full |

All on loopback, all payloads harmless (copies of id, uname, hostname, sleep; random bytes).
"light" traces processes, opens and connects only (no byte comparison).

## What compare.py reports

- **recall** per kind of fact: processes, parent links (CLONE edges), execs, opens, connects (with
  family, port and result), accepts. Every miss is listed.
- **bytes** per process: file/pipe bytes read and written, socket bytes received and sent.
- **extra**: processes under the workload's root that strace did not see; opens strace did not see
  (an exec's program and ELF interpreter are opened by the kernel with no open call: expected).
- **not comparable, by design, counted**: O_PATH opens (no security_file_open), AF_UNIX connects
  (no NET record), failed opens (they never reach security_file_open), sendmmsg/recvmmsg (the
  result is a message count), and data moved without vfs_read/vfs_write or the socket tracepoints
  (sendfile, splice, tee, vmsplice, copy_file_range, io_uring): reported with their bytes.
- **attack**: each `reach` (the walk from a file or process reaches a listener or a program, or,
  with `"expect": false`, must not), the bytes a catcher received, refused connects, renames, and
  which rules fired. A rule that did not fire is a **detection gap**, reported apart from capture
  or graph defects.

strace slows a workload several times; the timing that matters is `cost.sh`'s, without strace.
