# The soak graph rebuilt with ADR-0031 and tracking, the soak's file books, and the first cost numbers on today's main (2026-11-12)

VM `p15-dev-2604`, kernel 7.0.0-38, branch `docs/open-cost-research` at 2c70830 (#79, #80 and #81 stacked; the BPF code is main's). The hour's soak WAL is `/var/tmp/p15-soak/wal/20261111T225714Z-9c3a49c2` (E-0202). `vm-session.txt` is the maintainer's terminal, as sent on 2026-11-12. `file_stats.py` is the script it ran; the VM checked it against the sha256 given with it (`file_stats.py: OK`), and that sum matches the committed file.

## 1. ADR-0031 on the hour's graph (MEAS)
- `image_exec_without_edge` is **0** over 55,101 exec images. There are also 55,097 fork images and 34 snapshot images. 116 processes have no image; 11 edges go into a process with no program at their time.
- **p15d is named `p15d`** (tgid 60801). 3,628 renames of threads that are not their process's leader went to `thread_name` instead of renaming their process.
- The new SQL statements take 2.34 s: `edge_plain` 0.880, `edge` 0.897, `proc_image` 0.466, the `exe_node` update 0.056, `thread_name` 0.044. That is under ADR-0031's 5 s falsifier. `proc_src`, which now also builds the image rows, takes 1.498 s; E-0204 had it under 1.1 s.
- The build's profile sums to **107.8 s**, against about 80 s in E-0204. The difference is in reading the WAL and the process tree: 67.7 s here against 42.2 s. This PR changes only one comparison per RENAME in that phase, so the rise is INF until the two builds are timed back to back: VM stalls (E-0088) vary a run this long. Either way, the 60 s target of decision 34 is missed mostly in reading the WAL, which is R3's work (gate 10).

## 2. Tracking on the hour's graph (MEAS, wall time of the whole command: Python start, opening the file, building `track_edge`, the query)
- Backward from node 139 (the soak's own `soak.py`, tgid 60800) at the end: 82 nodes (74 files, 8 processes) in **0.48 s**, 204 MB peak. The files are mostly p15d's `/proc` files that soak.py samples.
- Forward from node 139 from the start: 62,734 nodes (55,067 processes, 7,667 sockets) in **0.39 s**, 227 MB. That is the whole workload's process tree and its connections. No file is reached: nothing points into a file before step 2b.

## 3. The soak's last FILE_STATS (MEAS, one hour)
- 805,932 opens emitted, none lost. 3 opens had their fentry skipped (`fentry_missed` 3); each was written by the return's walk (`missing_emitted` 3, `walked` 3). That is ADR-0029's fallback at work on real programs.
- **`free_run` 1,303,887, of which `free_unregistered` 497,875 (38.2 %) and `close_emitted` 806,012.** So under candidate C2, which pairs closes in user space with no map, the close would emit 62 % more CLOSE records unless it can tell unregistered files apart cheaply (note §4).
- `inode_free_run` 124,258, `inode_free_hit` 89,963. `files_live_max` 603 of 65,536 entries, `objs_live_max` 843 of 131,072.

## 4. The shipped programs' cost, unprofiled (MEAS, `bench/prim_cost/prog_stats.py`, round 6 of 7 only)
`vm-session.txt` holds only the last round's table; the 7-round summary is at the top of `build/prog_stats.txt` on the VM and is still to be sent. Round 6, per open+close:

| Program | ns per op |
|---|---|
| file_open_path (fentry) | 321.9 |
| file_free | 257.4 |
| file_open_session (entry and return) | 206.0 |
| all | **785.4** |

The kernel's statistics add their own cost to each run. The tool's README gives about 20 ns per run (INF here), which makes about 80 ns over 4 runs. The 500 ns budget (E-0193) is missed in this round, by 285 ns as measured and by about 205 net of that overhead (INF).

## 5. `bench/open_cost` did not run
`sudo make bench-open-cost` ran `run.py` with the system Python, which lacks `google_crc32c`. It failed at the first p15d arm's books, after the two untraced warm-up arms. The fix in this PR makes it stop before any arm, with the command to use (`P15_PYTHON=~/p15venv/bin/python`). The end-to-end number is still to be measured.

## 6. Read and write rates under the soak's workload (MEAS, bpftrace 0.25, system-wide, 300 s of `workload.py` without p15d)
- `vfs_read` 78,128 (260 per second), `vfs_write` 14,054 (47 per second), `sock_recv_length` 1,684, `sock_send_length` 1,166.
- `vfs_readv` and `vfs_writev` were never hit.
- In all, about 317 events per second. Opens in the hour's soak ran at 224 per second (805,932 in 3,600 s).
- The largest readers were `ld`, `curl`, `python3`, the assembler, `cc1` and `git`.

`SHA256SUMS` covers every file here except this README.
