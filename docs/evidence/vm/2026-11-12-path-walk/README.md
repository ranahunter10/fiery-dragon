# The dentry walk against bpf_d_path on the VM (2026-11-12)

Evidence for E-0196. VM `p15-dev-2604`, 7.0.0-38-generic, PR #72 at `4c90682`, `sudo build/path_walk /var/tmp/p15-path-walk 20 20000`. Host check before the run: 100.8 ns per null syscall (limit 131.25 ns; the run before E-0195's fix, same session).

`path_walk.md` is the report as the VM printed it. `vm-session.txt` is the whole pasted terminal. The raw output stayed on the VM (`build/path_walk.txt`, sha256 `e17a819e...8ae7`).

## Correctness (MEAS)

- 16 cases, one open each: 13 equal to `bpf_d_path` byte for byte (bind mount, tmpfs mount, overlay, chroot, a deleted file, 40 components, eight 255-byte names among them); 70 components TRUNCATED as expected; the pipe DNAME as expected; the memfd DNAME where the harness expected equal (below).
- Rename race: 20,000 opens against 3,818 renames on another CPU. 19,927 samples; 139 not compared because the tree moved between `bpf_d_path` and the walk; of the 19,788 compared, 19,693 equal and 95 flagged RACED (0.48 %); 97 more needed the one retry and then agreed. **0 wrong without a flag.** 74 opens failed because the file was mid-rename (both names absent), not a capture fault. No sample was lost to the ring.

**The memfd (SRC).** Its dentry comes from `d_alloc_pseudo` (fs/dcache.c L1866-1879, v7.0), whose default `d_op` has `d_dname = simple_dname`, which writes `"/" + name + " (deleted)"` (fs/d_path.c L318-325). `bpf_d_path` printed exactly that (`/memfd:p15memfd (deleted)`). The walk flags every `d_dname` dentry and gives no path, as designed; the harness's expectation was wrong, not the walk. Pipes (`pipefs_dname`, fs/pipe.c L874-878), sockets (`sockfs_dname`, net/socket.c L374-378) and anonymous inodes (`anon_inodefs_dname`, fs/anon_inodes.c L74-78) all build their names with `dynamic_dname` from the inode number or the dentry name, so the walk can write the same strings.

**The overlay case compared the backing file (SRC, INF).** The row shows `/low` with NOT_UNDER_ROOT on both sides. The harness kept the last sample of the case, and opening an overlay file opens its real file from inside the overlay's `->open` (`ovl_open` to `backing_file_open`), on the overlay's private clone of the lower layer's mount, a mount that is its own parent: `/low` is right for that file. The user-visible overlay file (the first sample) was not reported. The next run reports every sample of a case.

## Cost (MEAS), ns per call, median of 20 rounds of 20,000 opens, one pinned thread

| path | components | `bpf_d_path` (fentry) | walk (fentry) | walk (kprobe.session) |
|---|---|---|---|---|
| short | 8 | 156.3 | 246.6 | 233.2 |
| deep20 | 25 | 310.1 | 518.4 | 509.8 |

Per component (the difference of the two rows over 17 components): `bpf_d_path` 9.0 ns, the walk 16.3 ns. The walk in the kprobe costs 1.49 times `bpf_d_path` on the short path and 1.64 times on the deep one. Each figure holds two `bpf_ktime_get_ns` reads (about 13 ns each, E-0184).

## What it decides

By the rule stated before the run (PR #72: "unless the walk costs about the same as `bpf_d_path`"), the walk is not cheap enough to replace `bpf_d_path` on every open: walking always would add about 77 to 200 ns per open to the program bodies, against a 0.5 us budget the file programs already exceed (897.3 ns, E-0192). It is correct enough to stand in for the about one open in ten that the kernel skips under contention. ADR-0029 takes that design.
