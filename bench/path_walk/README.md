# The dentry walk against bpf_d_path (gate 2 of STATE decision 28)

**Question.** Under contention the kernel skips the fentry path program for about one open in ten (E-0189, E-0192), and that open's record has no path. The kprobe.session program on the same hook is never skipped that way (it runs with preemption off), but it cannot call `bpf_d_path`. Can a bounded walk of the dentries and mounts, run in the kprobe, give the same path as `bpf_d_path`, or say when it cannot? And what does it cost, in the fentry and in the kprobe? The answer decides between the two designs in STATE decisions waiting 1: (a) walk only when the fentry was skipped, or (b) one kprobe.session program that always walks and no fentry. An ADR will choose, from this harness's VM numbers.

**The walk** is `bpf/include/p15_dpath.h`. It follows the kernel's `d_path` (fs/d_path.c v7.0): the reading task's root, crossing from a mount's root to its mountpoint, " (deleted)" for an unlinked dentry, and, for a dentry whose filesystem makes up its name (`d_dname`), the same string the kernel's function would make for the four it uses for pseudo files: `simple_dname` (a memfd: `/memfd:x (deleted)`), `pipe:[ino]`, `socket:[ino]`, `anon_inode:name` (flag SYNTH; identified by the superblock's magic and default dentry operations, not by kernel addresses; E-0196). Any other `d_dname` is flagged DNAME with no path. `d_path` retries while the rename or mount sequence counter moved; a BPF program cannot take the lock, so the walk reads both counters before and after, retries once, and flags RACED if they moved again. Tetragon and Tracee do not read them (checked by text search at the commits in R-043: neither tree mentions `rename_lock` or `mount_lock`), so a path built during a rename can be one that never existed, without a flag. Bounds: 128 steps, 64 components, names cut at 255 bytes, 4,095 bytes in all; a cut is flagged TRUNCATED.

**How.** `path_walk.bpf.c` attaches two programs to `security_file_open`, for this process only:
- the fentry calls `bpf_d_path` and the walk on the same `struct file`, times each, and sends both strings and the walk's flags in one record;
- the kprobe.session runs the walk alone, timed, where design (b) would run it.

`path_walk.c` runs in a private mount namespace, pinned to the last CPU, and does three things.
1. **Cases**, one open each: a plain file, `/`, a directory, `/proc`, sysfs, devtmpfs, 40 and 70 components, eight names of 255 bytes, a tmpfs mount, a bind mount, an overlay mount, a deleted file, a memfd, a pipe, a socket and an eventfd (the last five reopened through `/proc/self/fd`; the socket's reopen fails with ENXIO in its `->open`, after `security_file_open`), and a chrooted child. Every sample a case causes is compared (an overlay open also opens its real file, E-0196), up to four; the case's verdict is the worst. Each sample is `equal`, `flagged` (a flag says why it differs; a SYNTH name must be equal), or `MISMATCH` (a different path, no flag). 70 components are expected TRUNCATED; every other case is expected equal.
2. **Rename race**: a thread on CPU 0 renames `race/a` to `race/b` and back while this thread opens `race/a/x/y/f` (or `b`) N times. A sample whose counters moved between `bpf_d_path` and the end of the walk is not compared, because each string may be right for its own instant; it is counted as `moved`.
3. **Timing**: ROUNDS rounds of N opens of an 8-component path (`plain/a/b/c/file` under DIR) and a 25-component one (`deep/d00/.../d19/f20`), a warm-up round first, reporting ns per call of `bpf_d_path`, the walk in the fentry and the walk in the kprobe.

Every timed round must have exactly N runs of each program; fewer means the fentry found the ring full (a discarded record keeps its space until the reader passes it, E-0195), and the round fails. `summarize.py` also fails the run on any MISMATCH in a case or in the race, on a case that could not run, on a race that compared no sample, and on a line it cannot parse. An unexpected flag on a case expected equal is a note (a gap in coverage, not a wrong path).

```
make build/path_walk                                       # as the user
sudo build/path_walk /var/tmp/p15-path-walk 20 20000 > build/path_walk.txt
python3 bench/path_walk/summarize.py build/path_walk.txt
```

**Limits.**
- One run is one kernel's dentries for these cases. Cases it does not cover: a path in another mount namespace than the opener's root (setns), a lazily unmounted mount, a mount moved during the walk (the mount counter catches it, but the race only renames), NFS or FUSE.
- The rename race tests one rename pattern on one directory, on a 3-vCPU VM. Zero mismatches in it bounds the rate for that pattern only (the summary prints the count, not a probability).
- Both programs time with `bpf_ktime_get_ns`, about 13 ns per read on the VM (E-0184); the figures compare the two paths with each other and with `bpf_d_path`, on the same opens. They are not a whole-program cost; `bench/open_sections` measures that.
- The fentry's scratch is per CPU and the harness is one pinned thread; in production the walk would run in the kprobe, which cannot be preempted.
- The dev container cannot load these programs (EPERM): CI's runner proves they load and the cases agree there; only the VM's numbers count, and only the VM's run decides the ADR.
