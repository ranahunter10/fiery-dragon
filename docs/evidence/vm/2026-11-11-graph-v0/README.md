# Graph v0 on the target VM: the first graph of a real run (2026-11-11)

Evidence for E-0168. PR #66 at `1c7663e`, fetched on the VM from GitHub (reachable again). `graph-v0-vm.txt` is the pasted output; its sha256 here equals the one the VM printed (`bd40848a...0418a`). The export's manifest was not pasted: the VM printed its sha256 (`2a7eaa79...e296`) only.

The run: `sudo build/p15d --wal-dir /tmp/g1/run --duration 60` on 7.0.0-38-generic with file identity and NET on, while `python3 -m http.server 18077` served one `curl` and one `ls /etc` ran. p15d ended with `exit=0 state=0 invariant=1`.

What it shows (MEAS):
- **The must-be-zero counts are zero** on real records: `edge_without_node` 0, `obj_facts_conflict` 0, `fid_two_objs` 0 (the last two are ADR-0015's falsifiers), over 259 OPEN, 276 CLOSE, 2,107 FD and 10 NET records. `rc=0`, no record error.
- **Nodes:** 136 processes, 652 files, 7 sockets. File nodes by rule: 205 by tuple, 167 by open file (anonymous inodes, ADR-0027), 280 by object id (pipes, sockets and other filesystems outside the trust table).
- **Every exec found its file by the ext4 tuple** (4 of 4; `exec_file_unjoined` absent).
- **Every open has a path** (`open_no_path` 0 of 259), none denied, none failed.
- **The one accepted connection was paired with its connect by ISN** (`accept_not_paired` 0).
- 2,107 FD rows over three snapshots became 590 HELD edges (the first sighting per process and open file) and 516 open files first seen in a snapshot.
- One open file is known only from its CLOSE (`openfile_close-only` 1): counted, no edge.
- The export wrote 272 events and held back 4 allowed OPEN edges stamped before the first clock anchor. That was a flaw of the export at `1c7663e`: the hooks attach before the first segment header is written. Fixed in the same PR: such an event is timed by the first anchor and counted in the manifest.

What it does not show: a workload (this is an idle VM plus three commands); PIDSMaker reading the CSV; a detection number.

One operator fact: p15d run with sudo writes its run directory readable by root only; `p15.graph` answered with a Python traceback. Fixed in the same PR (one line, exit 2).

**The fix on the VM** (`85e60bb`, the same run directory graphed again; `graph-v0-vm-rerun-85e60bb.txt` is the pasted `tail -4`, no sha256 was printed for it): all 259 allowed opens are exported (was 255), `event_table` has 276 rows (was 272), and 4 events are reported as timed by the first clock anchor.
