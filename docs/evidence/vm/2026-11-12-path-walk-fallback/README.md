# Gate 2 on the VM: skipped opens arrive walked (2026-11-12)

Evidence for E-0198 (ADR-0029 confirmations 1, 3 and 4). VM `p15-dev-2604`, 7.0.0-38-generic, PR #73 at `2a5d2eb`. Host check: 86.9 ns per null syscall (limit 131.25). `path_walk.md` and `open_contend.md` are the reports as the VM printed them; `vm-session.txt` is the whole terminal. Raw files on the VM: `build/path_walk.txt` (sha256 `258de2e6...4989`), `build/open_contend.txt` (`c0f9720d...c5cf5`), `~/it-v3.txt` (`1743760c...4b4c01`).

## The walk against bpf_d_path (MEAS)

All 18 cases agree or are flagged as expected; every sample of each case compared. The overlay case's two samples (the user-visible file and its real file on the overlay's private layer mount) are both equal. memfd, pipe, socket and eventfd are equal byte for byte with the names the walk now makes (`/memfd:p15memfd (deleted)`, `pipe:[124327]`, `socket:[124328]`, `anon_inode:[eventfd]`). Rename race: 19,904 samples, 177 not compared, 105 flagged RACED, **0 wrong without a flag**. Cost per call as in E-0196: 157.0 ns `bpf_d_path`, 245.1 ns the walk in a kprobe.session (8 components); 314.0 against 515.4 (25 components).

## Under contention (MEAS): every skipped open has its path

12 processes, 200,000 open+close each, on 3 vCPUs: the kernel skipped the path fentry for **192,715 of 2,400,000 opens (8.0 %)**, equal to its `recursion_misses`; the session and close programs skipped none. The session return walked **all 192,715**, none without a path, none RACED or TRUNCATED; all 192,715 walked OPENs read from the ring name `/var/tmp/p15-open-cost/same` exactly (**0 with another path**); nothing lost; books ok. Before ADR-0029 those opens had no path (E-0192: 258,504 of 2,400,026, 10.8 %, all PATH_MISSING).

## End to end (MEAS)

`it_p15d.sh` PASS with network and file identity. Case 12 (fentry unattached): 6 OPENs from the session return, 5 walked with a path, 1 PATH_MISSING (a file whose facts were not in that record, so its filesystem is not known from the case; a `d_dname` the walk does not know, counted).
