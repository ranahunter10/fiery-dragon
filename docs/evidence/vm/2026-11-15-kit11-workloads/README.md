# Kit fd-vm-test11 on the VM, 2026-11-15: real workloads and attacks against strace

`vm/integration-10` (`manifest.txt`, tree `e7987e4…`): the integrated tree with the TCP pair followed
both ways and `tools/workloads`. Run by the maintainer (`vm_test.sh all`: setup, build, test-c,
test-python, workloads, wlcost). Journal: E-0322.

## Method

Each scenario is captured by p15d (`--flow`, network on) and run under `strace -f -yy` (ptrace: a
witness that shares no mechanism with p15d); `tools/workloads/compare.py` measures the graph
against strace's facts, and the attacks' own manifests (`tools/workloads/README.md`).

## Results (`workloads/<scenario>/compare.txt`, `compare.json`; `workloads.txt` is the console)

- 12 of 12 scenarios ran; p15d exit 0 (RUNNING, books closed) in every one.
- Recall, summed over the 12: processes 340/340, parent links 328/328, execs 305/305,
  opens 18,107/18,107, connects 55/55 (with family, port and result), accepts 35/35. 100 % in
  every scenario.
- Extra processes under a workload's root: 0. Extra opens: an exec's program and ELF interpreter
  (opened by the kernel with no open call), except 2 in a3-fileless (see E-0322).
- Bytes, per process, in the 11 full-trace scenarios: 484,555,962 bytes compared (files read and
  written, sockets received and sent). As run, 1 difference: a1-exfil, one process, 4,150 bytes
  sent in the graph and not in strace's count. It was the witness's rule, not capture:
  `witness-recheck.txt` re-reads every strace log with the corrected rule (a splice into a socket
  is a send) and every kind of every scenario is EXACT.
- Attacks: every `reach` holds (a1 key → catcher with exactly 4,150 bytes; a2 controller → id and
  uname, and id's output → controller; a5 a document → archive → catcher with exactly 61,867
  bytes); a6's 20 refused connects are all in the graph; rules R1 (a1, a3), R2 and R3 (a3) fired;
  **R4 did not fire on the reverse shell (a2)**: a detection gap.
- a4-masquerade did not run as written (`coreutils: unknown program 'kworker'`: Ubuntu 26.04's
  multi-call coreutils); fixed and rerun in kit 12.
- Data moved without vfs_read/vfs_write or a socket tracepoint (unseen by the flow programs, by
  design until step 2d): copy_file_range 1,029 calls, 42,549,605 bytes (cp); splice between files
  and pipes 617 calls, 10,250,764 bytes (rust coreutils' cat, curl).
- Cost (`cost.csv`, `cost-paired.txt`; 5 alternating rounds, no strace, no A/A arm): only
  w5-python's is resolved (paired ratio median 1.066, range 1.022-1.136). w1-build 1.044,
  w4-archive 1.047 and w6-pipeline 0.998 are not resolved from 1. w3-web's arms are too noisy to
  read (0.505-1.231). It is retimed in kit 12.
