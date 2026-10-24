# Instructions for AI coding sessions

You are working in **Fiery Dragon**, the capture layer of ESE-P15. The maintainer is Ashu (`@ranahunter10`). He reviews every decision and every line himself. Write so that review is easy, and never make a change he hasn't seen.

## Start of every session

1. Read `docs/STATE.md`. It is the single source of truth for the current phase, gates and next step.
2. Read `CONTRIBUTING.md` (flow, commits, PRs, ADRs, evidence) and the ADRs that the task touches (`docs/decisions/`).
3. Work from a fresh branch off the latest `main`.
4. Say in one line what this session will do.

## Hard rules

- **Never push to `main`.** Every change goes through a PR built from `.github/PULL_REQUEST_TEMPLATE.md`, with all four parts filled in.
- **Never create, move or delete tags.** Mark a release candidate with a `release/*` branch and give the maintainer the tag commands.
- **Never edit an accepted ADR.** Write a new one that supersedes it.
- **Never execute code from a third-party repository** cloned for study.
- **Never quote a number without a harness.** Raw output goes under `docs/evidence/`, and every claim is graded SRC / DOC / PDF / MEAS / INF / OPEN. An INF is never stated as a result.
- **No silent fallbacks or caps.** Every early return, drop or bound has a counter.
- **Don't grade your own work as final.** The reviewer re-runs the test command in a fresh clone.
- **Don't weigh the maintainer's time or effort** in recommendations. Present the trade-offs and let him decide.
- **Surface decisions instead of making them.** End a session with a numbered list of decisions waiting, each with a recommendation and its evidence.

## Commits

```
<area>: <imperative summary>

<why>

Signed-off-by: Ashish Rana <ashishrana1619@gmail.com>
Co-Authored-By: <model> <noreply@anthropic.com>
Claude-Session: <session link>
```

## Environment facts (see `docs/evidence/` for proof)

- **Target:** VM `p15-dev-2604`, Ubuntu 26.04.1, kernel **7.0.0-38-generic, held**; 4 vCPU / 8 GB.
  - The maintainer reaches it with `ssh p15`.
  - Kernel-side work and every authoritative measurement happen there.
- **Toolchain on the VM:** clang 21.1.8, libbpf-dev 1.6.3, bpftool 7.7.0 (its own libbpf 1.7), pahole 1.31, bpftrace 0.25.0, Python 3.14.4.
- **Kernel facts established:**
  - BTF is present;
  - `fexit` on `vfs_read` with a return value works;
  - `vfs_readv`/`vfs_writev` are hookable;
  - `__sock_sendmsg` is inlined (not hookable), so the `sock_send_length`/`sock_recv_length` tracepoints are used;
  - `inode_storage` is unavailable (no BPF-LSM);
  - there is no `bpf` in the LSM list.
- **Cloud sessions can't run BPF programs on the target kernel.** Kernel-side changes are proven on the VM by the maintainer, and the PR shows that output.

## End of every session

1. Push the branch and open or update the PR.
2. Update `docs/STATE.md`: phase, gate status with evidence links, the next step, decisions waiting.
3. Add engineering-log rows to `docs/journal/engineering-log.csv` in the PR, following the rules in `docs/journal/README.md`.
