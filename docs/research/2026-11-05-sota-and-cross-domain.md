# Checking the capture's designs against state-of-the-art tools and other fields

**Asked by the maintainer (2026-11-05 IST):** while settling the decided designs, check them against every state-of-the-art tool that can be read, and against ideas from other fields. Adopt what makes the system more robust without making it complex.

**Status:**
- Two findings are already acted on: PR #47, atomic counters; and PRs #48–#49, the cost run ADR-0020 waits for.
- Two are proposed as ADRs for the maintainer: [ADR-0022](../decisions/0022-exact-client-join-tcp-isn.md) and [ADR-0023](../decisions/0023-lifecycle-reconciliation.md).
- One is an input for ADR-0013, the threat model.

**Grades:** SRC (source read at a pinned version), DOC (official docs or a patch posting), PDF (paper), INF (my inference). The sources are R-022..R-031 in [`papers.csv`](papers.csv). Nothing third-party was run.

## 1. The 7.0 tracepoint change, from upstream's side (DOC, R-022)

Rostedt's series "tracing: Guard `__DECLARE_TRACE()` use of `__DO_TRACE_CALL()` with SRCU-fast" (v6, landed in mainline):
- makes tracepoint callbacks preemptible;
- gives BPF `migrate_disable()` (`rcu_read_lock_dont_migrate()` in `__bpf_trace_run`);
- adds `guard(preempt)` to the perf handler "to keep the old behavior".

The cover letter doesn't discuss what this does to BPF's per-program recursion guard.

- **Consequence for us:** ADR-0020's premise holds by upstream's design, not by accident. Classic tracepoints, which take the perf path, stay non-preemptible.
- **Not seen upstream:** the recursion misses we measured on 7.0 (E-0089). Reporting them to the BPF list is the maintainer's call (decision waiting 3).

## 2. A CVE of the same family, used as an audit pattern (DOC, R-023)

- **The CVE:** CVE-2026-89580, "bpf: Disable preemption in `__bpf_get_stack`". A preemptible raw-tracepoint program had a per-CPU callchain buffer reused underneath it by another task on the same CPU, causing an out-of-bounds write. The fix puts preemption back off around the use.
- **The audit pattern:** any per-CPU state shared by programs that can now be preempted.
- **What it found in our code:**
  - the six network fexit programs all bump the same per-CPU `bulk_counters` slots with a non-atomic `*v += 1`;
  - fexit enters with `rcu_read_lock_dont_migrate()` (v7.0 `kernel/bpf/trampoline.c`), and the recursion guard is per program, so a preempted increment can lose another program's count.
- **Fixed:** both `count()` functions are now atomic (PR #47, E-0097).
- **Checked and safe:** the spine's per-CPU EXEC scratch, used only by the classic, non-preemptible exec program.

## 3. What other capture tools do about loss (DOC/SRC)

| Tool | How it detects loss | Located in time? | What it does then | Source |
|---|---|---|---|---|
| Falco | per-second kernel counters (`n_drops`) | per second | ignore, log, alert or exit, rate-limited by a token bucket | R-024 |
| LTTng | a sequence number in every packet, so a gap is a lost packet; discarded events per channel; a warning at stop | per packet | report | R-025 |
| Tetragon | `missed_prog_probes_total` from the kernel's `recursion_misses`; ring-buffer loss counters | no | export a metric | earlier session (SRC, read) |
| auditd | a `lost` counter, `backlog_limit` | no | the failure flag: silent, printk or panic | R-026 |
| **Fiery Dragon** | per-cause BPF counters; `recursion_misses` per program (ADR-0020); batch sequence numbers in the WAL | **per GAP window** | the run state: DEGRADED or INVALID, with the cause in END and STATS | ADR-0006, 0017, 0020 |

- **Consequence:** no tool we read does more than count, and only LTTng locates its losses. Our design already counts, locates and lets the loss decide the run's validity. Nothing to adopt; the comparison goes into ADR-0013.
- **What the 2026 study adds** (Houssel et al., R-027, PDF):
  - "most systems lose a considerable share of their logs";
  - none of the provenance tools it studies "verify that their subset captures provenance completely";
  - it advises capturing the kernel's verdict.
- **Where we stand on those:** we capture the verdict (fexit's return value). Completeness is the gap ADR-0023 closes for the process tree.

## 4. Pairing a connect with its accept: a shared token, not a timestamp

- **The problem** (E-0092): fexit stamps each record when its call returns. On loopback the server's `accept()` returned 12 µs before the client's `connect()` did. A rule that orders by timestamp therefore fails, which is Lamport's point (R-028, PDF): timestamps taken by different observers don't give causal order, and a token both sides carry does.
- **TCP already has such a token:** the client's initial sequence number (SRC, Linux v7.0):
  - **server side:** when the accepted socket is created, `tcp_create_openreq_child` sets `copied_seq = rcv_isn + 1` (`net/ipv4/tcp_minisocks.c` 573–575). The server process can't read anything before `accept()` returns, so at our fexit the client's ISN is `copied_seq − 1`;
  - **client side:** `tcp_v4_connect`/`tcp_v6_connect` set `write_seq` to the ISN (`tcp_ipv4.c` 329–335; `tcp_ipv6.c` 321–327). `tcp_connect` sends the SYN and moves `write_seq` to ISN + 1 (`tcp_output.c` 4365–4388). The process can't write anything before `connect()` returns, so at our fexit the ISN is `write_seq − 1`, for blocking and non-blocking connects alike;
  - the ISN is a keyed hash of the 4-tuple plus a clock (RFC 6528). A reused 4-tuple gets a different ISN.
- **Consequence:** the client join can be exact for TCP. It matches on endpoints, network namespace and ISN, with the time window kept only as a fallback that is counted. Proposed as **ADR-0022**.

## 5. Completeness of the process tree: what bookkeeping does

| Field | The practice | What it gives us |
|---|---|---|
| Accounting (INF) | double entry: opening balance + transactions = closing balance, checked by a reconciliation | the ADR-0007 snapshot is the opening balance and our events are the transactions. A **closing snapshot** at END makes the tree checkable: every process alive at the end must be in the opening snapshot or have a FORK; every process in the opening snapshot that is gone must have an EXIT |
| Clinical trials (CONSORT flow diagram, INF) | every participant is accounted for at every stage: enrolled, allocated, lost to follow-up, analysed | the same shape as our counter books (seen → emitted → drained → written), which already close |
| Messaging (Kafka KIP-98, DOC, R-029) | a per-producer sequence number lets the broker detect gaps and duplicates | the kernel's `self_exec_id` is a per-process exec counter. ADR-0020 rule 5 already plans to carry it, so a skipped EXEC is a gap in one process's sequence |
| System design (end-to-end argument, R-030, PDF) | correctness checks belong at the ends, where the whole operation is known | the reader, which sees the whole run, does the reconciliation. The kernel side stays simple |
| Epidemiology (capture–recapture, INF) | two independent sources estimate how many cases both missed | the snapshot and the event stream are two observers of the same processes. The estimate is biased, because snapshots only see long-lived processes, so it is **not** adopted as a number. The exact reconciliation of item 1 is |

- **Consequence:** proposed as **ADR-0023**. It is small: one more `bpf_iter` snapshot at END (ADR-0007 already takes one at every segment open), and a reconciliation in the reader. Each unexplained process is counted and located.

## 6. Tamper evidence: an input for ADR-0013, not now (PDF/DOC)

A HIDS's own log is a target. Three established designs:
- Schneier–Kelsey forward-secure audit logs (1999);
- Crosby–Wallach history trees (USENIX Security 2009, R-031);
- systemd-journald's Forward Secure Sealing, deployed (R-031).

The WAL's per-batch CRC32C catches corruption, not tampering. A keyed hash chain over batches, with keys that evolve forward, is the cheapest of the three.

**Status:** input for ADR-0013 (threat model). It changes the WAL format (ADR-0007), so it isn't done now.

## Decisions this note leads to

They are listed in STATE, "Decisions waiting":
- ADR-0022;
- ADR-0023;
- whether to report the recursion-miss finding upstream.
