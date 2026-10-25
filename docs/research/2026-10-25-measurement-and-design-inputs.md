# Measurement that holds across platforms, and design ideas backed by numbers

**Asked by the maintainer (2026-10-26 IST):**
- how Fiery Dragon can be quoted in numbers that stay valid across platforms (real workloads, stated limitations);
- design choices from industry and academia that are backed by numbers, to adopt if they fit.

**Status:** research input, nothing adopted. Each item ends in a candidate action. The decisions are listed at the end, for the maintainer.

**Scope:** this note adds to the project's earlier research and does not repeat it. Already covered there:
- eAudit, Houssel et al., Mao et al., ProvMark, Falco's 2021 load test, Tetragon's vendor figure, the kernel's ring-buffer/perf-buffer benchmark (commit c97099b0) and Cloudflare's hook costs;
- see `quantification.md`, `loaders_userspace.md` and `dataflow_hooks.md` in the project research notes.

**Grades:**
- **PDF:** read in the full text.
- **DOC:** official docs, a patch posting or the author's own published material. Vendor posts are marked *(vendor)*.
- **INF:** my inference.

Sources are R-011..R-021 in [`papers.csv`](papers.csv). None of them was read beyond what is quoted here.

---

## Part A. Numbers that survive a change of machine

The problem: an absolute number from this laptop's VM (records/s, ns per event) changes with the CPU, the hypervisor and the host's load. E-0044 showed 12–29 % CV on this host. Piotrowski benchmarked DTrace against eBPF on two identical 32-core servers and still concluded that "any performance comparison between DTrace and bpftrace would be unfair and misinformed," because factors such as compiler versions were not controlled (R-017, PDF). The literature does five things instead.

### A1. Lead with dimensionless metrics

These numbers are ratios or counts, so they move far less between machines than rates do:

| Metric | Definition used in the literature | Who uses it |
|---|---|---|
| Loss | discarded ÷ total, or 1 − traced ÷ expected with a witness event of known count | Nitro, CCS'25 (R-011); Houssel |
| Runtime overhead | (T_traced − T_base) ÷ T_base | Nitro (R-011); NoDrop, USENIX Sec'23 (R-012); Houssel |
| Completeness | per-syscall "captured / not", from foreground and background program pairs | ProvMark |
| Bytes per record | average record size on a named workload | Nitro: 24 B vs auditd's 850 B on Postmark (R-011) |
| Records per operation | records emitted per witness operation, i.e. selectivity | eAudit, Houssel (output volume) |

**Candidate:** the Phase-1 and Phase-6 headline table carries only these, each with the workload, the hook set and the run count. Rates and ns go in a second table labelled "this host".

### A2. Quote rates against a same-host upper bound

Hoefler and Belli's rule 11 (SC'15, R-013, DOC slides): *"If possible, show upper performance bounds to facilitate interpretability of the measured results."*

For us the bound is what the kernel's ring buffer can carry on the same VM with nothing else in the way. The kernel ships a harness for exactly this, `tools/testing/selftests/bpf/benchs` (`bench ringbuf`, with `-p N` producers). Published runs give:
- AMD EPYC 9654: 13.2 M records/s with 1 producer and 1.07 M/s with 52 producers (R-015, DOC);
- Kunpeng 920: 11.6 M/s with 1 producer (same thread).

**Candidate:** run the kernel's `bench ringbuf` on the VM at 1–4 producers, in the same session as our knee. Quote the knee as "N records/s = X % of this host's ring-buffer ceiling" and as a curve over vCPUs (1, 2, 4).
- A percentage of the host's own ceiling travels between machines far better than records/s (INF).
- Building `bench` needs the kernel's selftests source for 7.0 on the VM.

### A3. Quote per-event cost as a multiple of a same-host baseline

Gebai and Dagenais (ACM CSUR 2018, R-014, PDF) measured every tracer against a no-tracer baseline on one machine:
- baseline 17 ns;
- LTTng 92 ns, ftrace 116 ns, perf 121 ns, eBPF-tracing 128 ns, eBPF with kprobe 140 ns (Table III);
- setup: Intel i7-3770, hyperthreading, C-states, frequency scaling and Turbo off, interrupts disabled around each call, samples with an NMI discarded, buffers warmed first.

Cloudflare's hook costs (prior note) sit on a 117 ns `getpid` baseline in the same way.

**Candidate:** report our in-kernel cost from `bpf_stats` (`run_time_ns ÷ run_cnt`) and also as "× this host's null-syscall time". The null-syscall time comes from the same session (lmbench `lat_syscall null`, or our own loop).
- Bryce Kahle (eBPF Summit 2020 lightning talk, R-016, DOC) gives `bpf_stats` itself an overhead of **about 20 ns per run**. It must be stated and, for cheap programs, subtracted or bounded.
- `bpf_stats` covers only the BPF program. The drain's cost is measured separately (agent CPU-seconds, ADR-0012).

### A4. Statistics reviewers expect

**Hoefler and Belli** (R-013, DOC slides; the slides number eleven rules, and rule 7 is not on them):
- rule 3: arithmetic mean for costs, harmonic mean for rates;
- rule 4: *"Avoid summarizing ratios; summarize the costs or rates that the ratios base on instead"*;
- rule 5: report confidence intervals for nondeterministic data;
- rule 6: don't assume normality without checking;
- rule 9: document every varying factor and the complete setup.

**What the comparison papers do:**
- NoDrop: 10 runs, compared with the **Wilcoxon signed-rank test** (R-012, PDF).
- Nitro: 30 runs per experiment, with relative standard deviation 3.91–14.05 % (R-011, PDF).
- Houssel: 10 runs after 10 warm-ups.

**Tension with ADR-0012:** our protocol reports the median of per-round *paired ratios*, which rule 4 warns against. The pairing is there for a reason: it cancels this host's drift (E-0044, E-0046).

**Candidate** (a superseding ADR if accepted): keep the pairing and the A/A control, and report three things side by side:
- the paired-ratio median with its range (our drift-robust number);
- the medians of the traced and untraced costs, each with a nonparametric 95 % CI (what rule 4 asks for);
- a Wilcoxon signed-rank p-value on the pairs (the NoDrop precedent).

Raise the minimum from 7 rounds to 10 to match the field.

### A5. Real application workloads: use the set the comparison papers share

| Workload | Nitro CCS'25 | NoDrop Sec'23 | eAudit S&P'24 | Houssel |
|---|---|---|---|---|
| Postmark | ✓ | ✓ | ✓ | ✓ |
| shbm (exec loop) | ✓ | | ✓ | ✓ |
| find, tar | ✓ | | ✓ | |
| httperf / Nginx | ✓ (both) | Nginx | httperf | httperf |
| Redis | ✓ | ✓ | | |
| OpenSSL | ✓ | ✓ | | |
| 7-Zip | ✓ | ✓ | | |
| kernel build | ✓ | | ✓ | |
| lmbench | ✓ | ✓ | | |
| others | rdwr, Firefox Speedometer | Django, Go http, pgbench | rdwr | |

Sources: R-011, R-012 (PDF); eAudit and Houssel from the prior notes.

**Candidate:** the L7 suite becomes:
- eAudit's seven stress tests at 1–4 threads;
- Nginx, Redis, OpenSSL, 7-Zip and lmbench, at the parameters those papers state.

Then every overhead and loss figure has a published row next to it: "same workload, their hardware, their number". That is a fair comparison of method, not a claim that our machine is faster.

### A6. The adversarial test everyone now runs

The super producer:
- Mao et al.: `find` over `/usr` with five threads;
- NoDrop: one process per core writing in a loop for 30 s, at several rates.

Results:
- NoDrop: Sysdig drops 31 % on a 1-core VM and 98.5 % on a 32-core VM; LTTng 0–52 %; Linux Audit 99.1–99.6 % (Fig. 4, Table 5, R-012, PDF);
- Nitro under stress: 0.00–2.17 % loss, against QuickLog2's 30.9–98.0 % (Table 1, R-011, PDF).

**Candidate:** an L6 row "loss under NoDrop's super producer", reported as loss % per ring. The spine row matters most (B6).

### A7. Limitations to state up front

These are the ones the sources above would expect us to declare:
- the VM has no PMU counters, so cycles and instructions are not available (E-0057);
- the host runs under Hyper-V, so absolute timings drift (E-0044);
- we use one machine, where the comparison papers used 12–36 cores;
- vendor figures we compare against are not independently measured;
- compiler, kernel and tool versions are pinned and listed for every number.

---

## Part B. Design ideas with numbers behind them

### B1. Ring buffers per CPU, or per pair of CPUs, instead of one shared ring

**Evidence:**
- The ring buffer serialises reservations under a spinlock; commits are lockless (the commit that added it, R-021, DOC).
- Contention on EPYC 9654: 13.2 M records/s with 1 producer, falling to **1.07 M/s with 52 producers** (R-015, DOC).
- Gebai and Dagenais: tracers with per-CPU buffers (LTTng, perf) scale with cores; those with shared locks (ftrace's global clock) do not (R-014, PDF).
- Falco's modern probe defaults to **one ring buffer per two CPUs** (`modern_bpf.cpus_for_each_syscall_buffer`), 8 MB each by default (R-018, DOC, vendor). No numbers are given.

**Fit:** ADR-0006 already names "the reservation lock limits throughput on 4 vCPUs" as a falsifier. At 4 vCPUs the effect is probably small (INF).

**Candidate:** measure before changing anything. Run `bench ringbuf -p 1..4` on the VM (A2). If 4 producers lose more than about 2× against 1, a superseding ADR moves to per-CPU rings for the bulk class, merged by `ts_ns`. Our reader already plans that merge across rings.

### B2. Two-level buffering: stage in per-CPU arrays, flush in batches

**Evidence:**
- Nitro caches records in per-CPU arrays, flushes to the ring buffer every T_p = 200 ms (S_p = 32 KB) and to user space every T_r = 1 s (S_r = 64 MB) (R-011, PDF). It reports 10–25× over the prior tamper-evident logger under stress, 2–10× on real workloads, and loss of 0.00–2.17 %.
- eAudit uses the same idea (prior note).

**Fit:** the bulk class in Phase 2, where rates are high.
- Not the spine: staging adds up to T_p of latency, and Nitro still loses up to 2.17 % under stress.
- ADR-0006 says the spine is never shed.

**Candidate:** an input to Phase 2's ADR-0010, record classes.

### B3. Smaller records

| System | Average record size | Grade |
|---|---|---|
| Nitro | 24 B | PDF |
| eAudit | about 17 B | prior note |
| auditd | 850 B | PDF |
| Datadog's serialized events | about 5 KB | DOC, vendor |
| Our spine | 40–64 B fixed; EXEC up to 1,344 B | — |
| v3.7 | 392 B | — |

Sources: R-011; R-019 for Datadog.

**Candidate:** Phase-2 FLOW/OPEN records get a size target in ADR-0010, such as ≤ 32 B fixed part, measured as bytes per record on Postmark (A1).

### B4. Filter in the kernel before the ring buffer

**Evidence:** Datadog's file-integrity pipeline pre-filters "up to 94 % of events directly in the kernel" (R-019, DOC, vendor). Its two mechanisms:
- **approvers:** static values from the rules;
- **discarders:** runtime values that can never match, kept in LRU maps so memory stays bounded.

They report about 5,000 events/s per host from eBPF, about 300/s reaching the agent, and fewer than 1/s reaching the backend (same post, vendor).

**Fit and conflict:** this is ADR-0005's territory, and **discarders filter on values**. The blueprint rule is: filter on *who* and *what kind*, never on *which value*, because a value filter is an evasion surface.

**Candidate:** record it as a considered option in ADR-0005, with the conflict stated.

### B5. A tamper-evident WAL

**Evidence:** Nitro signs every record **inside eBPF**:
- a forward-secure aggregate MAC (XLog, using Chaskey because eBPF has no AES-NI);
- per-CPU key state;
- about 1.2 KB of secret state at 36 cores (R-011, PDF; CCS'25).

**Fit:** our WAL's CRC32C detects accidents, not an attacker with root who rewrites a segment. This belongs in ADR-0013 (threat model). It would be a real differentiator for a HIDS thesis, at a real cost: key handling, and more per-record work in BPF.

**Candidate:** list it in ADR-0013 as an option for after Phase 2; no change now.

### B6. What happens to the spine under a super producer

**Evidence:**
- NoDrop reaches **zero loss** with per-thread in-kernel buffers drained *in the producing thread's own context*. The flooder pays for its own events.
- The cost: lmbench OS overhead **35 % above vanilla Linux** (same as Sysdig), and application overhead 6.58 % above vanilla on average (Tables 3–4, R-012, PDF).
- Sysdig-CPR (data reduction) handles about 2,000 events/s per core, against a super producer that can generate 100,000/s (same paper).

**Fit:** our rule, a spine reserve failure invalidates the run (ADR-0006), is honest, but it lets an attacker *cause* invalid runs. An exec or fork storm is the only way to flood the spine; file and network floods go to the bulk ring (INF). BPF cannot block a producer, so NoDrop's mechanism is not available to us.

**Candidate:**
- state this as a declared limitation in ADR-0013;
- measure it: the L6 super-producer row (A6), with a fork/exec storm aimed at the spine, reporting the storm rate at which `spine_reserve_failed` first rises.

### B7. Latency percentiles per hook, and LTP as the workload

**Evidence:** ByteDance's Elkeid HIDS publishes, per kernel hook, the average, TP90, TP95 and TP99 handler latency over 90 s. For example, `execve_handler` averages 15.2 µs with TP99 36.1 µs. The workloads are LTP's syscall tests (`runltp -f syscalls -s execve -t 5m`), on a Xeon 8260 VM with kernel 4.14 (R-020, DOC, vendor).

**Candidate:**
- **LTP's syscall tests as a completeness driver (L5/L8):** they exercise many argument variants of each syscall, which our ProvMark-style suite can count against.
- **Percentiles:** `bpf_stats` gives only a mean. Percentiles would need timing inside the program, which adds cost. Recommend the mean only, unless a reviewer asks.

---

## Decisions for the maintainer

1. **Headline metrics (A1):**
   - Recommend: dimensionless only in headline tables, with absolute numbers in a "this host" table.
   - Evidence: R-011, R-012, R-017.
2. **Same-host ceiling (A2, B1):**
   - Recommend: build the kernel's `bench` for 7.0 on the VM and run `bench ringbuf -p 1..4` before the Phase-1 gate run.
   - It gives both the denominator for the knee and the B1 contention answer.
   - Evidence: R-013 rule 11, R-015.
3. **Statistics (A4):**
   - Recommend: a superseding ADR to 0012 that keeps the pairing and the A/A control, adds the medians of the raw costs with nonparametric CIs and a Wilcoxon signed-rank test, and raises the minimum to 10 rounds.
   - Evidence: R-013, R-012, R-011.
4. **L7 workload set (A5):**
   - Recommend: eAudit's seven stress tests plus Nginx, Redis, OpenSSL, 7-Zip and lmbench, at the published parameters.
   - Evidence: R-011, R-012, prior notes.
5. **Super producer and the spine (A6, B6):**
   - Recommend: add the L6 row now, and declare the "attacker can invalidate a run" limit in ADR-0013.
   - Evidence: R-012.
6. **Phase-2 inputs (B2, B3, B4):**
   - Recommend: record them as considered options in ADR-0005 and ADR-0010 when those are written.
   - No action now.
7. **Tamper-evident WAL (B5):**
   - Recommend: list it in ADR-0013 as a post-Phase-2 option.
   - Evidence: R-011.
