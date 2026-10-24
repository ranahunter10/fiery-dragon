# Fixed-work baselines (phase-0 probe P12): how fast, how stable, what tracing costs

`baseline.py` runs fixed jobs, untraced and under a probe, over several rounds, and reports for each job and configuration:
- the **mean**;
- the **spread** (CV %, the drift indicator);
- the **tracing slowdown**.

It's the instrument behind:
- P12, untraced baselines, which turn census selectivity into projected record rates;
- the Hyper-V on/off experiment (E-0029, E-0036).

```bash
python3 bench/baseline/baseline.py --label x --rounds 3 --dry-run          # show the counterbalanced plan
sudo python3 bench/baseline/baseline.py --label hyperv-on-A1 --rounds 3 \
    --snapshot 01-toolchain --host-note "Hyper-V ON, plugged in, Best performance, no other apps"
```

Output goes to `/var/tmp/fd-baseline/<UTC>-<label>/`: `index.md` (the table), `results.json` (every value), `conditions.json`, and each job's log.

## Jobs ([`jobs.py`](jobs.py))

Each job times **only its own work** and prints one JSON line.

| Job | Work | Unit |
|---|---|---|
| `find-serial` | `find /usr` × 3 in sequence | s (lower is better) |
| `find-parallel` | 5 concurrent `find /usr` | s |
| `exec` | 2,000 × `/bin/true` from a bash loop | s |
| `churn` | 10 s of PostMark-style small-file churn | ops/s (higher is better) |
| `disk` | 20 s of 1 MiB direct sequential writes (fio, as P5 test A) | MB/s |

If a job's tool is missing, the job is **SKIPPED** and that is shown. It is never silently dropped.

## Method choices

- **Counterbalanced order.** Odd rounds run untraced first, even rounds traced first, so "whatever ran second was warmer" cancels out instead of looking like overhead.
- **Slowdown is always "> 0 = tracing made it slower"**, whatever the unit's direction: time ratio for seconds, inverse ratio for ops/s and MB/s.
- **⚠ for any configuration whose CV exceeds 10 %**, and its slowdown is marked *not quotable*. In the dev-container dry run, `churn` varied 82 % between two rounds; a "+48 %" read from that would be noise.
- Swap is off while measuring and restored afterwards. Jobs run as the sudo user, not root.

## Tests

`python3 -m unittest -v bench/baseline/test_baseline.py`: 15 tests covering order, aggregation and slowdown direction, failed values, the unstable flag, parsing (including fio's leading notices), jobs, and the CLI. A mutation sweep of 6 deliberate bugs killed 6/6, after one test was strengthened: W6 had survived because the test couldn't tell first from last result line.
