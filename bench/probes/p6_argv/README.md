# P6: where to read argv at exec

**Question (blueprint §9.B, spine exec design):** the capture records each program's arguments. Should it read them:
- at **syscall entry**, from the caller's memory through the `argv` pointer; or
- at **`sched_process_exec`**, from the new program's stack (`mm->arg_start`)?

**Why it matters:** the caller's memory belongs to the caller. Another thread can rewrite an argument after the tracer read it and before the kernel copied it. The tracer then records something the kernel never ran. This is a time-of-check/time-of-use gap. The stack copy at `sched_process_exec` is written by the kernel, and the new program hasn't run yet.

**Expected (INF, from v7.0 source):**
- `fs/exec.c`: `do_execveat_common` copies argv with `copy_strings` (line 1826) and only then calls `bprm_execve`.
- `exec_binprm` fires `trace_sched_process_exec` (line 1718), after the new mm is installed.

So EXEC should always equal what the program received, and ENTER should not, under a race. The probe measures this.

## Method

- **[`racer.c`](racer.c):** forks a child per trial. The child calls `execve("/bin/echo", {"echo", ARG})` on a 16-byte argument of `A`s. In `race` mode, a second thread keeps flipping the argument's bytes between `A` and `B`. Echo prints what the kernel copied, and that is the **truth**.
- **[`argv.bt`](argv.bt):** reads argv[1] for the same pids twice:
  - **ENTER:** `raw_syscalls:sys_enter`, id 59. `syscalls:sys_enter_execve` delivers nothing on 7.0 (E-0022).
  - **EXEC:** `sched_process_exec` at `mm->arg_start + 5`.
- **[`run.py`](run.py):** builds the racer and runs a `control` mode (no race) and a `race` mode. It joins the three sources on the pid and counts match / mismatch / missing / empty per source.
  - **`control` must be 100 % match on both sources, or the run is marked unusable.** This checks the harness itself.
  - Lines of unknown shape, duplicate reads, and events with no trial are counted, never dropped.

In the dev container (no BPF), `race` mode alone already shows that the kernel copies a mixture: 2,826 of 3,000 trials were not all-`A`. The racer therefore wins the window at the kernel's copy almost every time.

## Run on the VM

```bash
cd ~/fiery-dragon && git fetch -q && git checkout -q bench/probes-p6-p8 && git pull -q
sudo python3 bench/probes/p6_argv/run.py --trials 1000
```

Output goes to `/var/tmp/fd-probes/<UTC>-p6/`: `index.md`, `results.json`, `conditions.json`, and every raw probe and racer output.

**Exit codes:**
- 0: both modes are usable;
- 1: a problem, listed in the table.

## Tests

```bash
python3 -m unittest -v bench/probes/p6_argv/test_run.py     # 8 tests, no root, no BPF
```
