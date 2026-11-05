# The demo script, dry run in the cloud container (2026-11-02)

**Where:** the cloud dev container, kernel 6.18. It is not the target, and it refuses fentry/fexit (E-0078), so this run used `P15D_FLAGS=--no-net`: **no network records**. It checks the script and the spine half of the story. The full run, with NET, is the VM's (docs/demo/README.md).

**Files:**
- [`story.log`](story.log): what the script did, with the PIDs it started;
- [`p15w-inspect.txt`](p15w-inspect.txt): the C reader on the run;
- [`port-4444.txt`](port-4444.txt): p15-trace for 4444, which says network capture was off;
- [`chain.txt`](chain.txt): the lineage of every `nc`, `sh`, `getent` and `curl` in the run, from the Python process tree.

## Findings (MEAS, dev container, spine only)

1. **The script runs end to end.** p15d exits 0; p15w-inspect exits 0; all three reports are made.
2. **The injected chain is in the spine.** `nc (31940) ← sh (31938) ← python3 (31908)`. 31908 is the web app (`story.log`, step 2), and sh's command line carries the injected `;nc -w1 127.0.0.1 4444`.
3. **The p15-trace report doesn't overclaim.** With network capture off it says so first ("NETWORK CAPTURE WAS OFF … no NET record means nothing is known"), and it ends with "this says nothing", not "nothing happened".
4. **Processes from before the capture are labelled, not given an invented parent.** The script's own shell (31891) is one.
