# The soak: p15d under real programs, checked against what they did (gate 4 of STATE decision 28)

**Question.** Does capture hold up under real programs for a long run? Three things are checked at once. Nothing a program did is missing from the WAL. Nothing leaks or drifts over an hour: CPU, memory, map fill, losses. The graph of the run is built, and it ties together what a detector needs.

**The workload** (`workload.py`) runs real programs in turn, each step in its own directory, and logs what it did:
- **compile:** 12 generated C files compiled with `cc`, linked, and the built program run;
- **git:** a repository with 12 files added, committed and logged;
- **archive:** `tar` with gzip packs 12 files, unpacks them elsewhere, and `sha256sum` reads the copies;
- **pyfiles:** a Python child writes, reads and deletes 12 files;
- **http:** a local `http.server` serves 8 fetches by `curl` (or Python);
- **shell:** a copied `/bin/true` runs 50 times from `bash`, then a pipeline;
- **memfd:** a program is copied into a memfd and executed from it (fileless execution).

Each step's log line says what the WAL must hold: the exact paths opened for writing and for reading, EXECs by filename or by argv[0] (at least n), and network accepts and connects on the step's own port (at least n). A record counts for a step only if its kernel timestamp falls inside that step's window. Steps run one after another, so a background program or a reused port can never stand in for a missed event.

**The soak** (`soak.py`, as root):
1. Starts p15d with its defaults, runs the workload for DURATION seconds, and every SAMPLE seconds records p15d's CPU per thread, its resident memory, the WAL's size and the text file's run state, events, kernel skips, queue-full and GAP counts.
2. Stops p15d and checks END.
3. Reads the whole WAL once, crediting each record to its step, and reports every step kind's recall with up to 5 missing items, plus the file programs' last FILE_STATS (the walk's counters included).
4. Builds the graph (`python -m p15.graph`) and checks three things against the log:
   - every compiled program is one file node, opened for writing by one process and executed into another (the dropper chain);
   - every http connection's client socket is paired with its server socket by the TCP ISN (ADR-0022);
   - every memfd execution is a process with its EXECUTE edge.

`summarize.py` passes the run only if the end is clean (exit 0, RUNNING, the invariant closed, no WAL error), the recall is 100 % for every step kind, the graph's must-be-zero books are 0, every graph check is complete, and at most 10 % of the workload's steps failed. It reports CPU, memory, WAL growth and event counts without judging them. Memory that grows by half and by more than 10 MiB over at least a quarter hour is a note.

```
make build/p15d                                             # as the user
sudo ~/p15venv/bin/python bench/soak/soak.py --p15d build/p15d --work /var/tmp/p15-soak --duration 3600 > build/soak.txt
python3 bench/soak/summarize.py build/soak.txt
```
CI runs 45 s of it on every PR (`--clean`), so a capture or graph regression on real programs fails the build.

**Limits.**
- Reads and writes are not captured yet (step 2b), so "written" means an open for writing. The dropper chain is an open for writing followed by an execution of the same object, not bytes that flowed.
- File renames, unlinks and mmap are not hooked yet (steps 3 to 5): the workload's deletes are not checked.
- The workload's pace (one step a second) is a working host's, not a stress test. bench/open_cost and open_sections measure the loaded paths, and the census's super-producer the rates.
- Reading a one-hour WAL in Python takes minutes; the report gives the time.
