# The demo on the VM, 2026-11-14

Run by the maintainer on `p15-dev` (7.0.0-38-generic) with `vm_test.sh demo`. The tree was `vm/integration` with `dragon/demo-v2` at bc650dd on top (`manifest.txt`). Command: `tools/demo/run_demo.sh` with `P15D_FLAGS=--flow`, so file identity, network intent and data flow were all on.

The story is in `docs/demo/README.md`:
- a web app with a command-injection bug;
- one request whose injected command calls home to 4444;
- it then downloads and runs a binary from a stager on 8000;
- last, it pipes a second stage into `sh`, which runs `id` from a memfd and from a deleted file.

| File | What it holds |
|---|---|
| `rules.txt` | the four rules over the run's graph: R1 dropper 3, R2 memfd-exec 1, R3 deleted-exec 1, R4 net-shell 2 |
| `attack-path.txt`, `attack-path.html` | the attack path from the injected shell (`python3 -m p15.graph.story --alert R4`) |
| `graph.txt` | the graph build's books: every zero book is 0 |
| `port-*.txt`, `port-*.html` | `tools/p15-trace` on ports 8080, 4444 and 4442 |
| `story.log`, `p15d.err`, `p15w-inspect.txt` | the story's own log, p15d's log, the WAL's record counts |
| `demo_capture.txt`, `demo_graph.txt`, `demo_track.txt` | the test script's three steps |

The attack path's cause chain is: injected shell ← web app (CLONE) ← the request's server socket (RECV) ← its client socket (TCP, joined by sequence number) ← `curl` (SEND) ← the demo script (CLONE).

Six of the seven alerts are on the path. The seventh is R4 on the ordinary lookup shell, which is not: the rule fires on every shell the web app starts.

The page's labels predate the commit that names pipes by their kind and shows what a multi-call binary was run as.

`SHA256SUMS` covers every file here.
