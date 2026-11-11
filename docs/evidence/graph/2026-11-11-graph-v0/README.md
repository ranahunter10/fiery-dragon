# Graph v0 in the dev container (2026-11-11)

Evidence for E-0165 and E-0166 (ADR-0028). Dev container: kernel 6.18.44, Python 3.13.18, DuckDB 2.0.0. Everything here is MEAS in the container; nothing here is from the target VM.

| File | What it is |
|---|---|
| `test-graph.txt` | `python3 -m unittest -v python/tests/test_graph.py`: 28 tests, OK |
| `test-gen.txt` | `python3 -m unittest schema/gen/test_gen.py`: 39 tests, OK (4 new, `SqlTest`) |
| `mutate-graph.txt` | `python3 tools/ci/mutate_py.py 172-267`: the 96 graph mutants, 96 killed. The other 172 mutants of the sweep touch files this PR does not change and were not re-run |
| `scenario-graph.txt`, `scenario-manifest.json` | `python3 -m p15.graph` on the synthetic scenario of `python/tests/scenario.py` (with snapshots), and the export's manifest |
| `container-spine-run.txt` | `python3 -m p15.graph` on a real 5 s p15d run in the container with `--no-files --no-net` |

What they show:
- The synthetic scenario: 7 process, 5 file and 7 socket nodes; 15 events exported; the refused connect and the bind and listen are listed as not exported.
- The real spine-only run: 80 process nodes, 13 CLONE and 12 EXECUTE edges, every exec's file named by the ext4 tuple, `edge_without_node`, `obj_facts_conflict` and `fid_two_objs` all 0.

What they do not show:
- **No real OPEN, FD, BACKING, CLOSE or NET record was graphed.** p15d's file and net programs fail to load in this container (`-EPERM`), so those rules are tested on synthetic records only. The first real graph is the VM run in PR #66.
- PIDSMaker has not been run; that its loader accepts the CSV files is OPEN.
- DuckDB facts used by the loader (a dict of numpy arrays is scanned; u64 above 2^63, BLOBs with NUL bytes and masked NULLs survive) are checked by `RawTables.test_rows_values_and_nulls`.
