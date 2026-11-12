# open_sections: where the file programs' time goes

Run: 12 processes, not pinned, 200,000 open+close each (2,400,000), on 3 CPUs.

- Opens seen by the session program while the workers ran (all tasks): 2,400,000; path program runs: 2,207,285.
- **Path program skipped: 192,715 opens** (OPEN written by the session return), 8.03e-02 of 2,400,000.
- The kernel's own counts: recursion_misses path 192715, session 0, close 0; kprobe_multi.missed session 0, close 0.
- Records lost to a full ring: OPEN 0, PATH_MISSING 0, CLOSE 0.

- **The session return walked 192,715 of the 192,715 skipped opens** (PATH_WALKED, ADR-0029); 0 without a path; 0 RACED, 0 TRUNCATED.
- Walked OPENs read from the ring: 192,715; of those naming a file called `same`, 192,715, **0 with another path than DIR/same**.
