# open_sections: where the file programs' time goes

Run: 12 processes, not pinned, 200,000 open+close each (2,400,000), on 3 CPUs.

- Opens seen by the session program while the workers ran (all tasks): 2,400,026; path program runs: 2,141,522.
- **Path program skipped: 258,504 opens** (OPEN written with PATH_MISSING), 1.08e-01 of 2,400,026.
- The kernel's own counts: recursion_misses path 258504, session 0, close 0; kprobe_multi.missed session 0, close 0.
- Records lost to a full ring: OPEN 0, PATH_MISSING 0, CLOSE 0.

