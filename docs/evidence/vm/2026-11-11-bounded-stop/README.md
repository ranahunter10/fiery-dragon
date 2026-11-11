# The bounded stop on the target VM (2026-11-11)

Evidence for E-0163. PR #65 at `07a66d7`, brought to the VM as a git bundle (`fd.bundle`, sha256 `332835ed...7232e`; GitHub was unreachable from the VM: DNS resolved, TCP to port 443 timed out). The outputs were pasted in chat; the VM printed sha256 `4dd60979...27590` for `it-stop.txt` and `0b06bf8b...e158` for `mutate-stop.txt`.

What they show (MEAS, 7.0.0-38-generic):
- `make it-p15d`: PASS, every case. Case 10: a writer stalled 30 s before the closing snapshot ends the stop with exit 75 (STUCK) in 4 s, the log names the phase, the WAL is valid without END; a writer slow for 0.8 s under a 2 s bound stops in order with END.
- `mutate_p15d.py 45 46 47 48`: the three watchdog mutants of `run.c` killed in 2 s each; mutant 48 (no watchdog on the closing wait) did not build: removing the line left its watch unused. It now disables the line instead.
