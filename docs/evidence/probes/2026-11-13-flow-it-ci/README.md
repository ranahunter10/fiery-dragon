# The flow programs' first run, on CI's runner kernel (2026-11-13)

Evidence for E-0245. This was not the target kernel. The VM run with `--flow` is the maintainer's (the matrix).

| File | What | Where it ran |
|---|---|---|
| `it-p15d-case13.txt` | it_p15d case 13 (`p15d --flow` under one process with known transfer sizes), as the job printed it, timestamps removed | GitHub Actions job 131619792933, kernel 7.0.0-1017-azure, PR #90 at commit `3c3adc5` |

What it shows (MEAS, runner kernel):
- Each known transfer is **exactly one FLOW with its bytes**:
  - the 12345-byte write and read of a file;
  - the 7-byte writev and readv, flagged VECTORED;
  - the 3331 bytes through a pipe;
  - over TCP loopback, 321 bytes by `write()` and 222 by `send()` as SEND;
  - the receiver's RECVs, which add up to the 543 bytes sent;
  - one receive with MSG_PEEK, flagged PEEK.
- **No double record for a socket:** the `write()` on the socket is a SEND only. The vfs hook counted it as owned by the socket, which fixes review V2.
- **FILE records:** 5 for open files the process first used at a transfer (the pipe's two ends among them), and 2 for its sockets.
- **Every FLOW starts before it ends**, and no start time was lost: option A held every time.
- **FLOW_STATS:** nothing refused (`flow_invalid` 0), nothing lost to the ring, no kernel skip. The run ended exit 0 and RUNNING, with every book closed (B1 to B5 among them). Both readers accept the WAL.
- With `--flow` on, the previous run had 43 FLOW/FILE records refused per case (E-0240). This run, after the FILE-name fix, had none refused.

One run on a shared runner. It shows the records are right; it is not a cost or a ceiling.

`SHA256SUMS` covers every file here.
