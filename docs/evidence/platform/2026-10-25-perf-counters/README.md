# Hardware performance counters and BPF run-time stats on the VM (2026-10-25)

**What:** on VM `p15-dev-2604` (kernel 7.0.0-38, VirtualBox 7.2.22 on Windows with Hyper-V on), the operator ran:

```bash
sudo perf stat -e instructions,cycles -- /bin/true 2>&1 | tail -6; sysctl kernel.bpf_stats_enabled
```

**Raw output:** [`terminal.txt`](terminal.txt).
- **It was transcribed from the operator's chat message**, not attached as a file, so its bytes are this session's copy of the pasted text (`SHA256SUMS`).
- The sudo prompt line is part of the paste.

## Findings (MEAS)

1. **The guest has no hardware performance counters:** `perf stat -e instructions,cycles` prints "No supported events found. The instructions event is not supported."
   - So cycle and instruction counts, which Tetragon's benchmark harness uses with `perf stat`, are **not available on this VM**.
   - The cause (VirtualBox's PMU virtualization, or Hyper-V underneath it) is not separated; it doesn't change the consequence.
2. **BPF run-time statistics are off by default:** `kernel.bpf_stats_enabled = 0`, the same as in `00-vm-baseline.txt`.
   - Whether turning them on works, and what it costs, is **OPEN**: the first Phase-1 program settles it.
