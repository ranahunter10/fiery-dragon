# Ring-buffer space per variable-length record, on the target VM (2026-10-25 UTC)

**Where:** VM `p15-dev-2604`, kernel 7.0.0-38-generic (held), clang 21.1.8, run by the maintainer on `main` at `118ccf9` (2026-10-26 03:54 IST), pasted into chat: [`terminal.txt`](terminal.txt).

**What:** the `rb_size` probe from the [dev-container run](../2026-10-25-rb-size-container/README.md), for argv of 20, 200 and 1,000 bytes.

## Findings (MEAS, target)

1. **All three ways pass the 7.0 verifier and deliver:**
   - a fixed reservation;
   - `bpf_ringbuf_output` of a run-time length;
   - `bpf_ringbuf_reserve_dynptr` of a run-time length.
2. **Same sizes as in the container.** A fixed reservation takes 1,344 B every time; the exact ways take the record's length:

   | argv bytes | fixed | exact |
   |---|---|---|
   | 20 | 1,344 | 88 |
   | 200 | 1,344 | 264 |
   | 1,000 | 1,344 | 1,064 |

   This is the measurement behind ADR-0017 layer 1, now on the target.

## Notes

- The two `unable to rmdir 'third_party/...'` warnings come from `git checkout`: the VM's checkout was switching from a branch state in which the submodule directories were not tracked. The build used the vendored libbpf (`libbpf v1.7` printed). To confirm the pinned commits: `git submodule update --init --recursive && git submodule status`. A `+` in front of a line means a commit other than the pinned one.
