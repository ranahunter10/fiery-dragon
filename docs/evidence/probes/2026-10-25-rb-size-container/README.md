# Ring-buffer space per variable-length record, three ways (dev container, 2026-10-25)

**Where:** the cloud dev container (kernel 6.18.44, clang 18.1.3, root). **Not the target kernel.** The target run gives the same sizes: [VM run](../2026-10-25-rb-size-vm/README.md).

**What:** [`bpf/test/rb_size.bpf.c`](../../../../bpf/test/rb_size.bpf.c) attaches three programs to `tp_btf/sched_process_exec`. On every exec, each emits one record of `len = 64 + argv bytes (≤ 1024)`, rounded up to 8, into its own ring:

| Mode | How |
|---|---|
| fixed | `bpf_ringbuf_reserve()` of the maximum (1,344 B); the spine's EXEC today |
| output | built in a per-CPU scratch buffer, then `bpf_ringbuf_output()` of exactly `len` |
| dynptr | `bpf_ringbuf_reserve_dynptr()` of exactly `len`, written with `bpf_dynptr_write()` |

The loader ([`rb_size.c`](../../../../bpf/test/rb_size.c)) execs `/bin/true` with an argv of 20, 200, 1,000 and 4,000 bytes. It prints the size each record occupies in its ring, the `size` libbpf passes to the callback. Raw output: [`rb-size.txt`](rb-size.txt).

## Findings (MEAS, dev container)

1. **All three ways pass the verifier and deliver.** Both exact-size ways accept a length computed at run time (bounded for the verifier).
2. **A fixed reservation always takes 1,344 B; the exact ways take the record's length:**

   | argv bytes | record len | fixed | exact |
   |---|---|---|---|
   | 20 | 88 | 1,344 | 88 |
   | 200 | 264 | 1,344 | 264 |
   | 1,000 | 1,064 | 1,344 | 1,064 |
   | 4,000 (cut to 1,024) | 1,088 | 1,344 | 1,088 |

   For a short command line, the spine's EXEC takes about 15× the ring space it needs.

## Notes

- The ring also adds an 8-byte header to every record (`Documentation/bpf/ringbuf.rst`, DOC); the table shows payload sizes only.
- `output` copies the record twice, once into the scratch buffer and once into the ring; `dynptr` writes it once. Their CPU cost is not measured here.
