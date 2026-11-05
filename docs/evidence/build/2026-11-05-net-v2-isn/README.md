# ADR-0022 built: NET v2 and the exact client join (2026-11-05)

**Where:** the dev container. It can't load fexit (E-0078), so the network programs are proved by CI's 7.0 runner (case 5, the load-time self-test) and by the VM.

**File:** [`container.txt`](container.txt): schema check, C and Python record tests, the C→Python cross-check, both planted-bug sweeps, and the end-to-end test.

## What changed
1. **Schema:** NET v2 = v1 + `reserved` (u16, zero) + `tcp_isn` (u32), still 104 bytes. Flag `P15_F_ISN` (bit 2) marks the ISN valid. NET v1 stays readable.
2. **BPF** (`net.bpf.c`):
   - **accept:** `copied_seq − 1` from `bpf_skc_to_tcp_sock` of the new socket;
   - **connect:** `write_seq − 1`, but only when the sequence space shows "exactly the SYN has been queued": `snd_nxt == write_seq` and `snd_una ∈ {write_seq − 1, write_seq}`, on a TCP socket not in repair mode, with `ret` 0 or `-EINPROGRESS`. Otherwise the flag stays unset.
   - **Why that check:** it covers ADR-0022 rule 3's deferred Fast Open case without hard-coding `INET_FLAGS_DEFER_CONNECT`, which is an anonymous enum that CO-RE can't relocate.
3. **Checks, the same in C (`records.c`) and Python (`records.py`):**
   - unknown flag bits are refused;
   - `P15_F_ISN` is refused on anything but NET v2;
   - NET v2 needs `reserved == 0`, and `tcp_isn == 0` when the flag is unset.
4. **Self-test** (ADR-0022 rule 5): the test child's TCP CONNECT and ACCEPT must both carry the flag and equal ISNs. UDP, bind and listen must carry none.
5. **The join** (`p15/net.py`):
   - an equal ISN is an exact match and wins over time;
   - a same-endpoint candidate with a different ISN is a different connection: set aside and counted (`isn_mismatch`);
   - without an ISN on either side, PR #45's window applies, labelled as an inference;
   - TCP records without an ISN are counted (`tcp_without_isn`).
   - Both reports label each join "exact" or "inferred".
6. **End-to-end case 5** now requires both clients to be joined exactly, 0 set aside, and every TCP record to carry its ISN.

## Findings (MEAS, container)
- Schema: 14 records, 0 problems; the lock records NET/5/v2.
- C record tests: 0 failures, 13 new cases.
- Cross-check: a C-written run holding NET v1 and v2 decodes field by field in Python, including an ISN with the top bit set.
- Python tests: 7 new join cases (reused port, mismatch only, fallback either way, ISN 0, outside the window), and Python flag tests matching the C ones.
- Planted bugs: Python 128/128 (10 new), record checks 28/28 (6 new).
- End-to-end: cases 1–4 pass; case 5 is skipped here.

## Not shown here
- That the verifier accepts the new reads on 7.0, and the exact joins on a real run. That is CI's case 5 and the VM's `vm_verify.sh`.
