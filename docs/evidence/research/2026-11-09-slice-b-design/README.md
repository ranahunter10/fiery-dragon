# Slice B design checks: raw output (2026-11-09)

Evidence for [`docs/research/2026-11-09-slice-b-design-checks.md`](../../../research/2026-11-09-slice-b-design-checks.md), ADR-0005 and ADR-0015.

| File | What | Where it ran |
|---|---|---|
| `container-btf.txt` | Which planned hook functions the kernel's BTF has, and `struct backing_file` as BTF shows it | dev container, kernel 6.18.44 (not the target), with the vendored bpftool v7.7.0 (`make` builds it) |
| `vm-sliceb-attach.txt` | For 7.0.0-38: each planned hook function in BTF and in `available_filter_functions`, the tracepoints, the config options, module BTF, and `struct backing_file` | VM p15-dev-2604, 2026-11-09 13:27 UTC, `sudo tools/vm/sliceb_attach_check.sh ~/sliceb-attach.txt` at commit `cbecb00` or later on the PR branch; sent by the maintainer (sha256 `306b3d52…146d`) |

`tools/vm/sliceb_attach_check.sh` stops with an error in the dev container: its `available_filter_functions` cannot be read there, and the script refuses to report a column it could not read. That is why the container file was made with the two `bpftool` commands named in its header.

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).
