# Slice B map sizing: raw output (2026-11-10)

Evidence for STATE decision "Map sizes" (step 2a, ADR-0015 rule 9) and E-0142.

| File | What | Where it ran |
|---|---|---|
| `sliceb-sizing.txt` | Memory, `vfs_cache_pressure`, loaded overlay/btrfs/xfs modules (none), the mkfs tools present, mounted filesystem types, and `/proc/sys/fs/file-nr` and `inode-nr` once a second for 90 s while `find /usr/lib -xdev -type f -readable -exec cat {} +` read every readable file under `/usr/lib` into `/dev/null` (from second 10 to `LOAD DONE`) | VM p15-dev-2604, 2026-11-09 22:43 UTC, the read-only command block given in chat on 2026-11-10; sent by the maintainer. The sha256 the VM printed begins `7c98020adafe62deb3` (the paste was cut there), which matches the committed file's first 18 hex digits |

What it shows (MEAS): open `struct file`s system-wide stay at 1,044-1,070; in-memory inodes rise from 37,125 to 65,300 while the files under `/usr/lib` are opened and read, and stay there after the load ends (the inode cache keeps them). No overlay, btrfs or xfs module was loaded; `mkfs.btrfs` and `mkfs.xfs` are installed.

`SHA256SUMS` covers every file here (`sha256sum -c SHA256SUMS`).
