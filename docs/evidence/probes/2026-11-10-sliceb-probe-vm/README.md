# Step 2a dry run on the target VM (2026-11-10)

Evidence for E-0146. PR #61 at commit `8a9a62f`, built on the VM with `make -j3 build/sliceb_probe`.

| File | What | Where it ran |
|---|---|---|
| `sliceb-probe.txt` | `sudo build/sliceb_probe --overlay`: 83 checks, 0 failed | VM p15-dev-2604, kernel 7.0.0-38-generic, sent by the maintainer on 2026-11-10 |
| `sliceb-probe-btrfs.txt` | `sudo build/sliceb_probe --btrfs /mnt/p15b/sv` on a 300 MB loop-mounted btrfs image with one subvolume (btrfs loaded by the mount, before the probe): 77 checks, 0 failed | same |

The maintainer sent the files without the sha256 lines the VM printed; `SHA256SUMS` holds the values of the files as received, to be compared with the VM's.

What they show (MEAS, target kernel):
- The verifier accepted all five programs and the kernel attached them; `recursion_misses` 0 for each.
- The session entry ran before the fentry for every open while both were attached (33 of 33; 30 of 30 in the btrfs run).
- ext4 facts match `stat`, `statfs` and `FS_IOC_GETVERSION`; the btrfs subvolume read by CO-RE against the module's BTF is 256, which `statx(STATX_SUBVOL)` also reports.
- ext4 reused inode number 3933265 within the run (the FIFO, then f2) with a different generation; capture gave them different object ids (53 and 81 in `sliceb-probe.txt`).
- Overlay: the merged file's inode reports the lower file's number on overlayfs (dev 0:56); BACKING names it (obj2 89) and the lower file's own object, the id the lower file already had from its creation (obj 83). Mounting the overlay made two opens in the mounting task: the work directory, and an unlinked temporary file whose `d_path` is `/ (deleted)` (path from overlayfs's private mount).
- `dup` shares the open file: fds 1 and 2 have one `fid` (58).
- 21 anonymous-inode descriptors share one object id (59), as on CI (E-0145).
- About 2,370 `security_file_free` calls of files capture never saw ran during the run (system-wide), the free probe's load on an idle VM.
