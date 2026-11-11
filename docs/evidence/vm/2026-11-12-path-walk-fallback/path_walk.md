# path_walk: the dentry walk against bpf_d_path (gate 2)

dir=/var/tmp/p15-path-walk rounds=20 n=20000 kallsyms_rename_lock=1 kallsyms_mount_lock=1

| case | samples | verdict (worst) | expected | walk's flags | bpf_d_path | walk |
|---|---|---|---|---|---|---|
| plain | 1 | equal | equal | - | `/var/tmp/p15-path-walk/plain/a/b/c/file` | `/var/tmp/p15-path-walk/plain/a/b/c/file` |
| root | 1 | equal | equal | - | `/` | `/` |
| dir | 1 | equal | equal | - | `/var/tmp/p15-path-walk` | `/var/tmp/p15-path-walk` |
| proc | 1 | equal | equal | - | `/proc/49604/status` | `/proc/49604/status` |
| sysfs | 1 | equal | equal | - | `/sys/kernel/mm/transparent_hugepage/enabled` | `/sys/kernel/mm/transparent_hugepage/enabled` |
| devtmpfs | 1 | equal | equal | - | `/dev/null` | `/dev/null` |
| deep40 | 1 | equal | equal | - | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` |
| deep70 | 1 | flagged | flagged | TRUNCATED | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` | `/d07/d08/d09/d10/d11/d12/d13/d14/d15/d16/d17/d18/d19/d20/d21` |
| longnames | 1 | equal | equal | - | `/var/tmp/p15-path-walk/long/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn` | `/var/tmp/p15-path-walk/long/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn` |
| tmpfs | 1 | equal | equal | - | `/var/tmp/p15-path-walk/tmpfs/sub/file` | `/var/tmp/p15-path-walk/tmpfs/sub/file` |
| bind | 1 | equal | equal | - | `/var/tmp/p15-path-walk/bound/b/c/file` | `/var/tmp/p15-path-walk/bound/b/c/file` |
| overlay | 2 | equal | equal | - | `/var/tmp/p15-path-walk/ovl/m/low` | `/var/tmp/p15-path-walk/ovl/m/low` |
| ... sample 1 | | equal | | NOT_UNDER_ROOT | `/low` | `/low` |
| deleted | 1 | equal | equal | DELETED | `/var/tmp/p15-path-walk/gone_(deleted)` | `/var/tmp/p15-path-walk/gone_(deleted)` |
| memfd | 1 | equal | equal | DNAME,SYNTH | `/memfd:p15memfd_(deleted)` | `/memfd:p15memfd_(deleted)` |
| pipe | 1 | equal | equal | DNAME,SYNTH | `pipe:[124327]` | `pipe:[124327]` |
| socket | 1 | equal | equal | DNAME,SYNTH | `socket:[124328]` | `socket:[124328]` |
| eventfd | 1 | equal | equal | DNAME,SYNTH | `anon_inode:[eventfd]` | `anon_inode:[eventfd]` |
| chroot | 1 | equal | equal | - | `/a/b/c/file` | `/a/b/c/file` |

Rename race: 20,000 opens against 3,742 renames on another CPU; 19,904 samples: 19,622 equal, 105 flagged, 177 not compared (the tree moved between bpf_d_path and the walk) (106 RACED after the retry; 129 needed the retry), **0 wrong without a flag**; bpf_d_path failed 0, opens failed 96.

Samples the ring had no room for (fentry, all parts): 0. Flags the walk set in the kprobe.session: TRUNCATED,RACED,DNAME,DELETED,NOT_UNDER_ROOT,RETRIED,SYNTH.

| path | rounds | bpf_d_path (fentry) | walk (fentry) | walk (kprobe.session) |
|---|---|---|---|---|
| short | 20 | 157.0 ns | 228.9 ns | 245.1 ns |
| deep20 | 20 | 314.0 ns | 506.1 ns | 515.4 ns |

## Verdict

- PASS: no case and no race sample gave a wrong path without a flag
