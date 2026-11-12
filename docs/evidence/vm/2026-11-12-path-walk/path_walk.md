# path_walk: the dentry walk against bpf_d_path (gate 2)

dir=/var/tmp/p15-path-walk rounds=20 n=20000 kallsyms_rename_lock=1 kallsyms_mount_lock=1

| case | verdict | expected | walk's flags | bpf_d_path | walk |
|---|---|---|---|---|---|
| plain | equal | equal | - | `/var/tmp/p15-path-walk/plain/a/b/c/file` | `/var/tmp/p15-path-walk/plain/a/b/c/file` |
| root | equal | equal | - | `/` | `/` |
| dir | equal | equal | - | `/var/tmp/p15-path-walk` | `/var/tmp/p15-path-walk` |
| proc | equal | equal | - | `/proc/49360/status` | `/proc/49360/status` |
| sysfs | equal | equal | - | `/sys/kernel/mm/transparent_hugepage/enabled` | `/sys/kernel/mm/transparent_hugepage/enabled` |
| devtmpfs | equal | equal | - | `/dev/null` | `/dev/null` |
| deep40 | equal | equal | - | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` |
| deep70 | flagged | flagged | TRUNCATED | `/var/tmp/p15-path-walk/deep/d00/d01/d02/d03/d04/d05/d06/d07/` | `/d07/d08/d09/d10/d11/d12/d13/d14/d15/d16/d17/d18/d19/d20/d21` |
| longnames | equal | equal | - | `/var/tmp/p15-path-walk/long/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn` | `/var/tmp/p15-path-walk/long/nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn` |
| tmpfs | equal | equal | - | `/var/tmp/p15-path-walk/tmpfs/sub/file` | `/var/tmp/p15-path-walk/tmpfs/sub/file` |
| bind | equal | equal | - | `/var/tmp/p15-path-walk/bound/b/c/file` | `/var/tmp/p15-path-walk/bound/b/c/file` |
| overlay | equal | equal | NOT_UNDER_ROOT | `/low` | `/low` |
| deleted | equal | equal | DELETED | `/var/tmp/p15-path-walk/gone_(deleted)` | `/var/tmp/p15-path-walk/gone_(deleted)` |
| memfd | flagged | equal | DNAME | `/memfd:p15memfd_(deleted)` | `` |
| pipe | flagged | flagged | DNAME | `pipe:[124018]` | `` |
| chroot | equal | equal | - | `/a/b/c/file` | `/a/b/c/file` |

Rename race: 20,000 opens against 3,818 renames on another CPU; 19,927 samples: 19,693 equal, 95 flagged, 139 not compared (the tree moved between bpf_d_path and the walk) (95 RACED after the retry; 97 needed the retry), **0 wrong without a flag**; bpf_d_path failed 0, opens failed 74.

Samples the ring had no room for (fentry, all parts): 0. Flags the walk set in the kprobe.session: TRUNCATED,RACED,DNAME,DELETED,NOT_UNDER_ROOT,RETRIED.

| path | rounds | bpf_d_path (fentry) | walk (fentry) | walk (kprobe.session) |
|---|---|---|---|---|
| short | 20 | 156.3 ns | 246.6 ns | 233.2 ns |
| deep20 | 20 | 310.1 ns | 518.4 ns | 509.8 ns |

## Verdict

- PASS: no case and no race sample gave a wrong path without a flag
- note: case memfd: flagged, expected equal
