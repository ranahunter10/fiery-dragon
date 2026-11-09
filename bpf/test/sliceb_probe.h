/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * sliceb_probe.h: what sliceb_probe.bpf.c and sliceb_probe.c share. The probe is the step 2a dry
 * run (ADR-0015, STATE decision 19): the identity mechanisms on the target kernel, before the
 * production programs. Its record is the probe's own, not a schema record: it always carries the
 * object facts, so every check can compare them with stat(2).
 */
#ifndef SLICEB_PROBE_H
#define SLICEB_PROBE_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define SBP_PATH_MAX 4096             /* PATH_MAX, include/uapi/linux/limits.h */
#define SBP_NAME_MAX 256              /* the dentry name written when the path is too long */
#define SBP_SLOTS 4                   /* path scratch slots per CPU (ADR-0015 rule 6: claimed per call) */

/* include/linux/fs.h, v7.0 (macros are not in BTF) */
#define SBP_FMODE_OPENED (1u << 19)
#define SBP_FMODE_BACKING (1u << 24)
/* include/uapi/linux/magic.h */
#define SBP_BTRFS_MAGIC 0x9123683Eu
#define SBP_OVERLAY_MAGIC 0x794c7630u

enum sbp_type { SBP_OPEN = 1, SBP_VERDICT = 2, SBP_BACKING = 3, SBP_CLOSE = 4, SBP_FD = 5 };

/* fflags (STATE decision 19.3: slice B flags live in the record, not the header) */
#define SBP_F_OBJ_NEW (1u << 0)         /* first record naming obj: facts are its facts */
#define SBP_F_PATH_MISSING (1u << 1)    /* written by the session return: the fentry did not run */
#define SBP_F_PATH_ERROR (1u << 2)      /* bpf_d_path failed (path_err) other than -ENAMETOOLONG */
#define SBP_F_NEVER_OPENED (1u << 3)    /* CLOSE: FMODE_OPENED was not set (the open failed in ->open) */
#define SBP_F_KTHREAD (1u << 4)         /* written in a kernel thread */
#define SBP_F_SUBVOL_UNKNOWN (1u << 5)  /* btrfs object, btrfs BTF absent at load */
#define SBP_F_TRUNCATED (1u << 6)       /* the path did not fit: path is the dentry name */
#define SBP_F_FULL_SIZE (1u << 7)       /* no scratch slot was free: a full-size record (ADR-0015 rule 6) */
#define SBP_F_OBJ2_NEW (1u << 8)        /* BACKING: facts2 are the overlay object's first facts */

struct sbp_facts {
	__u64 ino;
	__u64 subvol;     /* btrfs root id; 0 elsewhere */
	__u32 dev;        /* i_sb->s_dev, kernel encoding (major << 20 | minor) */
	__u32 gen;        /* i_generation */
	__u32 mode;       /* i_mode */
	__u32 fs_magic;   /* low 32 bits of s_magic */
	__u32 nlink;
	__u32 pad;
};

struct sbp_rec {
	__u16 type;
	__u16 len;        /* bytes of this record, path included */
	__u32 fflags;
	__u32 tgid;
	__u32 tid;
	__u64 fid;
	__u64 obj;
	__u64 obj2;       /* BACKING: the overlay inode's object id */
	__u32 f_flags;
	__u32 f_mode;
	__s32 verdict;    /* the session return's value of security_file_open */
	__s32 path_err;   /* bpf_d_path's error with SBP_F_PATH_ERROR */
	__u32 fd;         /* FD: the descriptor */
	__u32 path_len;   /* path bytes that follow, without a NUL */
	__u64 pos;        /* FD: f_pos */
	struct sbp_facts facts;
	struct sbp_facts facts2;  /* BACKING: the overlay object's facts */
	char path[SBP_PATH_MAX];
};

#define SBP_FIXED ((unsigned)__builtin_offsetof(struct sbp_rec, path))

/* Counters, one u64 each (the probe's books). */
enum sbp_hit {
	H_FENTRY_RUNS,       /* fentry on security_file_open ran for the harness */
	H_SESSION_ENTRY,     /* kprobe.session entry ran for the harness */
	H_SESSION_RETURN,
	H_SESSION_FIRST,     /* at the fentry, the session entry had already run for this call */
	H_FENTRY_FIRST,      /* at the session entry, the fentry had already run */
	H_COMMON,            /* session return: OPEN written by the fentry, verdict 0: nothing to write */
	H_VERDICT,           /* session return wrote OPEN_VERDICT */
	H_MISSING,           /* session return wrote OPEN with PATH_MISSING */
	H_NOCOOKIE,          /* session return with an empty cookie */
	H_RET_NO_ENTRY,      /* session return found no open-file entry */
	H_OPEN_EMITTED,
	H_BACKING_EMITTED,
	H_CLAIM_FAILED,      /* no scratch slot: full-size record */
	H_RESERVE_FAILED,    /* ring full: record lost */
	H_OUTPUT_FAILED,     /* bpf_ringbuf_output refused: record lost */
	H_TRUNCATED,
	H_PATH_ERROR,
	H_FILE_MAP_FULL,
	H_OBJ_MAP_FULL,
	H_FILE_RACE,         /* another program created the entry between lookup and insert */
	H_OBJ_RACE,
	H_FILE_STALE,        /* stored inode address differs from the live file's */
	H_OBJ_STALE,         /* stored dev/ino/gen differ from the live inode's */
	H_FACTS_DUP,         /* a second record carried OBJ_NEW for one object */
	H_CLOSE,
	H_CLOSE_LOST,        /* CLOSE reserve failed */
	H_FREE_UNREGISTERED, /* security_file_free of a file not in the map (system-wide) */
	H_INODE_FREE_HIT,    /* security_inode_free deleted an object entry */
	H_FD_ROWS,
	H_FD_DUP,            /* the FD pass found the file already registered (first registration wins) */
	H_FD_WRITE_FAILED,   /* bpf_seq_write refused an FD row */
	H_N,
};

#endif
