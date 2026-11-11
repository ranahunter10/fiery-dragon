/* SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause */
/*
 * Section timing for bench/open_sections (STATE decision waiting 1): where the file programs' time
 * goes, section by section. Only a build with -DP15_PROFILE has it (build/file_prof.bpf.o); without
 * it PROF_T and PROF_ADD are empty statements and file.bpf.o is unchanged (the harness's README
 * shows how that is checked). p15d never loads the profiled build.
 *
 * PROF_T(v) takes a start time; PROF_ADD(sec, v) adds the time since v and one sample to section sec,
 * for the task the harness names in p15_prof_tgid only (0: every task). Totals are global and
 * atomic: the fentry is preemptible, so two programs can interleave on one CPU (E-0097). A section
 * that was preempted keeps the time the CPU spent elsewhere: the harness runs pinned on an idle VM
 * and reports per-round medians.
 */
#ifndef P15_PROF_H
#define P15_PROF_H

enum p15_prof_sec {
	P15_PROF_EMPTY = 0,      /* a bracket around nothing: the cost of the bracket itself */
	P15_PROF_OPEN_ALL,       /* file_open_path, from its first line to its return (a full OPEN only) */
	P15_PROF_OPEN_CLAIM,     /* ... claiming a scratch slot */
	P15_PROF_OPEN_HDR,       /* ... the record's header (clock, task) */
	P15_PROF_OPEN_FACTS,     /* ... reading the object's facts from the inode */
	P15_PROF_OPEN_OBJ,       /* ... the object map: lookup, insert if new */
	P15_PROF_OPEN_FILE,      /* ... the open-file map: lookup (the session's entry inserted it) */
	P15_PROF_OPEN_DPATH,     /* ... bpf_d_path */
	P15_PROF_OPEN_OUTPUT,    /* ... the copy into the ring (bpf_ringbuf_output, with the wake-up query) */
	P15_PROF_SESS_ENTRY,     /* file_open_session at entry, whole */
	P15_PROF_SESS_FILE,      /* ... the open-file map: insert */
	P15_PROF_SESS_RETURN,    /* file_open_session at return, whole */
	P15_PROF_FREE_ALL,       /* file_free, whole (a registered file only) */
	P15_PROF_FREE_LOOKUP,    /* ... the open-file map: lookup */
	P15_PROF_FREE_RING,      /* ... the CLOSE record: reserve, fill, submit */
	P15_PROF_FREE_DELETE,    /* ... the open-file map: delete */
	P15_PROF__N,
};

#ifdef P15_PROFILE
__u64 p15_prof_ns[P15_PROF__N];
__u64 p15_prof_n[P15_PROF__N];
volatile __u32 p15_prof_tgid;   /* the harness writes its own tgid before it starts timing */

static __always_inline int p15_prof_mine(void)
{
	return !p15_prof_tgid || (__u32)(bpf_get_current_pid_tgid() >> 32) == p15_prof_tgid;
}

#define PROF_T(v) __u64 v = bpf_ktime_get_boot_ns()
#define PROF_ADD(sec, v)                                                                       \
	do {                                                                                   \
		__u64 p15_prof_end_ = bpf_ktime_get_boot_ns();                                 \
		if (p15_prof_mine()) {                                                         \
			__sync_fetch_and_add(&p15_prof_ns[(sec)], p15_prof_end_ - (v));        \
			__sync_fetch_and_add(&p15_prof_n[(sec)], 1);                           \
		}                                                                              \
	} while (0)
#else
#define PROF_T(v) do { } while (0)
#define PROF_ADD(sec, v) do { } while (0)
#endif

#endif /* P15_PROF_H */
