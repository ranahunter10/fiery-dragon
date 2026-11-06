# SPDX-License-Identifier: MIT
"""Code-provenance derivation (python/p15/provenance.py, ADR-0025): the classes computed from the
raw EXEC v2 / PROC v2 facts. No BPF, no WAL — records built in memory."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p15w_build import rec  # noqa: E402  (inserts python/ on the path)
from p15 import provenance as P  # noqa: E402
from p15 import records as R  # noqa: E402

SOCK, PIPE, FILE, CHR = 0o140666, 0o010600, 0o100644, 0o020666


def dec(b: bytes) -> R.Record:
    return R.decode(memoryview(b), 0, 0, 0)


def exe(**f):
    """An EXEC v2 record with provenance fields; sensible on-disk defaults."""
    base = dict(exe_nlink=1, exe_fs_magic=0xEF53, exe_mode=0o100755, exe_uid=0, exe_gid=0, uid=1000, euid=1000,
                gid=1000, egid=1000, fsuid=1000, fsgid=1000, stdin_mode=CHR, stdout_mode=CHR, stderr_mode=CHR)
    base.update(f)
    return dec(rec("EXEC", **base))


class Backing(unittest.TestCase):
    def test_disk(self):
        self.assertEqual(P.backing(exe()), "disk")

    def test_memory_by_nlink_on_tmpfs(self):
        self.assertEqual(P.backing(exe(exe_nlink=0, exe_fs_magic=P.TMPFS)), "memory")

    def test_memory_by_memfd_name(self):
        r = exe(exe_nlink=0, exe_fs_magic=P.TMPFS, var={"filename": b"/dev/fd/3", "argv": b"x\0",
                                                        "exe_name": b"memfd:payload"})
        self.assertEqual(P.backing(r), "memory")

    def test_tmpfs_linked_is_not_memory(self):
        self.assertEqual(P.backing(exe(exe_nlink=1, exe_fs_magic=P.TMPFS)), "tmpfs")

    def test_deleted(self):
        self.assertEqual(P.backing(exe(exe_nlink=0)), "deleted")

    def test_overlay(self):
        self.assertEqual(P.backing(exe(exe_fs_magic=P.OVERLAYFS)), "overlay")

    def test_kthread_has_no_backing(self):
        r = dec(rec("PROC", kind=1, pflags=R.PROC_KTHREAD))
        self.assertEqual(P.backing(r), "none")


class Streams(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual((P.stream_kind(SOCK), P.stream_kind(PIPE), P.stream_kind(FILE), P.stream_kind(0)),
                         ("socket", "pipe", "file", "closed"))


class Writable(unittest.TestCase):
    def test_root_owned_run_as_root_is_not_flagged(self):
        self.assertFalse(P.runner_can_write(exe(exe_uid=0, fsuid=0, exe_mode=0o100755)))

    def test_owner_writable_run_by_owner(self):
        self.assertTrue(P.runner_can_write(exe(exe_uid=1000, fsuid=1000, exe_mode=0o100755)))

    def test_world_writable(self):
        self.assertTrue(P.runner_can_write(exe(exe_uid=0, fsuid=1000, exe_mode=0o100777)))


class Unusual(unittest.TestCase):
    def test_ordinary_is_quiet(self):
        self.assertEqual(P.unusual(exe(uid=0, euid=0, fsuid=0)), [])

    def test_memfd_reverse_shell(self):
        u = P.unusual(exe(exe_nlink=0, exe_fs_magic=P.TMPFS, uid=0, euid=0, fsuid=0, stdin_mode=SOCK, stdout_mode=SOCK))
        self.assertIn("runs from memory (no file on disk)", u)
        self.assertIn("stdin and stdout are a socket (a shell wired to the network)", u)

    def test_setuid(self):
        self.assertIn("runs as a different user (uid 1000 -> euid 0)", P.unusual(exe(uid=1000, euid=0)))

    def test_only_stdin_socket_is_not_the_both_message(self):
        u = P.unusual(exe(uid=0, euid=0, fsuid=0, stdin_mode=SOCK, stdout_mode=CHR))
        self.assertIn("stdin is a socket", u)
        self.assertNotIn("stdin and stdout are a socket (a shell wired to the network)", u)


class Pipes(unittest.TestCase):
    def test_producer_into_interpreter(self):
        w = exe(stdout_mode=PIPE, stdout_ino=42, stdout_dev=7, var={"filename": b"/usr/bin/curl", "argv": b"curl\0"})
        rdr = exe(stdin_mode=PIPE, stdin_ino=42, stdin_dev=7, var={"filename": b"/usr/bin/python3", "argv": b"python3\0"})
        other = exe(stdin_mode=PIPE, stdin_ino=99, stdin_dev=7)
        links = P.pipe_links([w, rdr, other])
        self.assertEqual(len(links), 1)
        self.assertIs(links[0][0], w)
        self.assertIs(links[0][1], rdr)

    def test_no_false_link_on_zero_inode(self):
        a = exe(stdout_mode=PIPE, stdout_ino=0)
        b = exe(stdin_mode=PIPE, stdin_ino=0)
        self.assertEqual(P.pipe_links([a, b]), [])

    def test_no_self_link(self):
        # a process whose own stdin and stdout are the same pipe must not link to itself
        selfpipe = exe(stdin_mode=PIPE, stdin_ino=55, stdin_dev=7, stdout_mode=PIPE, stdout_ino=55, stdout_dev=7)
        self.assertEqual(P.pipe_links([selfpipe]), [])


if __name__ == "__main__":
    unittest.main()
