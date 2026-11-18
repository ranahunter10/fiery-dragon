# SPDX-License-Identifier: MIT
"""tools/workloads: strace's log read as facts (oracle.py), and the comparison with a graph
(compare.py) on a hand-made graph with only the tables it reads."""

import sys
import unittest
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))
import compare as C  # noqa: E402
import oracle as O  # noqa: E402

# A thread (102) prints a call before its parent's clone3 returns; an unfinished/resumed pair;
# sockets, a pipe and a device in -yy decorations; an O_PATH open; a failed open; a refused and an
# in-progress connect; an AF_UNIX connect; copy_file_range; sendmmsg; an exec that failed.
LOG = """\
100 1.000001 execve("/usr/bin/bash", [...], 0x1 /* 3 vars */) = 0
102 1.000002 openat(AT_FDCWD</w>, "t.txt", O_RDONLY) = 4</w/t.txt>
100 1.000003 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0} => {parent_tid=[102]}, 88) = 102
100 1.000004 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 101
101 1.000005 execve("./no", [...], 0x1 /* 3 vars */) = -1 ENOENT (No such file or directory)
101 1.000006 execve("/usr/bin/cat", [...], 0x1 /* 3 vars */) = 0
101 1.000007 openat(AT_FDCWD</w>, "a b, c", O_RDONLY <unfinished ...>
100 1.000008 read(0<pipe:[77]>, ""..., 10) = 7
101 1.000009 <... openat resumed>) = 3</w/a b, c>
101 1.000010 read(3</w/a b, c>, ""..., 4096) = 100
101 1.000011 write(1</dev/null<char 1:3>>, ""..., 100) = 100
101 1.000012 openat(AT_FDCWD</w>, "gone", O_RDONLY) = -1 ENOENT (No such file or directory)
101 1.000013 openat(AT_FDCWD</w>, "d", O_RDONLY|O_PATH|O_DIRECTORY) = 5</w/d>
102 1.000014 connect(6<TCP:[9]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)
102 1.000015 connect(7<TCP:[10]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (Operation now in progress)
102 1.000016 connect(8<UNIX:[11]>, {sa_family=AF_UNIX, sun_path="/run/x"}, 110) = 0
102 1.000017 sendto(7<TCPv6:[::1:5->::1:443]>, ""..., 50, 0, NULL, 0) = 50
102 1.000018 write(7<TCPv6:[::1:5->::1:443]>, ""..., 20) = 20
102 1.000019 recvfrom(7<TCPv6:[::1:5->::1:443]>, ""..., 64, 0, NULL, NULL) = 64
102 1.000020 sendmmsg(9<UDP:[12]>, [...], 2, 0) = 2
101 1.000021 copy_file_range(3</w/a b, c>, NULL, 4</w/o>, NULL, 1000, 0) = 1000
101 1.000022 splice(3</w/a b, c>, NULL, 5<pipe:[78]>, NULL, 1048576, 0) = 30
101 1.000023 splice(4<pipe:[78]>, NULL, 1<TCP:[127.0.0.1:5->127.0.0.1:9]>, NULL, 30, 0) = 30
101 1.000024 sendfile(1<TCP:[127.0.0.1:5->127.0.0.1:9]>, 3</w/a b, c>, NULL, 12) = 12
100 1.000022 accept4(10<TCP:[13]>, NULL, NULL, SOCK_CLOEXEC) = 11<TCP:[127.0.0.1:80->127.0.0.1:5]>
101 1.000023 exit_group(0) = ?
101 1.000024 +++ exited with 0 +++
"""


class Oracle(unittest.TestCase):
    def setUp(self):
        self.f = O.parse(LOG.splitlines(True))

    def test_groups_threads_even_when_printed_before_the_clone(self):
        self.assertEqual(self.f.root, 100)
        self.assertEqual(self.f.procs, {100, 101})
        self.assertEqual(self.f.clones, {(100, 101)})
        self.assertEqual(self.f.counts["thread"], 1)

    def test_execs_opens_and_what_is_kept_apart(self):
        self.assertEqual(self.f.execs, {(100, "/usr/bin/bash"), (101, "/usr/bin/cat")})
        self.assertEqual(self.f.counts["exec_failed"], 1)
        self.assertEqual(self.f.opens, {(100, "/w/t.txt"), (101, "/w/a b, c")})     # the thread's open is its group's
        self.assertEqual(self.f.opath, {(101, "/w/d")})
        self.assertEqual(self.f.counts["open_failed"], 1)
        self.assertEqual(self.f.counts["no_result"], 1)

    def test_connects_accepts_and_bytes(self):
        self.assertEqual(sorted(self.f.connects), [(100, "AF_INET", 80, "ECONNREFUSED"), (100, "AF_INET6", 443, "EINPROGRESS")])
        self.assertEqual(self.f.unix_connects, 1)
        self.assertEqual(self.f.accepts[100], 1)
        self.assertEqual(dict(self.f.bytes[100]), {"file_read": 7, "sock_send": 70, "sock_recv": 64})
        # the splice and the sendfile into a socket are sends; the splice from a file into a pipe is unseen
        self.assertEqual(dict(self.f.bytes[101]), {"file_read": 100, "file_write": 100, "sock_send": 42})
        self.assertEqual((self.f.unseen["splice"], self.f.unseen_bytes["splice"]), (1, 30))
        self.assertEqual((self.f.counts["splice_to_socket"], self.f.counts["sendfile_to_socket"]), (1, 1))
        self.assertEqual(self.f.counts["mmsg_call"], 1)
        self.assertEqual((self.f.unseen["copy_file_range"], self.f.unseen_bytes["copy_file_range"]), (1, 1000))

    def test_light_trace_has_no_bytes(self):
        f = O.parse(LOG.splitlines(True), light=True)
        self.assertEqual(dict(f.bytes), {})
        self.assertEqual(f.opens, self.f.opens)

    def test_decorations(self):
        self.assertEqual(O.fd_target("1</dev/null<char 1:3>>"), "/dev/null")
        self.assertEqual(O.fd_target("3<TCP:[1.2.3.4:5->6.7.8.9:10]>"), "TCP:[1.2.3.4:5->6.7.8.9:10]")
        self.assertTrue(O.is_sock("UNIX-STREAM:[5->6]"))
        self.assertFalse(O.is_sock("pipe:[77]"))
        self.assertEqual(O.split_first_arg('3</a, b>, "x, y", 4'), ("3</a, b>", '"x, y", 4'))


def graph(missing_open=False, wrong_bytes=False):
    """The tables compare.py reads, for the log above: procs 100 and 101, the clone, both execs,
    the opens, both connects, the accept and the transfers."""
    con = duckdb.connect()
    con.execute("CREATE TABLE proc (node_id BIGINT, tgid UINTEGER, start_ns UBIGINT, parent_node BIGINT, fork_ns UBIGINT)")
    con.execute("INSERT INTO proc VALUES (1, 100, 5, NULL, NULL), (2, 101, 6, 1, 6)")
    con.execute("CREATE TABLE proc_image (node_id BIGINT, seen_in VARCHAR, filename VARCHAR)")
    con.execute("INSERT INTO proc_image VALUES (1, 'exec', '/usr/bin/bash'), (2, 'exec', '/usr/bin/cat')")
    con.execute("CREATE TABLE openfile (fid UBIGINT, path VARCHAR, file_node BIGINT, first_ns UBIGINT)")
    con.execute("INSERT INTO openfile VALUES (1, '/w/t.txt', 10, 1), (2, '/w/a b, c', 11, 2), (3, '/usr/bin/cat', 12, 3)")
    con.execute("CREATE TABLE file (node_id BIGINT, path VARCHAR, first_ns UBIGINT)")
    con.execute("INSERT INTO file VALUES (14, '/memfd:x (deleted)', 4)")
    con.execute("INSERT INTO openfile VALUES (4, '/memfd:x (deleted)', 14, 4)")
    con.execute("CREATE TABLE sock (node_id BIGINT, lport USMALLINT)")
    con.execute("INSERT INTO sock VALUES (20, 0), (21, 0), (22, 80)")
    con.execute("CREATE TABLE raw_net (ring UTINYINT, seq UBIGINT, tgid UINTEGER, family USMALLINT, rport USMALLINT, ret INTEGER)")
    con.execute("INSERT INTO raw_net VALUES (1, 1, 100, 2, 80, -111), (1, 2, 100, 10, 443, -115)")
    con.execute("CREATE TABLE raw_rename (new_comm BLOB)")
    con.execute("""CREATE TABLE edge (src BIGINT, dst BIGINT, op VARCHAR, ok BOOLEAN, fid UBIGINT, ring UTINYINT,
                   seq UBIGINT, bytes UBIGINT, ts_ns UBIGINT, end_ns UBIGINT)""")
    rows = [(1, 2, "CLONE", True, None, 0, 0, None), (12, 2, "OPEN", True, 3, 0, 0, None),
            (1, 20, "CONNECT", False, None, 1, 1, None), (1, 21, "CONNECT", True, None, 1, 2, None),
            (22, 1, "ACCEPT", True, None, 0, 0, None),
            (77, 1, "READ", True, None, 0, 0, 7), (1, 21, "SEND", True, None, 0, 0, 70), (21, 1, "RECV", True, None, 0, 0, 64),
            (11, 2, "READ", True, None, 0, 0, 100), (2, 13, "WRITE", True, None, 0, 0, 99 if wrong_bytes else 100),
            (2, 21, "SEND", True, None, 0, 0, 42)]
    if not missing_open:
        rows += [(10, 1, "OPEN", True, 1, 0, 0, None)]
    rows += [(11, 2, "OPEN", True, 2, 0, 0, None)]
    # cat (101) also ran a memfd through /proc/self/fd: the kernel's open of it is an expected extra
    rows += [(14, 2, "EXECUTE", True, None, 0, 0, None), (14, 2, "OPEN", True, 4, 0, 0, None)]
    con.executemany("INSERT INTO edge VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1)", rows)
    return con


class Compare(unittest.TestCase):
    def test_everything_found_and_the_exec_open_is_an_expected_extra(self):
        r = C.compare(graph(), O.parse(LOG.splitlines(True)), None, 0)
        bad, gaps = C.verdict(r)
        self.assertEqual(bad, [])
        for k in ("processes", "clone_edges", "execs", "opens", "connects", "accepts"):
            self.assertEqual(r["recall"][k]["ratio"], 1.0, k)
        self.assertEqual(r["extra"]["opens"], {"n": 2, "exec_and_interpreter": 2, "other": 0, "other_first": []})
        self.assertEqual(r["bytes"]["sock_send"]["graph"], 112)      # 70 by sendto and write, 42 by splice and sendfile

    def test_a_missing_open_and_a_byte_off_are_named(self):
        r = C.compare(graph(missing_open=True, wrong_bytes=True), O.parse(LOG.splitlines(True)), None, 0)
        bad, _ = C.verdict(r)
        self.assertEqual(r["recall"]["opens"]["missed"], [[100, "/w/t.txt"]])
        self.assertEqual(r["bytes"]["file_write"]["differ"], [[101, 100, 99]])
        self.assertEqual(len(bad), 2)


if __name__ == "__main__":
    unittest.main()
