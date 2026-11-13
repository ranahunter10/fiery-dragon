-- SPDX-License-Identifier: MIT
-- Graph v0 (ADR-0028): the provenance graph of one run, built from the raw record tables
-- (schema/generated/p15_records.sql) and the process tree (`proc_src`, filled by build.py from
-- p15/proctree.py). A star: the hub `node`, its dimensions `proc`, `file`, `sock`, the open-file
-- dimension `openfile`, and the fact table `edge`.
--
-- Rules, each with the ADR that decides it:
--   process node = (tgid, start_ns)                                    ADR-0009
--   file node    = the reader's trust table over the object's facts    ADR-0015 rule 3, decision 3
--   anonymous-inode file node = the open file (fid)                    ADR-0027
--   socket node  = the socket cookie                                   ADR-0004 rule 5
--   an edge points the way information can flow; `ok` says whether the kernel let the operation happen
--   a transfer is an edge over [ts_ns, end_ns] with its bytes and count          ADR-0005 rule 8
-- Nothing is dropped without a row in `graph_count`.
--
-- Needs two scalar functions registered by build.py: p15_text(BLOB) -> VARCHAR (UTF-8 with
-- backslash escapes, as the reader decodes paths) and p15_addr(BLOB, family) -> VARCHAR.

-- ---- constants: include/uapi/linux/magic.h (v7.0), low 32 bits ----
CREATE MACRO m_ext4()  AS 61267;          -- 0xEF53
CREATE MACRO m_xfs()   AS 1481003842;     -- 0x58465342
CREATE MACRO m_tmpfs() AS 16914836;       -- 0x01021994
CREATE MACRO m_btrfs() AS 2435016766;     -- 0x9123683E
CREATE MACRO m_anon()  AS 151263540;      -- 0x09041934

-- ADR-0015 rule 3 / decision 3: filesystems whose (dev, subvol, ino, gen) cannot name two files
-- in one boot. btrfs only when its subvolume was read (oflags bit 0 = SUBVOL_UNKNOWN).
CREATE MACRO fs_trusted(fs_magic, oflags) AS
    fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) OR (fs_magic = m_btrfs() AND (oflags & 1) = 0);

CREATE MACRO file_rule(fid, fs_magic, oflags) AS CASE
    WHEN fs_magic IS NULL THEN 'obj-no-facts'                 -- the record with the facts is not in the run
    WHEN fs_magic = m_anon() AND fid IS NOT NULL THEN 'fid'   -- ADR-0027
    WHEN fs_trusted(fs_magic, oflags) THEN 'tuple'
    ELSE 'obj' END;

CREATE MACRO file_key(fid, obj, fs_magic, oflags, dev, subvol, ino, gen) AS CASE file_rule(fid, fs_magic, oflags)
    WHEN 'fid' THEN 'f:' || fid
    WHEN 'tuple' THEN 't:' || dev || ':' || subvol || ':' || ino || ':' || gen
    ELSE 'o:' || obj END;

CREATE MACRO mode_kind(mode) AS CASE (mode & 61440)           -- S_IFMT
    WHEN 49152 THEN 'socket' WHEN 40960 THEN 'symlink' WHEN 32768 THEN 'file' WHEN 24576 THEN 'block'
    WHEN 16384 THEN 'dir' WHEN 8192 THEN 'char' WHEN 4096 THEN 'pipe' ELSE 'other' END;

-- ---- clock: CLOCK_BOOTTIME -> wall time through the nearest earlier anchor (ADR-0007 L5) ----
CREATE TABLE clock AS
SELECT DISTINCT boottime_ns, realtime_ns FROM (
    SELECT b.value::UBIGINT AS boottime_ns, r.value::UBIGINT AS realtime_ns
    FROM run_meta b JOIN run_meta r USING (seg)
    WHERE b.key = 'clock.boottime_ns' AND r.key = 'clock.realtime_ns'
    UNION ALL SELECT boottime_ns, realtime_ns FROM raw_clock_sync);

-- ---- object facts: one row per object id, from the first record that carried them ----
CREATE TABLE fact_row AS
SELECT obj, ts_ns, ring, seq, facts_ino AS ino, facts_subvol AS subvol, facts_dev AS dev, facts_gen AS gen,
       facts_mode AS mode, facts_fs_magic AS fs_magic, facts_nlink AS nlink, facts_seen AS seen, facts_oflags AS oflags
FROM raw_open WHERE facts_len > 0
UNION ALL
SELECT obj, ts_ns, ring, seq, facts_ino, facts_subvol, facts_dev, facts_gen, facts_mode, facts_fs_magic, facts_nlink,
       facts_seen, facts_oflags
FROM raw_fd WHERE facts_len > 0
UNION ALL
SELECT obj, ts_ns, ring, seq, facts_ino, facts_subvol, facts_dev, facts_gen, facts_mode, facts_fs_magic, facts_nlink,
       facts_seen, facts_oflags
FROM raw_backing WHERE facts_len > 0
UNION ALL
SELECT user_obj, ts_ns, ring, seq, user_facts_ino, user_facts_subvol, user_facts_dev, user_facts_gen, user_facts_mode,
       user_facts_fs_magic, user_facts_nlink, user_facts_seen, user_facts_oflags
FROM raw_backing WHERE user_facts_len > 0
UNION ALL
SELECT obj, ts_ns, ring, seq, facts_ino, facts_subvol, facts_dev, facts_gen, facts_mode, facts_fs_magic, facts_nlink,
       facts_seen, facts_oflags
FROM raw_file WHERE facts_len > 0
UNION ALL
SELECT obj, ts_ns, ring, seq, facts_ino, facts_subvol, facts_dev, facts_gen, facts_mode, facts_fs_magic, facts_nlink,
       facts_seen, facts_oflags
FROM raw_flow WHERE facts_len > 0;

CREATE TABLE obj_facts AS
SELECT * EXCLUDE (ring, seq) FROM fact_row
QUALIFY row_number() OVER (PARTITION BY obj ORDER BY ts_ns, ring, seq) = 1;

-- ---- a socket's file object and its NET records' cookie (ADR-0032) ----
-- FILE v2 carries the cookie the kernel held in the sock when the socket was first seen at a
-- transfer. An object joins the socket node of that cookie when exactly one cookie names it and a
-- NET record names the cookie; anything else keeps its own node and is counted below.
CREATE TABLE sock_obj AS
SELECT obj, min(sock_cookie) AS cookie FROM raw_file WHERE sock_cookie > 0 GROUP BY obj
HAVING count(DISTINCT sock_cookie) = 1 AND min(sock_cookie) IN (SELECT sock_cookie FROM raw_net);

-- ---- openfile: one row per open-file id ----
CREATE TABLE fid_row AS
SELECT fid, obj, ts_ns, ring, seq, tgid, start_ns, f_flags, f_mode, path, 'open' AS how, 1 AS pri FROM raw_open
UNION ALL
SELECT fid, obj, ts_ns, ring, seq, tgid, start_ns, f_flags, f_mode, NULL, 'backing', 1 FROM raw_backing
UNION ALL
SELECT fid, obj, ts_ns, ring, seq, NULL, NULL, f_flags, f_mode, path, 'snapshot', 2 FROM raw_fd
UNION ALL
-- obj 0 in a CLOSE: neither open program computed it (counted in the kernel: E-0190); not an object id
SELECT fid, nullif(obj, 0), ts_ns, ring, seq, NULL, NULL, NULL, f_mode, NULL, 'close-only', 3 FROM raw_close
UNION ALL
-- a file first seen at a transfer (ADR-0015 rule 5): a pipe, socket, memfd or anonymous inode, or a
-- file opened before the capture. Its record holds the dentry's own name, not a path (`name` below).
SELECT fid, obj, ts_ns, ring, seq, tgid, start_ns, f_flags, f_mode, NULL, 'file', 1 FROM raw_file
UNION ALL
-- a transfer's own naming of its open file: the only row of an UNREGISTERED transfer (its fid is
-- fresh, ADR-0015 rule 9) and of one whose OPEN or FILE record is not in the run
SELECT fid, obj, first_ts, ring, seq, NULL, NULL, NULL, NULL, NULL, 'flow', 4 FROM raw_flow;

CREATE TABLE openfile AS
WITH first AS (
    SELECT * FROM fid_row QUALIFY row_number() OVER (PARTITION BY fid ORDER BY pri, ts_ns, ring, seq) = 1
), path AS (
    SELECT fid, p15_text(path) AS path FROM fid_row WHERE octet_length(path) > 0
    QUALIFY row_number() OVER (PARTITION BY fid ORDER BY pri, ts_ns, ring, seq) = 1
), name AS (                         -- the dentry's own name of a file first seen at a transfer
    SELECT fid, p15_text(name) AS name FROM raw_file WHERE octet_length(name) > 0
    QUALIFY row_number() OVER (PARTITION BY fid ORDER BY ts_ns, ring, seq) = 1
), closed AS (
    SELECT fid, min(ts_ns) AS closed_ns, bool_or((fflags & 32) <> 0) AS never_opened FROM raw_close GROUP BY fid
), denied AS (
    SELECT fid, min(verdict) AS verdict FROM (
        SELECT fid, verdict FROM raw_open_verdict
        UNION ALL SELECT fid, verdict FROM raw_open WHERE verdict < 0) GROUP BY fid
)
SELECT f.fid, f.obj, f.how, f.ts_ns AS first_ns, f.tgid AS opener_tgid, f.start_ns AS opener_start_ns,
       f.f_flags, f.f_mode, p.path, nm.name, c.closed_ns, coalesce(c.never_opened, false) AS never_opened,
       coalesce(d.verdict, 0) AS verdict,
       CASE WHEN so.cookie IS NOT NULL THEN 'sock-cookie'
            WHEN f.obj IS NULL THEN 'obj-unknown' ELSE file_rule(f.fid, o.fs_magic, o.oflags) END AS rule,
       CASE WHEN so.cookie IS NOT NULL THEN 's:' || so.cookie   -- the socket node of its NET records (ADR-0032)
            WHEN f.obj IS NULL THEN 'u:' || f.fid      -- no object id at all: a node of its own, never merged
            ELSE file_key(f.fid, f.obj, o.fs_magic, o.oflags, o.dev, o.subvol, o.ino, o.gen) END AS file_key
FROM first f
LEFT JOIN path p USING (fid)
LEFT JOIN name nm USING (fid)
LEFT JOIN closed c USING (fid)
LEFT JOIN denied d USING (fid)
LEFT JOIN obj_facts o ON o.obj = f.obj
LEFT JOIN sock_obj so ON so.obj = f.obj;

-- ---- the file an exec ran: by tuple where the filesystem is trusted, else by the object capture
-- ---- saw with the same (dev, ino, gen) most recently before the exec, else a node of its own ----
CREATE TABLE exec_file AS
WITH e AS (
    SELECT ring, seq, ts_ns, version, exe_dev AS dev, exe_ino AS ino, exe_gen AS gen, exe_fs_magic AS fs_magic
    FROM raw_exec
), m AS (
    SELECT e.ring, e.seq, file_key(NULL, o.obj, o.fs_magic, o.oflags, o.dev, o.subvol, o.ino, o.gen) AS key
    FROM e JOIN obj_facts o ON o.dev = e.dev AND o.ino = e.ino AND o.gen = e.gen AND o.ts_ns <= e.ts_ns
    QUALIFY row_number() OVER (PARTITION BY e.ring, e.seq ORDER BY o.ts_ns DESC, o.obj DESC) = 1
)
SELECT e.ring, e.seq,
       CASE WHEN e.fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) THEN 'tuple'
            WHEN m.key IS NOT NULL THEN 'object-match' ELSE 'unjoined' END AS how,
       CASE WHEN e.fs_magic IN (m_ext4(), m_xfs(), m_tmpfs()) THEN 't:' || e.dev || ':0:' || e.ino || ':' || e.gen
            WHEN m.key IS NOT NULL THEN m.key
            ELSE 'x:' || e.dev || ':' || e.ino || ':' || e.gen END AS file_key
FROM e LEFT JOIN m USING (ring, seq);

-- ---- file nodes ----
CREATE TABLE file_src AS
WITH from_fid AS (                  -- a socket joined to its cookie is a socket node, not a file node
    SELECT file_key AS key, rule, obj, first_ns, path FROM openfile WHERE rule <> 'sock-cookie'
), from_obj AS (                    -- objects named only as an overlay's user object (no fid of their own here)
    SELECT file_key(NULL, o.obj, o.fs_magic, o.oflags, o.dev, o.subvol, o.ino, o.gen) AS key,
           file_rule(NULL, o.fs_magic, o.oflags) AS rule, o.obj, o.ts_ns AS first_ns, NULL AS path
    FROM obj_facts o WHERE NOT EXISTS (SELECT 1 FROM openfile f WHERE f.obj = o.obj)
), from_exec AS (
    SELECT x.file_key AS key, CASE x.how WHEN 'tuple' THEN 'tuple' WHEN 'unjoined' THEN 'exec-unjoined' END AS rule,
           NULL AS obj, e.ts_ns AS first_ns, NULL AS path
    FROM exec_file x JOIN raw_exec e USING (ring, seq) WHERE x.how <> 'object-match'
), allk AS (
    SELECT * FROM from_fid UNION ALL SELECT * FROM from_obj UNION ALL SELECT * FROM from_exec
)
SELECT key, min(rule) AS rule, min(first_ns) AS first_ns, count(DISTINCT obj) AS n_objs,
       arg_min(path, first_ns) FILTER (WHERE path IS NOT NULL) AS open_path,
       arg_min(obj, first_ns) FILTER (WHERE obj IS NOT NULL) AS first_obj
FROM allk GROUP BY key;

-- the name an exec gave for a file: what execve was called with, which may be relative. Used as
-- the node's path only when no open or snapshot row gave the kernel's own path.
CREATE TABLE exec_name AS
SELECT x.file_key AS key, arg_min(p15_text(e.filename), e.ts_ns) AS name
FROM exec_file x JOIN raw_exec e USING (ring, seq) WHERE octet_length(e.filename) > 0 GROUP BY x.file_key;

-- ---- socket nodes ----
CREATE TABLE sock_src AS
WITH r AS (
    SELECT sock_cookie AS cookie, ts_ns, ring, seq, op, proto, family, netns, peer_cookie, ret,
           p15_addr(laddr, family) AS laddr, lport, p15_addr(raddr, family) AS raddr, rport
    FROM raw_net
), first AS (                       -- the row that says most: a connection row before a listen or bind
    SELECT * FROM r QUALIFY row_number() OVER (PARTITION BY cookie ORDER BY (op IN (1, 2)) DESC, ts_ns, seq) = 1
)
SELECT f.cookie, 's:' || f.cookie AS key, f.proto, f.family, f.netns, f.laddr, f.lport, f.raddr, f.rport,
       (SELECT min(ts_ns) FROM r WHERE r.cookie = f.cookie) AS first_ns,
       nullif((SELECT max(peer_cookie) FROM r WHERE r.cookie = f.cookie), 0) AS listener_cookie,
       (SELECT bool_or(op = 3 AND ret = 0) FROM r WHERE r.cookie = f.cookie) AS listening
FROM first f;

-- ---- the hub: one id space for every node, in a fixed order ----
CREATE TABLE node AS
SELECT (row_number() OVER (ORDER BY kind_order, first_ns, key))::BIGINT AS node_id, kind, key, first_ns
FROM (
    SELECT 1 AS kind_order, 'proc' AS kind, 'p:' || tgid || ':' || start_ns AS key, first_ns FROM proc_src
    UNION ALL SELECT 2, 'file', key, first_ns FROM file_src
    UNION ALL SELECT 3, 'sock', key, first_ns FROM sock_src);

CREATE TABLE proc AS
SELECT n.node_id, s.tgid, s.start_ns, pn.node_id AS parent_node, s.fork_ns, s.exit_ns, s.exit_code, s.exe_path,
       s.cmd, s.comm, s.origin, s.kthread, s.in_gap, s.n_images
FROM proc_src s
JOIN node n ON n.key = 'p:' || s.tgid || ':' || s.start_ns
LEFT JOIN node pn ON pn.key = 'p:' || s.parent_tgid || ':' || s.parent_start_ns;

-- a process's programs over time (ADR-0031): image i is in effect from valid_from until image i+1's.
-- exe_node: the file node of the EXECUTE edge that started an exec image (NULL for snapshot and fork rows)
CREATE TABLE proc_image AS
SELECT n.node_id, i.image_no, i.valid_from, i.ts_ns, i.seen_in, i.filename, i.cmd, i.truncated,
       i.exe_major, i.exe_minor, i.exe_ino, i.backing, NULL::BIGINT AS exe_node
FROM image_src i JOIN node n ON n.key = 'p:' || i.tgid || ':' || i.start_ns
ORDER BY n.node_id, i.image_no;

-- a thread's own names (ADR-0031): renames of a thread other than the leader, which name the thread,
-- not the process (prctl PR_SET_NAME, /proc/PID/task/TID/comm)
CREATE TABLE thread_name AS
SELECT n.node_id, r.tid, r.ts_ns, p15_comm(r.old_comm) AS old_comm, p15_comm(r.new_comm) AS new_comm, r.ring, r.seq
FROM raw_rename r JOIN node n ON n.key = 'p:' || r.tgid || ':' || r.start_ns
WHERE r.tid <> r.tgid
ORDER BY r.ts_ns, r.seq;

CREATE TABLE file AS
SELECT n.node_id, s.key, s.rule, coalesce(s.open_path, x.name) AS path,
       CASE WHEN s.open_path IS NOT NULL THEN 'kernel' WHEN x.name IS NOT NULL THEN 'exec-argument' END AS path_from,
       o.dev, o.subvol, o.ino, o.gen, o.mode, o.fs_magic, o.nlink,
       CASE WHEN o.mode IS NULL THEN NULL ELSE mode_kind(o.mode) END AS kind, s.n_objs, s.first_ns
FROM file_src s JOIN node n ON n.key = s.key LEFT JOIN obj_facts o ON o.obj = s.first_obj
LEFT JOIN exec_name x ON x.key = s.key;

CREATE TABLE sock AS
SELECT n.node_id, s.cookie, s.proto, s.family, s.netns, s.laddr, s.lport, s.raddr, s.rport, s.listening,
       ln.node_id AS listener_node
FROM sock_src s JOIN node n ON n.key = s.key LEFT JOIN node ln ON ln.key = 's:' || s.listener_cookie;

ALTER TABLE openfile ADD COLUMN file_node BIGINT;
UPDATE openfile SET file_node = n.node_id FROM node n WHERE n.key = openfile.file_key;

-- the dentry's own name of a file node first seen at a transfer: a last component, never a path
ALTER TABLE file ADD COLUMN name VARCHAR;
UPDATE file SET name = x.name
FROM (SELECT file_node, arg_min(name, first_ns) AS name FROM openfile WHERE name IS NOT NULL GROUP BY file_node) x
WHERE x.file_node = file.node_id;

-- an overlay file and the real file that stands for it (ADR-0015 rule 4): a relation, not a flow
CREATE TABLE file_backing AS
SELECT DISTINCT fo.file_node AS real_node, un.node_id AS user_node
FROM raw_backing b
JOIN openfile fo ON fo.fid = b.fid
JOIN obj_facts uo ON uo.obj = b.user_obj
JOIN node un ON un.key = file_key(NULL, uo.obj, uo.fs_magic, uo.oflags, uo.dev, uo.subvol, uo.ino, uo.gen);

-- a TCP connection's two sockets on this host, joined exactly by the client ISN (ADR-0022): the
-- same ISN, mirrored endpoints, one network namespace. An inferred join is not written (it is counted).
CREATE TABLE sock_pair AS
SELECT DISTINCT cn.node_id AS client_node, sn.node_id AS server_node
FROM raw_net c JOIN raw_net a
  ON c.op = 1 AND a.op = 2 AND (c.flags & 4) <> 0 AND (a.flags & 4) <> 0 AND c.tcp_isn = a.tcp_isn
 AND c.netns = a.netns AND c.family = a.family AND c.laddr = a.raddr AND c.lport = a.rport
 AND c.raddr = a.laddr AND c.rport = a.lport AND c.ret IN (0, -115) AND a.ret = 0
JOIN node cn ON cn.key = 's:' || c.sock_cookie
JOIN node sn ON sn.key = 's:' || a.sock_cookie;

-- ---- edges: src -> dst is the way information can flow ----
-- An event that happens at one moment has end_ns = ts_ns. A transfer (FLOW) covers [ts_ns, end_ns]:
-- the start of its first event to the end of its last (ADR-0005 rule 8), with the bytes moved and
-- the number of events folded into it (1 until step 2c).
CREATE TABLE edge_src AS
SELECT *, ts_ns AS end_ns, NULL::UBIGINT AS bytes, NULL::UINTEGER AS n FROM (
-- a parent's state goes to its child
SELECT ts_ns, 'p:' || tgid || ':' || start_ns AS src, 'p:' || child_tgid || ':' || child_start_ns AS dst,
       'CLONE' AS op, true AS ok, 0 AS ret, NULL::UBIGINT AS fid, NULL AS access, ring, seq
FROM raw_fork WHERE kind = 1
UNION ALL
-- a program file becomes the process's code
SELECT e.ts_ns, x.file_key, 'p:' || e.tgid || ':' || e.start_ns, 'EXECUTE', true, 0, NULL, NULL, e.ring, e.seq
FROM raw_exec e JOIN exec_file x USING (ring, seq)
UNION ALL
-- an open: the file's name, attributes and (if readable) contents become reachable by the process.
-- Bytes are not measured at open: `access` says what the open file allows (f_mode: 1 read, 2 write).
SELECT o.ts_ns, f.file_key, 'p:' || o.tgid || ':' || o.start_ns, 'OPEN',
       f.verdict = 0 AND NOT f.never_opened, f.verdict, o.fid,
       CASE (o.f_mode & 3) WHEN 1 THEN 'r' WHEN 2 THEN 'w' WHEN 3 THEN 'rw' ELSE '-' END, o.ring, o.seq
FROM raw_open o JOIN openfile f USING (fid)
UNION ALL
-- a descriptor already open when a snapshot ran: the first sighting of (process, open file)
SELECT ts_ns, file_key, 'p:' || tgid || ':' || start_ns, 'HELD', true, 0, fid,
       CASE (f_mode & 3) WHEN 1 THEN 'r' WHEN 2 THEN 'w' WHEN 3 THEN 'rw' ELSE '-' END, ring, seq
FROM (SELECT d.*, f.file_key FROM raw_fd d JOIN openfile f USING (fid)
      QUALIFY row_number() OVER (PARTITION BY d.tgid, d.start_ns, d.fid ORDER BY d.ts_ns, d.seq) = 1)
UNION ALL
SELECT ts_ns, 'p:' || tgid || ':' || start_ns, 's:' || sock_cookie, 'CONNECT', ret IN (0, -115), ret, NULL, NULL, ring, seq
FROM raw_net WHERE op = 1
UNION ALL
SELECT ts_ns, 's:' || sock_cookie, 'p:' || tgid || ':' || start_ns, 'ACCEPT', ret = 0, ret, NULL, NULL, ring, seq
FROM raw_net WHERE op = 2
UNION ALL
SELECT ts_ns, 'p:' || tgid || ':' || start_ns, 's:' || sock_cookie, CASE op WHEN 3 THEN 'LISTEN' ELSE 'BIND' END,
       ret = 0, ret, NULL, NULL, ring, seq
FROM raw_net WHERE op IN (3, 4))
UNION ALL
-- a transfer: READ and RECV carry the object's data to the process, WRITE and SEND the process's
-- data to the object (FLOW.kind; ADR-0005 rule 2; the reader's record check refuses any other
-- kind). Only transfers that moved data are recorded (rule 1), so every one happened. The process
-- is the thread group of the first event.
SELECT w.first_ts, CASE WHEN w.kind IN (1, 3) THEN f.file_key ELSE 'p:' || w.tgid || ':' || w.start_ns END,
       CASE WHEN w.kind IN (1, 3) THEN 'p:' || w.tgid || ':' || w.start_ns ELSE f.file_key END,
       CASE w.kind WHEN 1 THEN 'READ' WHEN 2 THEN 'WRITE' WHEN 3 THEN 'RECV' WHEN 4 THEN 'SEND' END,
       true, 0, w.fid, NULL, w.ring, w.seq, w.last_ts, w.bytes, w.count
FROM raw_flow w JOIN openfile f USING (fid);

CREATE TABLE edge_plain AS
SELECT (row_number() OVER (ORDER BY e.ts_ns, e.ring, e.seq, e.op))::BIGINT AS edge_id, e.ts_ns,
       s.node_id AS src, d.node_id AS dst, e.op, e.ok, e.ret, e.fid, e.access, e.ring, e.seq, e.end_ns, e.bytes, e.n
FROM edge_src e JOIN node s ON s.key = e.src JOIN node d ON d.key = e.dst;

-- each end's program at the edge's time (ADR-0031): the image whose valid_from is the latest at or
-- before ts_ns, by ASOF JOIN; NULL when that end is not a process or the process has no image then
CREATE TABLE edge AS
SELECT e.*, si.image_no AS src_image, di.image_no AS dst_image
FROM edge_plain e
ASOF LEFT JOIN proc_image si ON si.node_id = e.src AND e.ts_ns >= si.valid_from
ASOF LEFT JOIN proc_image di ON di.node_id = e.dst AND e.ts_ns >= di.valid_from
ORDER BY e.edge_id;
DROP TABLE edge_plain;

UPDATE proc_image SET exe_node = x.src
FROM edge x WHERE x.op = 'EXECUTE' AND x.dst = proc_image.node_id AND x.ts_ns = proc_image.ts_ns
  AND proc_image.seen_in = 'exec';

-- ---- the books: every case that is counted instead of guessed ----
CREATE TABLE graph_count (name VARCHAR, n BIGINT, meaning VARCHAR);
INSERT INTO graph_count
SELECT 'edge_without_node', (SELECT count(*) FROM edge_src) - (SELECT count(*) FROM edge),
       'edges whose source or destination has no node: must be 0'
UNION ALL SELECT 'obj_facts_conflict', (SELECT count(*) FROM (
        SELECT obj FROM fact_row GROUP BY obj
        HAVING count(DISTINCT (ino, subvol, dev, gen, fs_magic, mode & 61440)) > 1)),
       'object ids whose repeated facts disagree: must be 0 (ADR-0015 falsifier)'
UNION ALL SELECT 'fid_two_objs', (SELECT count(*) FROM (SELECT fid FROM fid_row GROUP BY fid HAVING count(DISTINCT obj) > 1)),
       'open-file ids named with two object ids: must be 0 (ADR-0015 rule 1)'
UNION ALL SELECT 'file_rule_' || rule, count(*), 'file nodes named by this rule (ADR-0015 rule 3, ADR-0027)'
       FROM file_src GROUP BY rule
UNION ALL SELECT 'openfile_' || how, count(*), 'open-file ids first seen this way' FROM openfile GROUP BY how
UNION ALL SELECT 'open_no_path', (SELECT count(*) FROM openfile WHERE how = 'open' AND path IS NULL),
       'opens with no path in the run (PATH_MISSING, PATH_ERROR)'
UNION ALL SELECT 'open_denied', (SELECT count(*) FROM openfile WHERE verdict < 0), 'opens the LSM denied'
UNION ALL SELECT 'open_never_opened', (SELECT count(*) FROM openfile WHERE never_opened),
       'opens that failed in ->open after security_file_open'
UNION ALL SELECT 'exec_file_' || how, count(*), 'execs whose file node was found this way' FROM exec_file GROUP BY how
UNION ALL SELECT 'accept_not_paired', (SELECT count(*) FROM raw_net a WHERE a.op = 2 AND a.ret = 0 AND NOT EXISTS (
        SELECT 1 FROM sock_pair p JOIN node n ON n.node_id = p.server_node WHERE n.key = 's:' || a.sock_cookie)),
       'accepted connections with no exact ISN join to a connect in the run (a remote client, or no ISN)'
UNION ALL SELECT 'edge_' || op || CASE WHEN ok THEN '' ELSE '_failed' END, count(*), 'edges' FROM edge GROUP BY op, ok
UNION ALL SELECT 'node_' || kind, count(*), 'nodes' FROM node GROUP BY kind
UNION ALL SELECT 'image_' || seen_in, count(*), 'process images by where they came from (ADR-0031)'
       FROM proc_image GROUP BY seen_in
UNION ALL SELECT 'image_exec_without_edge', (SELECT count(*) FROM proc_image WHERE seen_in = 'exec' AND exe_node IS NULL),
       'exec images with no EXECUTE edge at their time: must be 0 (ADR-0031)'
UNION ALL SELECT 'edge_proc_end_without_image', (SELECT count(*) FROM edge e JOIN node n ON n.node_id = e.dst
        WHERE n.kind = 'proc' AND e.dst_image IS NULL),
       'edges into a process that had no known program at their time (ADR-0031)'
UNION ALL SELECT 'flow_interval_reversed', (SELECT count(*) FROM raw_flow WHERE last_ts < first_ts),
       'transfers that end before they start: must be 0 (ADR-0005 rule 8)'
UNION ALL SELECT 'flow_unregistered', (SELECT count(*) FROM raw_flow WHERE (fflags & 512) <> 0),
       'transfers on a file with no open-file entry (UNREGISTERED): each names an open file of its own'
UNION ALL SELECT 'flow_start_unknown', (SELECT count(*) FROM raw_flow WHERE (fflags & 4096) <> 0),
       'transfers whose start time was not kept (START_UNKNOWN): their edge starts at its end'
UNION ALL SELECT 'flow_sock_joined', (SELECT count(*) FROM raw_flow w JOIN openfile f USING (fid)
        WHERE w.kind IN (3, 4) AND f.rule = 'sock-cookie'),
       'transfers on a socket whose edge is on the socket node of its NET records (ADR-0032)'
UNION ALL SELECT 'flow_sock_not_joined', (SELECT count(*) FROM raw_flow w LEFT JOIN openfile f USING (fid)
        WHERE w.kind IN (3, 4) AND f.rule IS DISTINCT FROM 'sock-cookie'),
       'transfers on a socket left on the socket''s file object: no cookie when it was first seen, no NET record of the cookie (a socket that never connected, accepted, listened or bound in the run), or two cookies for one object (ADR-0032)'
UNION ALL SELECT 'sock_obj_two_cookies', (SELECT count(*) FROM (SELECT obj FROM raw_file WHERE sock_cookie > 0
        GROUP BY obj HAVING count(DISTINCT sock_cookie) > 1)),
       'socket objects named with two cookies: must be 0 (ADR-0032 falsifier)'
UNION ALL SELECT 'sock_cookie_without_net', (SELECT count(DISTINCT sock_cookie) FROM raw_file
        WHERE sock_cookie > 0 AND sock_cookie NOT IN (SELECT sock_cookie FROM raw_net)),
       'cookies in FILE records that no NET record names (made by another program, or a socket NET does not hook)'
UNION ALL SELECT 'thread_rename', (SELECT count(*) FROM thread_name), 'renames of a thread that is not its process''s leader';

DROP TABLE sock_obj;
DROP TABLE fact_row;
DROP TABLE fid_row;
DROP TABLE edge_src;
DROP TABLE file_src;
DROP TABLE sock_src;
DROP TABLE exec_name;
