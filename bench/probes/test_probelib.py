# SPDX-License-Identifier: MIT
"""Tests for probelib.py. Run: python3 -m unittest -v bench/probes/test_probelib.py

test_real_drop_to_nobody needs root (it really calls runuser) and is skipped otherwise.
It is the gate for the 2026-10-25 VM failure: 'runuser' was looked up on the child's
PATH (/usr/bin:/bin), which doesn't contain /usr/sbin."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probelib as P  # noqa: E402


# A real passwd entry for a made-up user 'u' (name, passwd placeholder, uid, gid, gecos, home, shell).
USER_U = P.pwd.struct_passwd(("u", "x", 1000, 1000, "", "/home/u", "/bin/sh"))


class RunAsTest(unittest.TestCase):
    def test_runuser_is_called_by_absolute_path(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(P.shutil, "which", return_value="/usr/sbin/runuser"), \
                mock.patch.object(P.pwd, "getpwnam", return_value=USER_U), \
                mock.patch.object(P.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual(P.run_as("u", ["/x/prog", "1"], Path(d) / "o", 5, Path(d)), 0)
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/runuser", "-u", "u", "--", "/x/prog", "1"])

    def test_missing_runuser_is_an_error_not_a_silent_root_run(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(P.shutil, "which", return_value=None), \
                mock.patch.object(P.subprocess, "run") as run:
            with self.assertRaises(P.ProbeError):
                P.run_as("u", ["/x/prog"], Path(d) / "o", 5, Path(d))
        run.assert_not_called()

    def test_no_user_runs_directly(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(P.subprocess, "run", return_value=mock.Mock(returncode=3)) as run:
            self.assertEqual(P.run_as(None, ["/x/prog"], Path(d) / "o", 5, Path(d)), 3)
        self.assertEqual(run.call_args.args[0], ["/x/prog"])

    @unittest.skipUnless(os.geteuid() == 0, "needs root to call runuser")
    def test_real_drop_to_nobody(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)
            code = P.run_as("nobody", ["/usr/bin/id", "-un"], Path(d) / "o", 10, Path(d))
            self.assertEqual(code, 0)
            self.assertEqual((Path(d) / "o").read_text().strip(), "nobody")


if __name__ == "__main__":
    unittest.main()
