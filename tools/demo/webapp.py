#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A deliberately vulnerable little web app for the capture demo (docs/demo/README.md). It
listens on 127.0.0.1 only. GET / answers "ok"; GET /lookup?name=X runs `getent hosts X` through
a shell, so a request can inject a command, as a real web shell would. That gives the capture a
known chain to show: web server -> sh -> whatever the request injected.

    python3 tools/demo/webapp.py PORT        (stops after 120 s on its own)
"""
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/lookup":
            name = parse_qs(u.query).get("name", [""])[0]
            # THE BUG, on purpose: user input in a shell command line
            out = subprocess.run(f"getent hosts {name}", shell=True, capture_output=True, text=True, timeout=10).stdout
            body = out or "not found\n"
        else:
            body = "ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        sys.stderr.write("webapp: " + fmt % args + "\n")


if __name__ == "__main__":
    srv = HTTPServer(("127.0.0.1", int(sys.argv[1])), App)
    threading.Timer(120, srv.shutdown).start()
    srv.serve_forever()
