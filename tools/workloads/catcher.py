# SPDX-License-Identifier: MIT
"""A stand-in for an attacker's machine, on loopback: listen on PORT, say so by creating READY,
accept one connection, send SEND's contents if given (a controller's commands), then read until
the peer closes and keep every byte in OUT.

    python3 catcher.py PORT OUT READY [SEND]
"""
import socket
import sys
from pathlib import Path

port, out, ready = int(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
send = Path(sys.argv[4]).read_bytes() if len(sys.argv) > 4 else b""
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
ready.write_text("ready\n")
c, _ = s.accept()
if send:
    c.sendall(send)
got = bytearray()
while True:
    b = c.recv(65536)
    if not b:
        break
    got += b
out.write_bytes(bytes(got))
print(f"catcher {port}: {len(got)} bytes")
