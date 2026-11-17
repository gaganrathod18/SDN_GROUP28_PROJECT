#!/usr/bin/env python3
"""Multi-port TCP service for experiment servers: accept, send a short reply at once, close (never blocks on a client).
    services.py 22,80,443,8080,3306"""
import selectors
import socket
import sys

sel = selectors.DefaultSelector()
for p in sys.argv[1].split(","):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(p)))
    s.listen(4096)
    s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
REPLY = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"
while True:
    for key, _ in sel.select():
        while True:
            try:
                c, _ = key.fileobj.accept()
            except (BlockingIOError, OSError):
                break
            try:
                c.setblocking(False)
                c.send(REPLY)
            except OSError:
                pass
            c.close()
