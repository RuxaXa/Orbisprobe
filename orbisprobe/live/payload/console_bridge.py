#!/usr/bin/env python3
"""console_bridge.py — bidirectional relay for the LIVE0 adapter (runs on the LAN worker).

The console's payload can only reach the LAN; it cannot route back into the Hermes segment. This
bridge therefore listens twice:

    0.0.0.0:9025  <- the on-console payload connects here
    127.0.0.1:9026 <- the host connects here (through an SSH local forward)

and splices the two sockets byte for byte. It is read/write transparent: it never parses, stores or
modifies the frame stream, so it cannot alter evidence.

Usage:  python3 console_bridge.py [payload_port] [host_port] [lifetime_s] [logfile]
"""

from __future__ import annotations

import socket
import sys
import threading
import time

PAYLOAD_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9025
HOST_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9026
LIFETIME = float(sys.argv[3]) if len(sys.argv) > 3 else 1200.0
LOG = sys.argv[4] if len(sys.argv) > 4 else "/tmp/console_bridge.log"


def log(message: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(f"[{stamp}] {message}\n")


def pump(src: socket.socket, dst: socket.socket, label: str) -> None:
    total = 0
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            total += len(chunk)
    except OSError as exc:
        log(f"{label}: {type(exc).__name__}: {exc}")
    finally:
        log(f"{label}: closed after {total} bytes")
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> int:
    payload_listener = socket.socket()
    payload_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    payload_listener.bind(("0.0.0.0", PAYLOAD_PORT))
    payload_listener.listen(1)
    host_listener = socket.socket()
    host_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_listener.bind(("127.0.0.1", HOST_PORT))
    host_listener.listen(1)
    deadline = time.time() + LIFETIME
    payload_listener.settimeout(max(1.0, LIFETIME))
    host_listener.settimeout(max(1.0, LIFETIME))
    log(f"BRIDGE-READY payload_port={PAYLOAD_PORT} host_port={HOST_PORT} lifetime={LIFETIME}s")

    while time.time() < deadline:
        try:
            payload_sock, payload_addr = payload_listener.accept()
        except OSError:
            break
        log(f"payload connected from {payload_addr[0]}:{payload_addr[1]}")
        host_sock = None
        host_listener.settimeout(60.0)
        try:
            host_sock, host_addr = host_listener.accept()
            log(f"host connected from {host_addr[0]}:{host_addr[1]}")
        except OSError:
            log("no host connection within 60s; closing payload")
            payload_sock.close()
            host_listener.settimeout(max(1.0, deadline - time.time()))
            continue
        payload_sock.settimeout(None)
        host_sock.settimeout(None)
        t1 = threading.Thread(target=pump, args=(payload_sock, host_sock, "payload->host"), daemon=True)
        t2 = threading.Thread(target=pump, args=(host_sock, payload_sock, "host->payload"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        log("session finished")
        host_listener.settimeout(max(1.0, deadline - time.time()))
    log("BRIDGE-END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
