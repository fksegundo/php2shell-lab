# Authorized use only

This repository contains **working exploit code** for two critical PHP
memory-safety vulnerabilities:

- CVE-2026-109618 — RCE via OOM corruption
- CVE-2026-109619 — RCE via stale global state

## Rules of use

1. **Local lab only.** The Docker lab binds every service to `127.0.0.1`.
   Keep it that way.
2. **Only test systems you own** or for which you have explicit, written
   authorization from the system owner.
3. **Do not** use these PoCs against production systems, third-party
   infrastructure, shared hosting, or any system you do not control.
4. **Do not** redistribute the exploit chain as a service or integrate it
   into attack tooling.
5. The vulnerabilities are already public and patched. Prefer updating PHP
   over running the PoC.

## Legal notice

Unauthorized access to computer systems is a crime in many jurisdictions.
In Brazil, depending on the conduct, it may fall under:

- Art. 154-A of the Penal Code (invasão de dispositivo informático);
- Art. 266 of the Penal Code (interrupção ou perturbação de serviço
  telemático ou de informação de utilidade pública);
- The Marco Civil da Internet (Lei 12.965/2014) and related data-protection
  rules.

This is not legal advice. Check your local law and your employer's security
research policy before using this material.

## No warranty

The code is provided "as is", without warranty of any kind. The authors are
not responsible for misuse or for any damage caused by it.

## Disclosure status

The CVEs were disclosed by the PHP project on 2026-10-21 and fixed in PHP
8.2.35, 8.3.36, 8.4.27 and 8.5.12. This lab is for understanding the bugs and
validating the fixes, not for attacking exposed systems.
