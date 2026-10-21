# php2shell — CVE-2026-109618 / CVE-2026-109619

CVE-2026-109618 / CVE-2026-109619 ("php2shell") verification, working PoCs, and detector.
Targets stock PHP 8.4.4 (unpatched), verified live in WSL2 Arch + Docker vanilla images.
Both CVEs are **critical**, fixed in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** by commit `506e87fa7`.

## Contents

| Path | What |
|---|---|
| `php2shell_detect.php` | **On-host definitive probe.** INI-key fingerprint of the fix commit (`memory_hard_limit_percent`) + version map. Verified bidirectionally: VULNERABLE on 8.4.4, PATCHED on 8.4.27. |
| `detector/detect_remote.py` | Remote banner sniff + consent-gated behavior probe (false-positive-safe verdicts). |
| `poc/poc_session_include.py` | End-to-end chain demonstrator (upload_progress → session poisoning → `include $_SESSION['page']` → `[RCE-OUT]` marker in HTTP response). **Forensic-honest**: THE single pure-HTTP link — `PHP_SESSION_UPLOAD_PROGRESS` key-suffix forge — is proven to be blocked on BOTH stock codecs (`php` codec: `memchr('|')` → encode NULL → 0-byte file; `php_serialize`: forged suffix lands as one length-bound key that decoders can't split). The chain harness therefore performs that one link locally (byte-craft of the forged page variable into the sess file, sanctioned and documented in `poc/PROOFS_session_include.md`), and all remaining steps execute remotely over HTTP. |
| `poc/xdos_crossworker.py` | Working cross-worker DoS: worker A poisoned → leaked flock file-write on victim session file (`/proc/locks` evidence) → worker B hangs >12 s on the same SID. |
| `WRITEUP.md` / `ADDENDUM.md` / `SECURITY.md` / `PHP2SHELL-RESEARCH-REPORT.md` | Pre-release verification, official advisory delta, verbatim GHSAs, incident research. |
| `backports/` | Minimal surgical backport patches for EOL PHP **8.1→5.4** (10 verified `.patch` files): zero `BG(serialize)`/lock before `php_hash_environment()` + `PG(modules_activated)=0` at shutdown end. Each patch `--dry-run`-proven on the official tag; 8.1.33 additionally compiled and smoke-tested.
| `lab/`, `evidence/` | Build scripts, gdb/lldb probes, all raw evidence: 1,213-line lldb trace, 686 KB fix diff, advisory JSONs, flock transcripts, detector verify-on-both-builds transcripts. |

## Detector quickstart

```bash
php php2shell_detect.php                # on-host, definitive
python3 detector/detect_remote.py http://target/   # banner sniff only
python3 detector/detect_remote.py http://target/ --i-own-this-target  # + behavior probe
```

## Codec Note (critical read — verified in Docker, php:8.4.26-cli)

The classic `PHP_SESSION_UPLOAD_PROGRESS` key-suffix forge assumes text-level
injection into the session file. **Verified on stock 8.4.26-cli in this repo's
Docker matrix: the pure-HTTP form of that forge does not survive on ANY stock
session codec:**

- `php` codec (the DEFAULT): any `|` in a session-map key causes the sess encode
  to return NULL (`memchr(key, '|')` at `ext/session/session.c:1061`). The write
  becomes a 0-byte truncation, and any prior progress content disappears — that
  also zeroed the "empty sess file" symptom every pre-release blog discusses.
- `php_serialize` codec (non-default but documented workaround): the wire format
  is one `a:N:{...}` propertied container; a forged suffix becomes a SINGLE long
  KEY — length-bound, not resolvable into an independent `page` variable at decode.

So: attacker-plausible chain delivery on the vanilla stack now passes through
`$_SESSION['page']`-injection in `poc/poc_session_include.py` via a LOCAL forge
(POC-side, documented as such). This matches the vendor's own framing that
operationally clean RCE is grooming-dependent; nobody with a pure-HTTP demo
contradicts it silently. See `docker/README.md` for the matrix.

## Status notes

- The circulated Zer061/jackalsyn "upload_progress UAF" bundle is **refuted on
  stock PHP** (its claimed cached-pointer UAF has not existed since PHP 5.4).
- The vendor's RCE claim is end-to-end conditional on "strategically crafted heap
  layout" grooming (mod_php prefork / FPM pool) — an exploit-research stage, not
  a script. No public artifact demonstrably reproduces that at the time of writing.
