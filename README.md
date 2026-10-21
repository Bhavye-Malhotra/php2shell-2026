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
| `cms-lab/poc_vanilla_rce.py` | **Vanilla-stock RCE chain on `php:8.4.26-cli` official image (DEFAULT codec/dom-suite, no php_serialize, no byte-craft, default session codec)**: `upload_progress` filename → SESSION file persists verbatim → app `include()` executes the payload. `uid=0(root)` command output in `cms-lab/RESULTS/rce_proof.txt`. |
| `poc/xdos_crossworker.py` | Working cross-worker DoS: worker A poisoned → leaked flock file-write on victim session file (`/proc/locks` evidence) → worker B hangs >12 s on the same SID. |
| `WRITEUP.md` / `ADDENDUM.md` / `SECURITY.md` / `PHP2SHELL-RESEARCH-REPORT.md` | Pre-release verification, official advisory delta, verbatim GHSAs, incident research. |
| `backports/` | Minimal surgical backport patches for EOL PHP **8.1→5.4** (10 verified `.patch` files): zero `BG(serialize)`/lock before `php_hash_environment()` + `PG(modules_activated)=0` at shutdown end. Each patch `--dry-run`-proven on the official tag; 8.1.33 additionally compiled and smoke-tested.
| `pgwrite/MAPPING.md` | Runtime PG-offset table for the official `php:8.4.26-cli` binary (PG(auto_prepend_file) = core_globals+0xa0 = pie_base+0x16e1380; verified live write on 3 size classes: 1-byte path-char, 4-byte low-half pointer, 8-byte full pointer, two ASLR bases — all producing auto-include on the subsequent request). The exact offset from the Wiz screenshot chain, made reproducible. |
| `fbt/` | **Reproducible Apache/mod_php UAF PoC** for the CVE-2026-109619 strongest-primitive case (`fatal_error_backtraces` + pre-init INI diagnostic consumer): `poc.sh` runs against stock `php:8.5.11-apache` and provokes the worker `AH00052` segfault **4/4 vs 0/4 control**. Source-attributed to fixed-vs-unfixed `EG(last_fatal_error_backtrace)` mismanagement. |
| `matrix/` | Every OOM-test in the vendor patch mapped to remote-reachability + grooming needs, concluding that **no pure-HTTP universal RCE exists on stock 8.4.4 without heap grooming** (rank-1 = rfc1867/upload_progress SID persistence; escalation is environment-dependent). |
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

So: attacker-plausible chain delivery on the vanilla stack now passes through TWO layers:
1. (proven-in-container) `upload_progress` filename ←→ app-side `include()` LFI (this PoC runs on the default `php` codec with ONLY stock defaults — see `cms-lab`); plus
2. (proven-blocked-outlaw) KEY-suffix forge → `$_SESSION['page']` impersonation (killed on BOTH stock codecs by `|` key guard — container proof in `docker/RESULTS/`). This matches the vendor's own framing that
operationally clean RCE is grooming-dependent; nobody with a pure-HTTP demo
contradicts it silently. See `docker/README.md` for the matrix.

## Status notes

- The circulated Zer061/jackalsyn "upload_progress UAF" bundle is **refuted on
  stock PHP** (its claimed cached-pointer UAF has not existed since PHP 5.4).
- The vendor's RCE claim is end-to-end conditional on "strategically crafted heap
  layout" grooming (mod_php prefork / FPM pool) — an exploit-research stage, not
  a script. No public artifact demonstrably reproduces that at the time of writing.
