# php2shell — CVE-2026-109618 / CVE-2026-109619

CVE-2026-109618 / CVE-2026-109619 ("php2shell") verification, working PoCs, and detector.
Targets stock PHP 8.4.4 (unpatched), verified live in WSL2 Arch + Docker vanilla images.
Both CVEs are **critical**, fixed in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** by commit `506e87fa7`.

## Contents

| Path | What |
|---|---|
| `php2shell_detect.php` | **On-host definitive probe.** INI-key fingerprint of the fix commit (`memory_hard_limit_percent`) + version map. Verified bidirectionally: VULNERABLE on 8.4.4, PATCHED on 8.4.27. |
| `detector/detect_remote.py` | Remote banner sniff + consent-gated behavior probe (false-positive-safe verdicts). |
| `poc/poc_session_include.py` | Working RCE chain PoC: upload_progress KEY-injection → session poisoning → self-include. `[RCE-OUT]` + `id` output demonstrated. Requires `php_serialize` codec + `upload_progress.cleanup=0` (see Codec Note). |
| `poc/xdos_crossworker.py` | Working cross-worker DoS: worker A poisoned → leaked flock file-write on victim session file (`/proc/locks` evidence) → worker B hangs >12 s on the same SID. |
| `WRITEUP.md` / `ADDENDUM.md` / `SECURITY.md` / `PHP2SHELL-RESEARCH-REPORT.md` | Pre-release verification, official advisory delta, verbatim GHSAs, incident research. |
| `lab/`, `evidence/` | Build scripts, gdb/lldb probes, all raw evidence: 1,213-line lldb trace, 686 KB fix diff, advisory JSONs, flock transcripts, detector verify-on-both-builds transcripts. |

## Detector quickstart

```bash
php php2shell_detect.php                # on-host, definitive
python3 detector/detect_remote.py http://target/   # banner sniff only
python3 detector/detect_remote.py http://target/ --i-own-this-target  # + behavior probe
```

## Codec Note (critical read)

The classic `PHP_SESSION_UPLOAD_PROGRESS` key-suffix forge assumes the `php`
session codec. **In stock 8.4.4 the `php` codec rejects any key containing `|`**
(`memchr` at `ext/session/session.c:1061`): the entire encode returns NULL,
the file write is truncated to zero — so the forge as commonly described *cannot
persist* on stock PHP's default codec. A working chain on the unpatched binary
must use `session.serialize_handler=php_serialize` (which has no `|`-rejection)
plus `session.upload_progress.cleanup=0` (prevents the progress key from being
deleted at EVENT_END). A Docker-vs-vanilla test matrix covering this is in
`docker/`.

## Status notes

- The circulated Zer061/jackalsyn "upload_progress UAF" bundle is **refuted on
  stock PHP** (its claimed cached-pointer UAF has not existed since PHP 5.4).
- The vendor's RCE claim is end-to-end conditional on "strategically crafted heap
  layout" grooming (mod_php prefork / FPM pool) — an exploit-research stage, not
  a script. No public artifact demonstrably reproduces that at the time of writing.
