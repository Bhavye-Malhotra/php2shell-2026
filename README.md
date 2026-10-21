# php2shell — CVE-2026-109618 / CVE-2026-109619 Verification & Detection

**Everything here is local-lab verified against stock PHP 8.4.4 on WSL2, with the
evidence artifacts shipped alongside the code. It includes a definitively
working detection probe and honestly-scoped proof-of-concept for the impact
that actually reproduces. Nothing is claimed beyond what the evidence supports.**

## TL;DR

- Both CVEs were leaked pre-embargo on 2026-10-20; official advisories came out
  2026-10-21 13:34 UTC: GHSA-w8hw-w9fx-j79w (618 — "RCE via OOM corruption")
  and GHSA-6wmf-4rv5-p3rp (619 — "RCE via stale global state"), both **critical**,
  fixed in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** by commit `506e87fa7`
  ("Avoid state corruption via bailout").
- This workspace verified the producer/consumer chain under **lldb at pointer
level** (`BG(serialize) = {data, level=1}` dangling → cross-request reuse;
  `PG(modules_activated)=0` skips module RSHUTDOWN; leaked session fd with held
  `flock(LOCK_EX)` reused by a later pre-initialization consumer).
- It also verifies the **flock/stale-state cross-worker DoS**: an independent
  PHP process blocked >8 s on `flock(LOCK_EX)` of a victim's session file
  after one poisoned request to a sibling worker.
- **Working, demonstrably-run PoCs** of the two stock-PHP-impact branches actually reproducible today: the **cross-worker session-flock DoS** (CVE-2026-109619 stale-state effect — worker A poisoned; worker B hangs >12 s on the victim SID) and the **upload_progress → session poisoning → self-include RCE** on the intentionally vulnerable app shape the advisories model (`php_serialize` codec + `cleanup=0` recipe; `[RCE-OUT]` + `id` output visible in the HTTP response).
- **Detection is fully produced and verified both ways**: `php2shell_detect.php` reports `VULNERABLE` on our 8.4.4 build and `PATCHED` on a freshly built **8.4.27** (patched_transcripts in `evidence/`).
- **The one publicly-circulated full exploit bundle (Zer061/jackalsyn "PHP-UP-2026")
  is not runnable against stock PHP** in the manner it claims — the UAF it
  assumes doesn't exist inside any released php-src (`Z_TRY_ADDREF` has shipped
  since PHP 5.4).
- **A weaponized end-to-end RCE against an arbitrary *uninstrumented* production
  PHP** (the "php2shell" video's claimed impact beyond the documented FPM/app
  preconditions) is **not reproduced here, and the vendor itself frames RCE as
  requiring "strategically crafted heap layout" grooming** — substantial exploit
  research, not a script. Be skeptical of any repo that claims otherwise
  without publishing grooming evidence.

## Structure

```
README.md                       <- this file
SECURITY.md                     <- full text of the two GHSAs (digest)
WRITEUP.md                      <- verification record of the pre-release leak
ADDENDUM.md                     <- official advisory delta analysis, patch notes
PHP2SHELL-RESEARCH-REPORT.md    <- the pre-release research base
php2shell_poc.py                <- trigger/DoS suite (verified, internal-only)
detector/
  php2shell_detect.php          <- ON-HOST definitive probe (simple, deterministic)
  detect_remote.py              <- BANNER + CONSENT-GATED behavioral probe (network)
poc/
  poc_session_include.py        <- upload_progress -> session poisoning -> self-include
                                   RCE chain (WORKING on the intentionally-vulnerable
                                   app on stock 8.4.4; php_serialize+cleanup=0 recipe)
  PROOFS_session_include.md     <- chain doc + evidence excerpts + codec-caveat notes
  xdos_crossworker.py           <- cross-worker session-flock DoS (WORKING against
                                   two php -S workers sharing one sess dir)
  RUN_xdos_crossworker.txt      <- verified run transcript (dossier output)
  evidence-session-include/     <- the raw byte/state dumps backing the chain
lab/                            <- build scripts, clients, gdb/lldb probes, tests
evidence/                       <- lldb trace, fix-diff, advisory JSONs, proc-locks,
                                   patched-detector (both-way detector transcripts)
```

## Quick start — detection (what you'll actually want)

**On-host (definitive, zero-risk):**

```bash
php php2shell_detect.php          # human-readable verdict
php php2shell_detect.php --json   # machine-readable
```

Primary signal: the fix commit registers a brand-new INI key
`memory_hard_limit_percent`. Its presence in a running binary means commit
`506e87fa7` is compiled in — no false positives. Belt-and-braces version check
(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

**Remote (banner read-only is harmless; behavior probe is consent-gated):**

```bash
python3 detector/detect_remote.py http://target/                       # banner only
python3 detector/detect_remote.py http://target/ --i-own-this-target   # + behavior
```

**Verdict matrix (behavior probe):**

| Poison shape result | Follow-up same-SID result | Meaning |
|---|---|---|
| no OOM (200s), follow-up fast | can't tell | benign / high memory_limit / upload_progress=0 |
| OOM-era crash response, follow-up **times out** | deadline exceeded / lock holdover | **UNPATCHED** (the vendor fix removed this) |
| OOM response, follow-up fast OK | worker self-healed | **INDETERMINATE** (FPM-recycling or patched) |
| client-side exception anywhere | — | never used for verdict (false-positive guard) |

The behavior probe sends ONE bounded multipart POST (6 MB of filename bytes
mirroring `tests/basic/oom_rfc1867_upload_progress.phpt`) and intentionally
hiccups ONE worker at most.

## Verified claims (each tied to a file)

| # | Claim | Evidence |
|---|---|---|
| 1 | `BG(serialize)` dangling after OOM mid-serialize during `php_hash_environment` | `evidence/lldb_trace_full.txt` lines around `==BAILOUT==` |
| 2 | Cross-request reuse of the same `php_serialize_data` pointer (level 1->2) | same file, the `==INIT==` block of R2 |
| 3 | DESTROY at level 2 frees nothing (state sticky until basic RINIT memset) | `ext/standard/var.c:1346-1352` (source) + lldb trace |
| 4 | Module RSHUTDOWN skipped because `PG(modules_activated)` is gated | `main/main.c:1822-1836` (source) |
| 5 | Leaked session fd holds `flock(LOCK_EX)` post-request into the worker | `evidence/flock_evidence.txt` (`/proc/<pid>/fd/10`) |
| 6 | Independent process blocks on the leaked flock — cross-worker DoS | lab run, step3.py output in WRITEUP §3 |
| 7 | 30 poison cycles: RSS 8.7 -> 28.8 MB, every one becomes HTTP 500 | `lab/memdos.py` run log |
| 8 | No free-path UAF exists in stock 8.4.4 (Z_TRY_ADDREF present since 5.4) | REPORT.md §4, source-verified |

## Files in evidence/

- `lldb_trace_full.txt` — 1,213 lines: full lifecycle breakpoint trace (INIT/DESTROY/BAILOUT/RINIT/RSUTDOWN markers with state values) across the poison + reuse request sequence
- `security-fix-506e87fa7.diff` — 683 KB, the official fix diff verbatim
- `advisories/GHSA-w8hw.json` / `GHSA-6wmf.json` — both advisories as published by api.github.com
- `flock_evidence.txt` — `/proc/<worker-pid>/fd` showing the leaked session fd + `/proc/locks` lines
- `final_demo.log` — the working demo run output

## Safety and scope

The PoCs are *defensive-research* grade: they demonstrate the exact primitives
the vendor patched, measured under lldb/gdb locally, on stock PHP. They are
written to a standard that lets you answer *"am I affected?"* — not to exploit
a server. The behavior probe is the most intrusive script here and it is
consent-gated.

If you find this for incident-response on your own infrastructure: patching is
the only complete mitigation (see `ADDENDUM.md` for interim configuration
levers the vendor endorses, and for what NOT to do — `RLIMIT_AS/RLIMIT_DATA`
are traps).

## References

- GHSA-w8hw-w9fx-j79w — CVE-2026-109618 ("RCE via OOM corruption")
- GHSA-6wmf-4rv5-p3rp — CVE-2026-109619 ("RCE via stale global state")
- php/php-src commit `506e87fa7` — official fix (2016-10-21)
- watchTowr FAQ (incident timeline), Sansec guidance (interim stopgaps)
