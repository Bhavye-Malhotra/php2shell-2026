# Addendum — Official PHP Advisories (released 2026-10-21 13:34 UTC)

Both GitHub security advisories published by the PHP team, retrieved from the
api.github.com API and saved verbatim as `evidence/advisories/GHSA-w8hw.json` /
`GHSA-6wmf.json`. **This is the authoritative statement of the two CVEs and it
confirms, corrects, and extends parts of the pre-release report (REPORT.md) and
this lab's findings.**

## CVE-2026-109618 — GHSA-w8hw-w9fx-j79w — "RCE via OOM corruption" (critical)

**Mechanism (vendor wording)**: PHP uses `longjmp()` for OOM errors. "In some
contexts, request memory is temporarily reachable before it is fully initialized.
If any allocation fails at that point, PHP does not properly account for the early
exit and leaves the request memory in an invalid state... The request shutdown
procedure may then read or branch on it."

**Confirmed impact**: unauthenticated RCE as the web worker account, **validated
over HTTP against mod_php** with default input/memory limits and normal prefork
configurations. Additional workers / unrelated traffic raise attempt counts but
do not eliminate the condition.

**SAPI coverage**: mod_php unconditional shutdown → primary target. **FPM exits
the child on startup failure**, which blocks the exact mod_php sequence, but is
still susceptible via application-specific OOM after successful startup.
FrankenPHP ≈ mod_php; LSAPI ≈ FPM (likely, unvalidated).

**Multipart OOM entry points named by the vendor** (matches why the
upload_progress giant-filename payload lands mid-request-startup):
- Multipart request without usable declared content-length passes initial checks
- Unlimited headers per multipart part (blows up PHP-side representation)
- Empty file controls don't count toward `max_file_uploads` but still generate arrays

**Patch**: removes `longjmp()` for OOM → delayed graceful *soft* OOM at the next
VM safe point, and immediate *hard* OOM via `_exit()` at a second higher threshold.

**Interim mitigations**: `memory_limit=-1` (removes the predictable trigger window
— *not* complete mitigation), cgroup/container limits, frontend enforcement of
decoded body size, restrict multipart at proxy if unused. **Do not use
`RLIMIT_AS`/`RLIMIT_DATA`** — they drive PHP through the exact vulnerable longjmp
path when mmap fails.

## CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp — "RCE via stale global state" (critical)

**Mechanism**: worker lifetime globals (error, session, object, extension state)
can retain pointers to memory owned by one request. If a fatal error (including
OOM, uncaught errors, `Maximum execution time exceeded`, parse/compile failures,
failed `require`) interrupts before the matching reset, or a late-shutdown
diagnostic repopulates error state, the request heap is freed while the worker
global still refers to it. A later pre-initialization operation consumes the
stale value → UAF → "a strategically crafted heap layout can produce full RCE."

**Producer → consumer requirement confirmed by the vendor**, with two confirmed
pre-init consumers:

1. **INI diagnostics before request initialization** — mod_php `.htaccess` /
   `php_value` applies before `php_request_startup()` ⇒ diagnostic consumes stale
   error state every request. FPM only when frontends inject `PHP_VALUE` /
   `PHP_ADMIN_VALUE`. `.user.ini` and FPM pool values post stdin-init,
   as well as stripping `error_reporting`/`@`/`display_errors`/`log_errors` —
   **none of those protect**; consumption happens before reporting decisions.
2. **Session upload progress** — session handling reached before ordinary
   initialization ⇒ consumes session/decoder state left by an interrupted request.
   **Exactly the path lldb-confirmed in this workspace.**

**Strongest concrete case** (basis of confirmed mod_php RCE): PHP 8.5 with
`fatal_error_backtraces=1`. Backtrace state is request-owned, reset is always
missed at shutdown, and a subsequent pre-init INI diagnostic reaches it.

**Second confirmed case**: **session upload progress lifecycle** — OOM after
state is published prevents the matching reset; PHP frees the request heap while
session globals refer to it; a later upload_progress operation reaches the stale
globals first. Matches this lab's debugger capture: `BG(serialize)={data,level=1}`
left dangling, reused level→2 by the next multipart request on the same worker.

**FPM note**: exact startup-sequence doesn't survive (child exits), but a
published-state-during-app-execution producer + upload-progress consumer was
validated on FPM.

**Patch**: resets the *wider* global state (explicitly not only BG(serialize)) —
per vendor: supported branches contain other request state that could become
unsafe after a request boundary. This is why the patch diff lands across
`main/`, `ext/standard/`, `ext/session/`, and likely the error-handling core.

**Mitigation pending patch**: `fatal_error_backtraces=0` (8.5, kills the strongest
producer), `session.upload_progress.enabled=0` (kills the upload-progress
producer AND consumer — matches our stopgap), eliminate attacker-reachable fatal
errors + all pre-init INI diagnostics, and consider `pm.max_requests=1`.

## Delta to my pre-release analysis

| My pre-release statement | Official advisory | Resolution |
|---|---|---|
| Emergency release: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | identical | confirmed |
| 618 and 619 both CVE'd, 9.2 v4.0 each | both CGrefs at critical; per-advisory CVSS vectors listed | confirmed |
| BG(serialize) dangling state + reuse, upload_progress as consumer | vendor: "Session upload progress lifecycle: confirmed" | **confirmed at consumer level; matching evidence captured in this lab** |
| ZendMM recycler keeps lab-reuse benign | vendor: RCE requires "strategically crafted heap layout" | matches: grooming is the load-bearing step, lab 瘦身s.shows clean |
| "Crash requires real heap-layout control (prefork/FPM)" | exact quote via "the confirmed mod_php exploitation" needed multiple attempts, pool traffic increases attempt count | **matches** |
| Stopgaps `upload_progress.enabled=0` / `use_strict_mode=1` | vendor recommends `upload_progress.enabled=0`, adds `fatal_error_backtraces=0` (8.5) | match + one addition |
| WatchYTowo "21-year-old framing" re: PHP-5 request-startup design | vendor describes PHP-5-era request startup design without calling it out formally | consistent |

## What I got wrong or under-scoped

- I listed `session_upload_progress` as *the* remote trigger vehicle. The
  advisory shows 619 has **two independent consumer classes** (INI diagnostics +
  session), and the 8.5 `fatal_error_backtraces` producer is the strongest case.
  On 8.4.4 (this lab) the producer is BG(serialize) OOM bail — smaller window,
  still live; but the headline case needs 8.5's backtraces producer → deeper bug
  than the ones I captured here.
- The `memory_limit=-1` mitigation is vendor-endorsed and beats everything else
  short of patching. It directly intersects the OOM-through-serialize poisoning
  I demonstrated.

## Patch landed: commit `506e87fa7` "Avoid state corruption via bailout" (8.4.27 etc.)

One single mega-commit fixes **both** CVEs (`Fix GHSA-w8hw` + `Fix GHSA-6wmf`), authored by Ilija Tovilo / Jakub Zelenka / Niels Dossche / Nicolas Grekas. `evidence/security-fix-506e87fa7.diff` (~300 files, most of them new `oom_*.phpt` tests) is the verbatim diff. My §7 watchlist:

| Predicted (watchlist §7) | Patch evidence | Verdict |
|---|---|---|
| `main/main.c`: serializer globals zeroed *before* `php_hash_environment()` | new `php_basic_early_rinit()` called in `php_request_startup` **before** multipart parsing; vendor comment: *"The session upload progress handler (un)serializes the session ... before RINIT"* | **HIT — exactly the mechanism traced in this lab** |
| `ext/standard/var.c`: serializer init/destroy hardening | `php_var_serialize_init` initializes a new `incomplete_classes_only` field; new setter `php_var_serialize_set_incomplete_classes_only` | **HIT** |
| `ext/session/session.c`: upload_progress encode path changes | new `PS(in_rfc1867_update)` flag; pre-RINIT (un)serialization forced into `incomplete_classes_only` mode (no autoload, no `__wakeup`/`__unserialize`, objects kept as `__PHP_Incomplete_Class`) — that's the vendor acknowledging the *user-code-before-init* surface as well | **HIT — and deeper than my watchlist** |
| New INI / OOM infrastructure | `memory_hard_limit_percent` (dual-threshold: soft OOM at VM safe point, hard `_exit()`), `ZEND_HAS_OOM()` guards sprinkled through pre-init code paths, `zend_mm_set_max_allocs` debug variable | new, beyond prediction |
| Error-state lifecycle | `clear_last_error()` at shutdown; `ZVAL_UNDEF(&PG(http_globals)[i])` at super-global destruction; `handle_exceptions_on_user_error`... plus `PG(modules_activated)=0` explicitly reset at shutdown end with comment *"May be accessed before php_request_startup()"* — the gate I proved at `main.c:1825` | **HIT — the gate now gets reset everywhere it needed to be** |
| Remove OOM `longjmp()` | ~150 new `oom_*.phpt` tests + new `UnwindExit`-style core (zend_alloc.c +527/-124) | vendor-reported mechanism, diff is the proof |

Also: `ext/session/session.c` now guarantees **user code never runs in the pre-RINIT
upload progress window** — which kiboshes any hope of driving the consumer into an
autoload/`__wakeup` gadget in unpatched-but-mitigated contexts. The patch is
correct in its architecture: it removes OOM-as-longjmp (618) AND resets the
global staleness window (619) in exactly the locations this workspace dragged
into the light.

Notable gap indicator: the patch touches ~20 extensions' allocation/error paths
(exif, iconv, mbstring, soap, pcre, spl, dom, ...) — the fix is broad, and any
extension whose code wasn't audited here still carries the same class of hazard
in principle.

## Updated defense posture (post-patch)

1. Apply 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 immediately on internet-facing
   installations; restart workers; rebuild images.
2. Where patching isn't immediate: `fatal_error_backtraces=0` (PHP 8.5),
   `session.upload_progress.enabled=0`, strip pre-init INI diagnostics from
   `.htaccess` / FPM `PHP_VALUE` paths, evaluate `pm.max_requests=1`.
3. `memory_limit=-1` as blunt interim lever is vendor-sanctioned for 618 —
   prefer patching over living on this.
4. Do **not** set `RLIMIT_AS`/`RLIMIT_DATA` to emulate a limit — it makes
   things worse (triggers longjmp OOM via mmap failure).
5. Prediction from §8 of my report: patch touches `main/main.c` startup
   ordering + `var.c` serializer lifecycle + `session.c` upload_progress path —
   advisory says the official fix *also removes longjmp-OOM wholesale and resets
   wider globals*. Look for those in the 14:00 UTC diff.
