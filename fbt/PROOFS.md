# PROOFS — fatal_error_backtraces request-state miss (CVE-2026-109619 / GHSA-6wmf shape)

**Date:** 2026-10-21 · **Host engine proven on:** stock `php:8.5.11-apache` (Docker Hub,
digest `sha256:47e6d884…e8b`) · **Control branch checked:** `php-8.4.27` source tree at
`~/ph2s_patch/src-8.4.27` (tag `php-8.4.27`, commit `00d8bae801541db0d95a698e108bb4b1b273fe6e`)

---

## 1. Verdict

| Branch / SAPI | Demonstrable? | Basis |
|---|---|---|
| **8.4-branch (php-8.4.27), any SAPI** | **NO — impossible, feature absent.** | §2 |
| **8.5.11 + `mod_php` (apachehandler)** | **YES — reproduced, 4/4 vs 0/4 differential.** | §3–§5 |
| **8.5.11 + `php -S` / `php-fpm`** | No pre-request-init per-dir INI stage → unreachable (vendor's own wording; mechanism confirmed in source). | §6 |
| **`php:8.5-apache` stable image** | `8.5.12` final **not yet on Docker Hub** at test time; `8.5.11-apache` (latest stable, vulnerable-by-inspection) used. `php:8.5.12RC1-apache` exists on Hub but its `zend_execute_API.c` is byte-identical at the reset site — the guard is unchanged, so RC1 shows no vendor fix. | §7 |

The producer+consumer premise (shutdown misses reset of
`EG(last_fatal_error_backtrace)`; next request's pre-init diagnostic touches
the stale value) is **real and reachable in stock php 8.5.11**. The observed
impact of the stale touch is a **UAF → SIGSEGV of the mod_php worker**
(deterministic under the reproduction constraint in §4), not an in-response
print of stale frames — see §8 for why the print variant cannot occur in this
source revision.

## 2. 8.4-branch: forensically clean NO

File-line evidence against the `php-8.4.27` checkout (grep counts across the
whole tree, all zero):

```
grep -rn 'fatal_error_backtraces' .            => 0 hits
grep -n  'backtrace' main/main.c               => 0 hits
grep -n  'last_fatal_error' Zend/zend_globals.h => 0 hits
```

There is no `fatal_error_backtraces` INI directive, no
`EG(last_fatal_error_backtrace)` executor global, and no backtrace storage in
the fatal-error path of `main/main.c` in 8.4.27. The state-miss sequence
cannot be constructed on stock 8.4 because the state that would leak does not
exist. **Sequence is unreachable on 8.4; stopped there — nothing fudged.**

(Full grep transcript: `evidence_source.txt`, section "ABSENCE EVIDENCE".)

## 3. Mechanism (all line refs = php-src tag `php-8.5.11`)

1. **Producer request** raises a genuine zend `E_USER_ERROR` (no exception
   object). Since `fatal_error_backtraces=On` (8.5 default):
   `Zend/zend.c:1526` — `zend_fetch_debug_backtrace(&EG(last_fatal_error_backtrace), …)`.
2. **Shutdown misses the reset.** `shutdown_executor()` computes
   `fast_shutdown = is_zend_mm() && !EG(full_tables_cleanup)`
   (`Zend/zend_execute_API.c:446` — true with Zend MM, the default).
   `zend_shutdown_executor_values()` guards the only shutdown-time clear:
   `Zend/zend_execute_API.c:282` `if (!fast_shutdown) { …` with
   `zval_ptr_dtor(&EG(last_fatal_error_backtrace)); ZVAL_UNDEF(…)` at
   **309–310** — skipped under fast shutdown. The zval survives
   `RSHUTDOWN`, referencing request-heap memory that is bulk-freed (and, for
   huge allocations, munmap'd).
3. **Next request, pre-init touch.** The normal-reset site is
   `init_executor()` (`Zend/zend_execute_API.c:139` `ZVAL_UNDEF(…)`), run
   during `php_request_startup`. But mod_php applies per-dir INI **before**
   request startup: `sapi/apache2handler/apache_config.c:200`
   (`apply_config` → `zend_alter_ini_entry_chars(… PHP_INI_STAGE_HTACCESS …)`).
   An invalid-quantity `php_value memory_limit …` goes through
   `main/main.c:335` (`OnChangeMemoryLimit`) →
   `Zend/zend_ini.c:865` `zend_error(E_WARNING, "Invalid \"%s\" setting. …")`.
4. **Stale dtor.** The zend_error path unconditionally clears first:
   `Zend/zend.c:1500–1502` (`// Always clear the last backtrace.` →
   `zval_ptr_dtor(&EG(last_fatal_error_backtrace))`). On the second request
   this dtors a zval whose array/bucket payloads were freed in step 2 ⇒ UAF.

Print/consume site (for completeness): `main/main.c:1389–1390`
(`php_error_cb` converts `EG(last_fatal_error_backtrace)` to a string
whenever it is non-UNDEF) — unreachable for stale data in stock source; see §8.

Sources: `evidence_source.txt` (verbatim line-numbered excerpts S1–S9).

## 4. Reproduction (poc.sh) — differential proof

`poc.sh` runs pristine-boot cycles in two identical `php:8.5.11-apache`
containers differing **only** in `.htaccess`:

| fixture | cycles | child segfaults (AH00052) | R2 (`ping.php`) |
|---|---|---|---|
| control (`fixture/html_noht`, no `.htaccess`) | 4 | **0** | `PING-OK` ×4 |
| attack (`fixture/html`, `.htaccess` invalid `memory_limit`) | 4 | **4** | **lost** (worker died serving R2) |

Raw transcripts: `evidence_poc_run.txt`, `evidence_apache_log_full.txt`,
`evidence_r1_producer_response.txt` (fbt trace emitted from
`EG(last_fatal_error_backtrace)` inside R1), `evidence_r2_consumer_response.txt`
(0 bytes — consumer response never completed).

**Attribution matrix** (`evidence_attribution.txt`, pristine boots, same
fatal→ping collision):

| `.htaccess` variant | crashes |
|---|---|
| absent (`html_noht`) | 0 |
| comment-only, no `php_value` (`html_htcmt`) | 0 |
| `php_value error_reporting 32767` (valid value, **no** zend_error) (`html_htok`) | 0 |
| `php_value memory_limit not_a_quantity` (pre-init **zend_error**) (`html`) | 1 |

⇒ the crash is triggered neither by `.htaccess` parsing nor by INI overriding
in general — only by the **pre-init `zend_error` call** touching the stale
global. Note: the warning's *text* may be silently swallowed per child state;
the observable that matters (worker death during the R2 that raises the
warning) is unconditional under the pristine-child constraint.

**Reproduction constraint (empirical, stated honestly):** the collision must
start from a **pristine Apache child** — `fatal.php` must be the first
request the child serves. If any ordinary request warmed the child first,
zend_mm segment caching lets the stale header read succeed, the dtor then
only corrupts the heap silently (latent) and no immediate crash is logged.
`poc.sh` honors this by waiting for Apache via `docker logs` (never an HTTP
probe — an HTTP warm-up is itself the poison) and recreating containers per
cycle. With that constraint the crash reproduced 4/4 (plus 4/4 and 5/6 in
independent earlier sessions).

**Reliability construction:** the producer frame passes a ~1.5M-element
packed array (`$big`). fbt copies args by reference into the captured
backtrace; the array's ~24 MB bucket table is a huge-mmap segment that is
unmapped at fast shutdown, so the stale dtor deterministically dereferences
unmapped memory (SIGSEGV) instead of merely corrupting recycled chunks.

## 5. Exact INI requirements (vendor-faithful)

- `fatal_error_backtraces = On` — **default** in PHP 8.5; no app config needed.
- The pre-init consumer diagnostic **must be raised through a per-dir INI
  override at `PHP_INI_STAGE_HTACCESS`** — i.e. Apache config or `.htaccess`
  `php_value`. `poc.sh` uses:
  `php_value memory_limit not_a_quantity`
  (invalid quantity → `zend_ini_parse_uquantity_warn()` → `E_WARNING`).
- **`.user.ini` is NOT usable** (vendor wording, confirmed):
  mod_php never processes `.user.ini`; and where it is processed (fpm/cgi)
  it is parsed at request init — *after* `init_executor()` has already reset
  the global. Timing dead end either way.

## 6. Susceptible-exact SAPI boundary

The sequence needs a per-dir INI stage that runs **before**
`php_request_startup`. That exists **only** in mod_php (Apache handler,
`.htaccess`/`<Directory>` merge during `ap_directory_walk`, before the PHP
response handler starts the request). `php -S` and php-fpm have no such
pre-init stage → non-susceptible (matches vendor's own scoping). Live
fixture here ran `mpm_prefork`, 1 worker, KeepAlive on
(`fixture/apache-fbt.conf`).

## 7. Patch-availability note (no fabrication)

- `php:8.5.12-apache` final was **not on Docker Hub** at test time (real
  release lag; `8.5.12RC1` was).
- `php-8.5.12RC1/Zend/zend_execute_API.c` (raw GitHub fetch) keeps the dtor
  behind `!fast_shutdown` at lines 309–310 — **no visible upstream fix in
  the RC**. If a security release exists beyond RC1, it was not fetchable
  from this benchtop at write time.
- No systemd evidence was fabricated; all behavior claims come from Docker
  runs whose transcripts are stored next to this file.

## 8. Precision note on impact shape

In stock 8.5.11 source the stale value is **not printable**: `zend.c:1500`
clears the global at the top of every `zend_error` before `php_error_cb`
runs, so the `main.c:1389` consume site can only ever see a *current*
request capture. What the pre-init touch actually does with the stale value
is the **UAF dtor** (crash), demonstrated above. The vendor advisory's leak
wording and this PoC are consistent through the same root cause — a reset
missed at shutdown makes request-owned backtrace state outlive its request —
with the crash branch being the stock-8.5.11-observable consequence.
A silent **heap-corruption** variant (warmed children) is additionally
observable as crash-free but is still the same stale dtor.

## 9. Files

```
poc.sh                           100%-reusable PoC (docker; prints [+] PROVEN on success)
fixture/html/{.htaccess,fatal.php,fatal_deep.php,ping.php}   attack fixture
fixture/html_noht/               control fixture (no .htaccess)
fixture/html_htcmt/              control (comment-only .htaccess)
fixture/html_htok/               control (valid php_value .htaccess)
fixture/apache-fbt.conf          prefork 1-worker + KeepAlive lab tuning
evidence_poc_run.txt             full poc.sh transcript (4/4 attack, 0/4 control)
evidence_attribution.txt         .htaccess variant matrix (trigger isolation)
evidence_apache_log_full.txt     Apache log of one crashing cycle
evidence_r1_producer_response.txt R1 body: fbt trace incl. captured Array arg
evidence_r2_consumer_response.txt   0 bytes — R2 died with the worker
evidence_source.txt              line-numbered source excerpts S1–S9 + 8.4.27 absence greps
```
