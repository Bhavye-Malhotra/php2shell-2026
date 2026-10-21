# CANDIDATES.md — CVE-2026-109618 OOM-persistence candidate inventory

Scope: every test path shipped by the vendor security fix, scored as remote-RCE candidate
chains against **stock PHP 8.4.4 unpatched** (pre-patch semantics).

Evidence base (all line numbers verified against):
- Tests: `php-8.4.27` tag clone at `/home/wh1t3r0se/ph2s_patch/src-8.4.27`
  (git: tag `php-8.4.27`, HEAD `00d8bae801541db0d95a698e108bb4b1b273fe6e`).
- Fix list: `/home/wh1t3r0se/ph2s_matrix/security-fix-506e87fa7.diff` (20,704 lines;
  **279 `.phpt` files** + 111 C/h/re/re2 source files; 6 `oom_rfc1867*.inc` helpers).
- Fix commit: `506e87fa7` (parent-supplied diff, local copy above).

Test-source split of the fix: 279 phpt tests = 65 in `Zend/tests`, 16+3 in `ext/session`,
16+11+2 in `tests/basic`, remainder across ext/*. Four accessor families dominate the
security surface: `unserialize_*` (15), `rfc1867_*` (16 tests/6 inc + GHSA-f883 11 +
GHSA-2cv3 2), `attach/zend_*` engine-state tests (interrupt/soft/hard-limit, 10), `json_*` (7+5).

---

## 0. Mechanism model (what the patch changed, why "persistence")

8.4.4: exceeding the soft `memory_limit` inside ANY allocation calls
`zend_mm_safe_error` → immediate `zend_bailout()` — **even mid-RINIT**, mid-multipart-parse,
mid-session-decode. There is no OOM state object at all.

8.4.27: the fix introduces a deferred-OOM state machine so allocation failure is
*recorded* and handled at engine checkpoints instead of longjmping out of arbitrary
library code:

- `Zend/zend_globals.h:321` — `zend_oom_info delayed_oom;` added to executor globals.
- `Zend/zend_alloc.h:63` — `#define ZEND_HAS_OOM() (UNEXPECTED(EG(delayed_oom).state != ZEND_OOM_STATE_NONE))`
- `Zend/zend_alloc.c:3644` — `zend_handle_delayed_oom()` (PENDING→HANDLING→HANDLED).
- `main/SAPI.c:168-170` — after `post_handler()` returns inside `sapi_handle_post()`:
  `if (ZEND_HAS_OOM()) { zend_handle_delayed_oom(); }`
- `main/main.c:1033` — `php_verror()` returns early if `ZEND_HAS_OOM()` (no error
  formatting allocations during OOM).
- `main/main.c:1930` and `main/main.c:2025` — `EG(delayed_oom).state = ZEND_OOM_STATE_NONE`
  forced at entry **and** end of `php_request_shutdown()`, so state cannot leak across
  requests in a persistent worker (FPM/mod_php).
- `main/rfc1867.c:814` and `main/rfc1867.c:826-829` — multipart parser checkpoints
  `ZEND_HAS_OOM()` per part ("A previous body part has reached the soft memory limit:
  Stop here").
- `ext/session/session.c:964-976` — `php_session_unserialize_init()` forces
  `php_var_unserialize_set_incomplete_classes_only(*var_hash, true)` while
  `PS(in_rfc1867_update)`; the comment at `session.c:964-969` states the handler
  "decodes and re-encodes the session during request startup, before RINIT, when no
  user code may run".

"OOM-persistence" (CVE-2026-109618) = in 8.4.4 an OOM raised during RINIT request
parsing / upload-progress session handling bails out with half-mutated globals and
allocator state that (a) survives into request shutdown and (b) in persistent SAPIs
survives into the next request of the same worker, and (c) when the multipart/upload
-progress handler is mid-flight, is *written to durable state* (the session file on disk).

Ax (c) — allocator divergence R1(8.4.4) vs R2(8.4.27): **true**. The whole
`ZEND_HAS_OOM` placement set (`SAPI.c:168`, `rfc1867.c:814/826`, `main.c:1033`,
`zend_execute_API.c:825/1071`) exists only post-patch; 8.4.4 takes the immediate-bailout
branch at every one of those points. Every candidate below is scored against the 8.4.4
branch.

RINIT-before-user-code chain (producer/consumer plumbing):
- `main/main.c:1866` `php_request_startup()` → `main/main.c:1906` `php_hash_environment()`
  (inside `zend_try`) → `main/php_variables.c:837-848` `php_auto_globals_create_post()` →
  `main/php_variables.c:488` `php_default_treat_data()` → `main/php_variables.c:524`
  `sapi_handle_post(&array)` → `main/SAPI.c:164-171` → `main/rfc1867.c:806`
  `SAPI_POST_HANDLER_FUNC(rfc1867_post_handler)`.
- All of this runs **before the target script is compiled**. No user code executes.

Stock defaults that gate the remote window:
- `memory_limit` = 128M (`main/main.c:827`)
- `post_max_size` = 8M (`main/main.c:809`), `upload_max_filesize` = 2M (`main/main.c:808`),
  `max_file_uploads` = 20 (`main/main.c:835`)
- `max_input_vars` = 1000 (`main/main.c:812`), `max_input_nesting_level` = 64 (`main/main.c:811`)
- `max_multipart_body_parts` = **-1 (unlimited)** (`main/main.c:836`)
- `session.upload_progress.enabled` = **1 (On, default)** (`ext/session/session.c:944-945`);
  `.cleanup` = 1 (`session.c:946-947`); `.freq` = "1%", `.min_freq` = 1 (`session.c:952-954`)
- `session.serialize_handler` = **"php"** (`ext/session/session.c:925`)
- `mbstring.encoding_translation` = **0 (Off, default)** (`ext/mbstring/mbstring.c:946`)
- `zend.fatal_error_backtraces`: **zero matches for "fatal_error_backtraces" in the entire
  php-8.4.27 tree** (`grep -rn`) — not available in 8.4.x (8.5+ only). Cannot be used to
  make fatal OOMs allocate backtraces on 8.4.4.

**The default-config arithmetic that matters:** memory is only exhausted by request
parsing when the attacker-controlled body (≤ `post_max_size`) can force allocations
near `memory_limit`. Stock `post_max_size=8M` vs `memory_limit=128M` ⇒ a single stock-
default request parser CANNOT OOM itself; the OOM precondition needs
`post_max_size`/`upload_max_filesize` raised toward/above `memory_limit` (extremely
common in real deployments: post_max 32M–512M with memory_limit 128M–256M) **or** a
per-part amplification (upload-progress session re-encode per chunk — frequency-gated).
The vendor tests themselves run with `post_max_size=1G;upload_max_filesize=1G;
memory_limit=4M-8M` (`tests/basic/oom_rfc1867.inc:44-50`), i.e. exactly that window.

---

## 1. Ranked candidates (1 = most plausible remote-RCE vector)

### Rank 1 — rfc1867 multipart parser + session upload_progress handler
Verdict: **incomplete without heap-grooming** (remote producer AND remote consumer exist
in stock defaults; leak→RCE transition needs a groomable leak target / POP gadget).

Coverage: `tests/basic/oom_rfc1867_*.phpt` (16 tests), `tests/basic/oom_rfc1867{,_mb,_session}_skipif.inc`,
`tests/basic/oom_rfc1867.inc`, `tests/basic/oom_rfc1867_target.inc`,
`tests/basic/GHSA-f883-x959-3vr9_001..011.phpt` (multipart regression corpus),
`tests/basic/GHSA-2cv3-554h-jpmh_{multipart,urlencoded}.phpt`,
`ext/session/tests/rfc1867_{sid_invalid,no_user_code,incomplete_class_reserved_props}.phpt`.

Generator/API: raw `POST multipart/form-data` over stock HTTP. Producer condition — all of:
1. `file_uploads=1`/POST accepted by the web SAPI (FPM/mod_php/php-cgi; CLI irrelevant).
2. Size window: `post_max_size` ≳ `memory_limit` (see §0 arithmetic); tests raise every
   input limit so memory is the only bound (`oom_rfc1867.inc:44-50`).
3. For the **session sub-path**: `session.upload_progress.enabled=1` — default On
   (`session.c:944`), body part order `PHPSESSID` then `PHP_SESSION_UPLOAD_PROGRESS`
   first (`oom_rfc1867_upload_progress.phpt:26-31`), `session.use_strict_mode=0`
   (default) to accept an attacker-minted SID, and a reachable `session.save_path`.
4. mbstring conversion sub-path (`oom_rfc1867_mb_encoding.phpt:9-14`) needs
   `mbstring.encoding_translation=1` — **non-default** (`mbstring.c:946`); scored under
   Rank 5, not here.

Consumer over stock HTTP before RINIT: **yes**, twice over:
- `PG(http_globals)[TRACK_VARS_POST]/[TRACK_VARS_FILES]` are registered during request
  startup (`main/php_variables.c:505-516`) and auto-globalized before user code
  (`main/php_variables.c:837-848`). A RINIT OOM mid-registration is exactly what
  `oom_request_parsing.phpt`/`oom_rfc1867_post_vars.phpt` exercise.
- The upload-progress handler **opens, decodes, mutates and re-encodes the session file
  during multipart parsing**: `session.c:3265` (enabled gate), `session.c:3279-3284`
  (`MULTIPART_EVENT_START` → comment "This runs before RINIT"), `session.c:3223-3224`
  (comment "Runs before RINIT: no user code may be invoked"), `session.c:3237`
  `php_session_flush(1)` — the tampered session record is **durable on disk** and is
  consumed by request R2 presenting the same SID (the OOM-persistence carrier).

Codec/format constraint: session record in `php` (default), `php_binary`, or
`php_serialize` codec (`session.c:925`); the handler decode is gated post-patch to
incomplete-classes-only (`session.c:970-976`). In 8.4.4 (pre-patch, the scored
semantics) that gate did not exist → decode ran with full unserialize semantics during
request startup. `rfc1867_no_user_code.phpt:21-37`
documents the protected record shapes (`O:` with `__wakeup`, `C:` Serializable payload,
`E:`/`r:` shared enum). `rfc1867_no_user_code.phpt:81-86` documents the second leak:
pre-patch the handler could leave `$_SESSION` registered in the symbol table of a
request that never called `session_start()` — **cross-session disclosure to the R1
script itself**.

Why not a full RCE ranking: turning the pre-patch RINIT OOM-into-session-write into
code execution still needs (i) a deserializable class chain present on the target
(POP gadget) or (ii) precise heap layout control in the persistent worker to make the
half-mutated session/`PG(http_globals)` overlap attacker data — i.e. grooming.
Attacker-controlled knobs alone (SID, part names, part sizes) give the
write-amplification and the OOM timing oracle, not the type confusion.

### Rank 2 — urlencoded/GET request parsing (auto-global registration)
Verdict: **incomplete without heap-grooming** (pure-producer remote; consumer is the
script's own `$_POST/$_GET`; persistence only into worker shutdown/next-request state).

Coverage: `Zend/tests/oom_request_parsing.phpt`,
`tests/basic/GHSA-2cv3-554h-jpmh_urlencoded.phpt`, `Zend/tests/oom_interrupt*.phpt` (3).

Generator/API: `application/x-www-form-urlencoded` POST and GET query string, parsed in
`php_default_treat_data` (`php_variables.c:488`) from `php_hash_environment`
(`main/main.c:1906`) — before user code. The test proves three distinct OOM loci in the
parser: single huge value (read loop), many vars (registration loop), mixed
(`oom_request_parsing.phpt:65-82`), each against a tiny and a 60k-statement target
script (`:22-23`) — i.e. engine state after RINIT OOM diverges depending on script size.

Constraints: same size-window arithmetic as Rank 1; `max_input_vars=1000` default caps
the many-vars amplifier (`main/main.c:812`) — the `oneValue` shape (`a=` + 6MB,
`:67`) is the only default-reachable sub-shape and it still needs
post_max≫8M. Divergence ax (c): true (parser checkpoints are the patched loci).

### Rank 3 — unserialize() family (engine-level deserialize hardening)
Verdict: **not remotely triggerable** in stock default SAPIs *as a standalone producer*;
it is the **decode side of Rank 1's session path** and of any app `unserialize($req)`
sink. "fully-mitigated-by-patch" for the engine-state half.

Coverage: `Zend/tests/oom_unserialize_001..009, 011..016` (15; `oom_unserialize_001.phpt`
array payload `:14`, `_005` stdClass payload `:16`), `Zend/tests/oom_SplFixedArray___unserialize.phpt`,
`oom_SplFixedArray___wakeup`, `oom_SplFixedArray_copy_ctor`, `oom_SplFixedArray_fromArray_001/002`,
`Zend/tests/oom_array_pad_001..008`, `oom_array_fill_001..004`, `oom_range_*` (allocation
amplifiers reachable from userland and from crafted unserialize/spl payloads).

Generator/API: `unserialize()` on attacker string; session decode uses the identical
`php_var_unserialize` core (`ext/session/session.c:1009/1066/1143` →
`stream ⇒ PS_SERIALIZER_DECODE_FUNC(php)` default `php` handler). Patched C side:
`ext/standard/var_unserializer.re` — 21 hunks (OOM-safe `var_destroy`, nested-object
cleanup, custom-object paths).

Why rank 3 not 1: nothing in stock PHP feeds HTTP bytes into unserialize except the
session upload-progress decode (Rank 1) and session decode at `session_start()` — both
require the session-surface conditions of Rank 1, plus a POP chain. Producer
reachability without an app endpoint: **none**.

### Rank 4 — engine OOM-state machine tests (interrupt / soft / hard limit / shutdown)
Verdict: **not remotely triggerable** as producer (needs in-request userland
allocations); they define the persistence primitive the patch fixes.
"fully-mitigated-by-patch" for cross-request state.

Coverage: `Zend/tests/oom_hard_limit_exceeded.phpt`, `oom_hard_limit_exceeded_during_complilation.phpt`,
`oom_soft_limit_exceeded{,_fcall}.phpt`, `oom_soft_limit_in_callback.phpt`,
`oom_interrupt{,_unfinished_call_frame{,_fiber}}.phpt`, `oom_pending_at_shutdown.phpt`,
`oom_after_main_script.phpt`, `oom_singleton_array.phpt`, `oom_debug_backtrace{,_args,_named_args}.phpt`,
`oom_exception_trace.phpt`, `oom_error_get_last.phpt`, `oom_call_function{,_002,_003}.phpt`,
`Zend/tests/fibers/get-return-after-bailout.phpt`, plus bug regression
(gh11189, bug40770/54268/76846, str_repeat, debug_backtrace_sensitive_named_variadic).

Generator/API: pure userland (`str_repeat`, `ini_set('memory_limit',...)`,
`zend_test_emalloc(1GB)` — `oom_hard_limit_exceeded.phpt:12`, `register_shutdown_function`
`oom_after_main_script.phpt:9` / `oom_pending_at_shutdown.phpt:7`).

What they encode as load-bearing (and why the parent should care): OOM raised in R1's
*shutdown sequence* (`oom_pending_at_shutdown.phpt:2`) or at end-of-script
(`oom_after_main_script.phpt:2`) previously escaped reporting and poisoned the worker's
next request; the patch's `main/main.c:1930/2025` resets are the fix. Remote value
without Rank-1/2 producer: none — but they are the formal proof that persistence was
the vulnerability class.

### Rank 5 — userland sinks and non-default-surface paths (the long tail)
Verdict: **not remotely triggerable** over stock HTTP without an application endpoint
feeding request data to the API; **fully-mitigated-by-patch** w.r.t. engine state.

Families (test counts in parens) and blocking constraint:

| Family | Generator/API | Blocking constraint for stock-HTTP |
|---|---|---|
| `Zend/tests/oom_json_decode_001..007` (7); `ext/json/tests/oom_json_decode_utf8_substitute`, `oom_json_encode_*` (4) | `json_decode()`/`json_encode()` | needs app code passing `php://input`; json body NOT parsed by RINIT in stock PHP |
| string fns: wordwrap×3, str_repeat, str_replace/ireplace, strtr, str_pad, str_split, str_getcsv, explode, implode, chunk_split, str_word_count, nl2br, substr_replace, levenshtein, setcookie, unpack (~16) | string sinks | userland only; wordwrap leans on `memory_limit` reached via attacker length |
| `ext/mbstring` oom_* (~24) incl. `mb_parse_str` | mbstring conversions | `encoding_translation` default Off (`mbstring.c:946`); else userland only |
| `ext/pcre` oom_* (8) | `preg_*` | userland; needs attacker-controlled subject at limit |
| `ext/iconv` (6), `ext/intl` (4), `ext/imap` (1) | charset/normalizer | userland |
| `ext/date` oom_* (14), `ext/date` parse_date/iso | `strtotime`, `DateTime*` | userland |
| `ext/gd` (13), `ext/exif` (5), `ext/standard/tests/image/*` (3) | `imagecreatefrom*`, `exif_read_data`, `getimagesize*` | needs app to process attacker-up-loaded image at limit |
| `ext/xml`(3), `ext/xmlreader`(7), `ext/simplexml`(4), `ext/dom`(1), `ext/libxml` | XML parsers | userland; XXE-class surfaces, not the OOM path |
| `ext/soap` (8+2 inc) | `SoapServer->handle()` | needs app SoapServer endpoint; remote XML → userland |
| `ext/tokenizer` (1), `ext/hash` pbkdf2 (2), `ext/filter` (6), `ext/fileinfo` cdf (1), `ext/bz2`(3), `zlib`(9 incl. gzdecode/gzfile/inflate filters), `ext/standard/tests/file|streams|serialize` (~12), `ext/curl` (2+responder), `ext/bcmath`(1), `ext/shmop`, `ext/standard/tests/array`(2) | misc sinks | userland only |
| `ext/opcache/tests/jit/frameless_interrupt*` (3), opcache C hunks (JIT/persist) | JIT interrupt paths | needs opcache+JIT enabled (non-default web), userland |
| `ext/zend_test/*` (5), `zend_test_handle_post_data` | zend-test helpers | extension not built/shipped in stock |
| `sapi/fpm/tests/oom_request_parse_body_multipart_options_post_max_size.phpt`, `bug77023` | `request_parse_body()` (8.4 userland API) | requires userland call; `session.c:3269-3271` explicitly excludes the post-`modules_activated` case ("corrupts the session") |
| `sapi/cli/tests/oom_{request_parsing,shutdown_function}_next_request.phpt` (2) | CLI multi-request simulation | CLI only; encodes the cross-request persistence invariant |
| `tests/output/*` (2), `tests/basic/*` misc | output handlers | userland/config |
| `ext/exif/tests/oom_exif_*` (5) + inc big-thumbnail | EXIF parse | needs attacker file processed by app |
| GHSA-f883-x959-3vr9 (11) + GHSA-96wq-48vp-hh57 (1) | multipart corpus + header() | counted under Rank 1 / userland respectively |

---

## 2. Per-branch inventory of the 4 security-carrying families (ax a–d)

| Family | (a) producer over stock HTTP | (b) consumer over stock HTTP before RINIT | (c) allocator divergence R1/R2 | (d) codec/format constraints |
|---|---|---|---|---|
| rfc1867 multipart parse (`rfc1867.c`, 31 diff hunks) | YES — any POST multipart; window gated by post_max_size≳memory_limit (~non-stock arithmetic but stock knobs) | YES — `$_POST`/`$_FILES` registered at `main.c:1906` startup | YES | boundary/headers; `max_multipart_body_parts=-1` (`main.c:836`) |
| upload_progress session flush (`session.c:3223-3238`) | YES — POST multipart with `PHPSESSID`+`PHP_SESSION_UPLOAD_PROGRESS`; **enabled by default** (`session.c:944`) | YES — decodes+rewrites session file pre-RINIT (`session.c:3223` comment); R2 consumes the file by SID | YES | `session.serialize_handler=php` default (`session.c:925`); SID order-first in body (`oom_rfc1867_upload_progress.phpt:26-31`); `use_strict_mode=0` default |
| urlencoded GET/POST parse (`php_variables.c`) | YES — GET always parsed; POST urlencoded stock | YES — auto-globals at startup | YES | `max_input_vars=1000`, nesting 64 (`main.c:811-812`) — caps amplification |
| unserialize (`var_unserializer.re`, 21 hunks) | NO — userland/session path only | indirectly via session decode (row 2) | YES | php/php_binary/php_serialize codecs; post-patch incomplete-classes-only (`session.c:970-976`) |
| zend engine OOM state (`zend_alloc.c` 37 hunks, `main.c` 11, `zend_execute_API.c`) | no (needs in-request allocation) | shutdown/next-request persistence carrier itself | YES — the divergence *is* the vuln | n/a |
| mbstring encoding translation | conditional — needs `encoding_translation=1` (`mbstring.c:946` default 0) | YES when enabled (RINIT conversion) | YES | declared http_input charset |
| json / string / date / gd / soap / etc. sinks | NO | NO | YES | per-API formats; userland-required |

---

## 3. Sovereign-honest verdict

**Does a pure-HTTP universal Stock-8.4.4 RCE exist without grooming? NO.**

Reading the vendor's own 279-test map top to bottom: the only fully-remote,
config-default producer→consumer chain is multipart + `session.upload_progress`
(Rank 1), and even its best pre-patch outcome on an unconfigured 8.4.4 instance is:
cross-request **state poisoning / session-data disclosure** ("$_SESSION left in the
symbol table", `rfc1867_no_user_code.phpt:81-86`; tampered session record persisted by
`php_session_flush(1)`, `session.c:3237`), plus a persistent-worker OOM oracle. Two
independent blockers stand between that and universal RCE: (1) the OOM window itself is
not default-reachable (`post_max_size=8M` vs `memory_limit=128M`, `main.c:809,827` —
the vendor tests require `post_max_size=1G`, `oom_rfc1867.inc:44-50`); (2) weaponizing
the persisted half-mutated state needs either a deserializable POP chain on the target
or heap grooming in the worker to land attacker data over the leaked allocations.
Every other covered path (unserialize, json, zend engine, the ~200 userland sinks)
requires in-request code execution, a non-default INI (`encoding_translation`,
opcache+JIT), or application cooperation, and is **fully-mitigated-by-patch** as far as
the engine state machine is concerned. Rank-1 remains an "A-tier primitive +
environment-dependent escalation" — incomplete without heap-grooming — not a universal
remote RCE.
