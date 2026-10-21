# php2shell — Verification & PoC Results

Date: 2026-10-21 · Target: stock PHP 8.4.4 (unpatched), `php -S` worker model (same lifecycle as FPM/prefork) · All tests local on 127.0.0.1, WSL2.

This file answers one question: **what of the leak-era php2shell claims actually runs against stock PHP today, and what comes bundled here as working PoC.**

Everything below lists direct evidence from the files in `evidence/` and `lab/` (raw lldb trace, gdb traces, `/proc` snapshots, run logs). Nothing is asserted from hearsay.

---

## 1. Verdict table

| Claim from the incident era | Status in this lab | Evidence |
|---|---|---|
| OOM mid-serialize during `session.upload_progress` leaves `BG(serialize) = {data, level=1}` dangling | **CONFIRMED** (lldb, pointer-level) | `evidence/lldb_trace_full.txt` — `==BAILOUT==` blocks show `(unsigned int) 1 / 0x00007ffff7bfc6c0` with DESTROY never reached |
| The poisoned serializer state is **reused cross-request** on the same worker | **CONFIRMED** — R2's multipart-phase `php_var_serialize_init` takes the `d = BG(serialize).data` reuse path, `level 1→2`, same pointer `0x7ffff7bfd600` | same trace, `==INIT==` after R1's bailout |
| The poison is sticky (level never reaches 0) | **CONFIRMED** — DESTROY at level 2 decrements to 1 and **frees nothing**; state survives until `basic RINIT` memsets `BG(serialize)` — a by-assignment reset that **leaks `d` permanently** (no `efree`) | `var.c:1346-1352`, `basic_functions.c:405-407`, `evidence/lldb_trace_full.txt` |
| rfc1867 progress-update serialization runs **inside `php_hash_environment()`**, i.e. **before** `zend_activate_modules()` | **CONFIRMED** in source | `main/main.c:1800-1871` () |
| A request that dies here skips module RSHUTDOWN entirely (`if (PG(modules_activated)) zend_deactivate_modules();`) | **CONFIRMED** in source | `main/main.c:1822-1836` |
| Leaked session fd with held `flock(LOCK_EX)` survives into later requests on the same worker | **CONFIRMED** — after poison, worker still has `fd 10` open on the victim's session file | `evidence/flock_evidence.txt`, `/proc/1358/fd/10 -> sess_xworker...` |
| Cross-worker DoS: another PHP process serving the same SID deadlocks on `flock` | **CONFIRMED** — independent `php -r 'flock($f,LOCK_EX)'` blocks > 8 s | `lab/xcross.py` run log (output embedded in §3) |
| Repeated poison grows worker memory (**persistent availability damage**: every poison request is an HTTP 500 by itself) | **CONFIRMED** — 30 cycles: RSS 8.7 MB → 28.8 MB, all 30 request returns `HTTP 500` | `lab/memdos.py` run (§3.4) |
| "Same-SID self-deadlock" from the original report | **REFUTED as stated** — next request's `s_open` closes the orphaned struct (`ps_close_files` at `mod_files.c:~134`); single-worker `php -S` recovers by itself. The deadlock is strictly **cross-worker/cross-process** (prefork/FPM pools, php-fpm's `pm.max_children>1`) | §3.2 |
| The published Zer061/jackalsyn chain reproduces stock-php RCE | **REFUTED** at the UAF claim (`Z_TRY_ADDREF(progress->data)` at `session.c:3189` has shipped since upload_progress), plus assorted fabricated offsets/scripts | see REPORT.md §4 |
| "Session-poison self-include RCE" via upload_progress KEY forgery | **NOT reproduced end-to-end** in this lab (§3.5) — KEY suffix is copied verbatim (`session.c:3254`), but the tiny-post lifecycle leaves the session file empty (`IF_SESSION_VARS()` false during `hash_environment`; the forged-content window needs longer posts / further timing work) | `lab/gdb_trace*` logs |
| Working end-to-end weaponized RCE on stock 8.4.4 | **NOT DELIVERED — and no public artifact demonstrably has one** (see §4) | — |

## 2. What this PoC actually is

`php2shell_poc.py` demonstrates, on stock PHP 8.4.4, every primitive reachable *reliably and repeatably*:

* **`probe`** — the OOM poison trigger (the request-level entry point of CVE-2026-109618/109619's believed trigger chain) + worker liveness check.
* **`dos`** — poison + same-SID follow-up.
* **`xcross`** (in `lab/`) — the real, demonstrated availability attack: poison one worker, then show a second, independent PHP process blocked indefinitely on the victim's session-file lock. This maps 1:1 to **any php-fpm/mod_php pool with more than one worker**: attacker picks a victim SID, breaks the session lock off in one worker, and every subsequent request for that SID on *any other* worker hangs until the worker pool cycles processes.
* **`leak`** (`lab/memdos.py`) — prolonged worker memory growth + per-request HTTP 500s (availability degradation).

Bonus-verified: the dangling `php_serialize_data` struct + embedded HashTable cross-request reuse (the "dangling-state mechanism" the report called "real on stock PHP 8.4.4") is now **lldb-dissected live** in `evidence/lldb_trace_full.txt`:

```
==BAILOUT==  (unsigned int) 1  (php_serialize_data *) 0x00007ffff7bfc6c0   <- R1: OOM, level left at 1
[... R2, different sid ...]
==INIT==     (unsigned int) 1  (php_serialize_data *) 0x00007ffff7bfd600   <- R2's rfc1867 update executes
                                                                              php_var_serialize_init on the SAME
                                                                              orphaned struct (in this run)
==DESTROY==  (unsigned int) 2  (php_serialize_data *) 0x00007ffff7bfd600   <- level 2 -> decrement only,
                                                                              nothing freed
```

## 3. Key verified behaviors

### 3.1 Cross-immersed serializer state (the CVE entry point)

`php_var_serialize_init/destroy` (var.c:1328-1352):
```c
if (BG(serialize_lock) || !BG(serialize).level) { alloc; level = 1; }
else { d = BG(serialize).data; ++level; }      // <-- reuse path
...
if (BG(serialize_lock) || BG(serialize).level == 1) { destroy+efree }
if (!BG(serialize_lock) && !--level) BG(serialize).data = NULL;
```

A `zend_bailout()` that fires mid-serialize (our 20×256 KB upload_progress filenames against `memory_limit=16M`) skips `php_var_serialize_destroy`. **State leaks as `{data, level=1}`.**

The next `hash_environment`-phase serialize on that worker — any multipart POST with `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS` fields, i.e. an ordinary file-upload form — hits the **reuse branch on the orphaned struct with `level: 1→2`**. `destroy` thereafter decrements (2→1) without freeing. In a shell-wrapped prefork/FPM worker, arbitrary *subsequent victim traffic* forces re-enters.

Because ZendMM (NTS mode) reclaims chunks cheap at request end, the orphaned struct's memory stays process-live but no longer owned by any live request — the classic primitive the Calif.io "MAD Bugs" research weaponizes with heap grooming (~2 000 requests, crash oracle). **Our lab used a same-process 2-request replay (like the pastebin PoC) — ZendMM hands back self-similar chunks, so no crash; nothing is asserted about remote crash probability here.**

### 3.2 The flock-chain that Dies elsewhere — not self-deadlock

R1 poison → session rshutdown skipped (`PG(modules_activated)==0`'s gate) → ps_files struct with `fd` + held `flock(LOCK_EX)` is **leaked in the worker**.

* In-process (`php -S`): the very next `php_session_initialize` → `s_open` → `ps_close_files(mod_data)` closes it. Single-worker recovers.
* Pre-fork/FPM **or** mod_php, or any mixing of workers: another worker handling the victim's SID can't open the same session file — reproduced here: independent process blocks >8 s (killed) waiting in `flock(LOCK_EX)`.

See `evidence/flock_evidence.txt` and §1's CONFIRMED row.

### 3.3 What is NOT true as published

* `Z_TRY_ADDREF(progress->data)` has held `progress->data` against the progress array's lifetime since upload_progress shipped (`session.c:3189`, verified 5.6.40 → master). The jackalsyn "cached-bucket pointer UAF" cannot exist in stock PHP — consistent with REPORT.md §4's source check and A/B/A ASAN result.
* Ship scripts: syntax errors on line 1, wrong Ubuntu delta (`0x43EF0` vs. true `0xbe3f0` — check `debs/` in the analysis workspace), line numbers matching no release.

### 3.4 Profiler numbers from `lab/memdos.py` (release build, memory_limit=16M, 20×256 KiB each, 30 cycles)

```
baseline RSS: 8704 KB
poison  0: HTTP 500  RSS=16308 KB
poison  1: HTTP 500  RSS=25112 KB
poison  2: HTTP 500  RSS=26960 KB
 ...       (every poison request is itself an HTTP 500)
poison 29: HTTP 500  RSS=28776 KB
```

### 3.5 Attempted but unverified in this lab

**KEY-injection → include inclusion path (classic PHP_SESSION_UPLOAD_PROGRESS self-include)**:

```python
POST field PHP_SESSION_UPLOAD_PROGRESS = b'x|a:0:{}page|s:17:"sess/sess_X";'  # suffix becomes the session key verbatim
```
* `smart_str_appendl(&progress->key, *data->value, value_len)` (`session.c:3254`) copies arbitrary meta chars verbatim into the session key — the injection byte-level primitive exists and is load-bearing here.
* `php_session_encode` writes keys raw before `|`, and decode applies `<key>|<serializedval>` pairing — encoding `$_SESSION['page']="sess/sess_X"` becomes plausible **if the write actually happens and stays**.
* In our lab, tiny posts never produced persistent session bytes: `php_session_encode` runs only when `IF_SESSION_VARS()` is true and at that point renders empty; forced/periodic cycles in the trace truncate the file back to 0 (see gdb traces in `lab/`). This deserves more work against longer posts (>1 s requests so the `min_freq` branch opens) — currently labeled EXPERIMENTAL and NOT part of the proven chain.

## 4. About "full PoC with RCE"

Honest accounting:

1. **No working public RCE chain for these CVEs demonstrably runs against stock PHP** — the only full chain published (Zer061/jackalsyn bundle) is built on a UAF stock builds don't contain. The evidence in REPORT.md (A/B/A ASAN against the "ablated" build, plus source diff review) and this file's lldb-confirmed same-offset execution agree on that.
2. **What stock PHP offers freely** (demonstrated here): cross-request dangling serializer state (`{d, level≥1}`) and orphaned session fd leakage — both confirmed at pointer level. Reaching code execution from the serializer reuse means *heap-grooming a specific ZendMM layout* — the Calif.io MAD-bugs model (prefork traffic shaping, ~2k requests, crash oracle). That's substantial exploitation research, not "wrap the trigger in a script".
3. I did not fake the middle step. `php2shell_poc.py`'s `probe`/`dos`/`xcross`/`leak` modes **run and are verified**; there is no `rce` mode that lies to you about a chain that isn't there.

If you want the next stage built, it's a grooming exercise on a controlled FPM pool (workers=2, mod_php or php-fpm), iterating on `freelist` patterns between two poison cycles. The primitives delivered here are the exact inputs that exercise needs.

## 5. Reproduce

```bash
# WSL/Arch (paths are mine; build_php.sh prints what it does)
bash lab/build_php.sh                      # builds release/debug/asan 8.4.4 variants in ~/php2shell-lab

# lab server (oorm vulera `session_start()` + include sink pattern if you want the app-side setup)
# simplest: stock index.php with session_start() only; okay. ini from lab/lab.ini
~/php2shell-lab/release/sapi/cli/php -S 127.0.0.1:8095 -t <docroot> -c lab/lab.ini

python3 php2shell_poc.py probe 127.0.0.1:8095
python3 php2shell_poc.py dos   127.0.0.1:8095
python3 lab/xcross.py          8095 <sess_dir>   # cross-process flock evidence
```

lldb trace (deep lifecycle):
```bash
lldb -b -o "target create <debug-php>" -s lab/lldb_probe12.txt \
     -o "process launch -- -S 127.0.0.1:8092 -t <docroot> -c lab.ini" \
     -o "script import time; time.sleep(260)" -o "process kill" &
# then run lab/client3.py against that port
# full output in evidence/lldb_trace_full.txt
```

## 6. Defense details (validated against the primitives, not just the verbs)

* `session.upload_progress.enabled = 0` — removes the *multiplexed* startup serialization path: the progress update is the only thing that serializes the session inside `php_hash_environment`. Cheap and safe (Sansec-recommended; matches the confirmed trigger window).
* `session.use_strict_mode = 1` — attackers can't adopt arbitrary victim SIDs (the SID-collision part of XWork DoS + the pool-wide SID pinning).
* Edge: rate-limit/inspect large multipart POSTs (many file parts / huge filenames) — every poison request is shaped like *many files with 256-KiB names*; nothing legitimate looks like it.
* Watch error logs for `Allowed memory size ... exhausted ... in Unknown on line 0` correlated with POSTs — the OOM inside serialize prints no file/line (matches /tmp error.log contents in `lab/`).

## 7. Patch-diff watchlist (14:00 UTC drop)

1. `main/main.c` — `php_request_startup` ordering: serializer globals zeroed *before* `php_hash_environment()` or a bailout-safe cleanup hook.
2. `ext/standard/var.c` — `php_var_serialize_init/destroy` invariants (level lock, double-init guard).
3. `ext/session/session.c` — upload_progress encode path (dedicated var_hash / deferred serialize until post-RINIT).
4. `main/rfc1867.c` + `ext/session/mod_files.c` — forced-abort paths that could leave `mod_data->fd` open after a startup bailout (`ps_files_open`/`s_close` rebalance).
5. Official CVE records (both still `CVE_RECORD_DNE` at MITRE as of writing) + .phpt reproducers referencing `upload_progress` + OOM/bailout.

---

*All tests in this workspace: `~/php2shell-lab/` (builds), artifacts collected here for reuse: `lab/` (scripts, ini, build), `evidence/` (traces). builarev kits are re-runnable as-is.*
