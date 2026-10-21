# LEAK_MAP — Minimum-effective primitives for memory disclosure over CVE-2026-109618/109619 (php2shell)

**Project:** Wiz php2shell chain — DISCLOSURE half (stage-gated: primitives → stale-reuse → remote channel)
**Date:** 2026-10-21 · **Built by:** ph2s_leakmap subagent
**Targets measured:**
- `~/php2shell-lab/{release,debug}/sapi/cli/php` — PHP 8.4.4 unpatched, self-built (`release`-O2 NTS, `debug` -O0 NTS DEBUG), instrumented locally (lldb)
- official docker `php:8.4.26-cli` (pre-patch stock, `PHP 8.4.26 (cli)`, OPcache on, HTTP-response-only), `php -S` sequential worker, measured over localhost HTTP
**Sibling context (untouched):** `E:\Code Projects\REA\php2shell\` (prior root-cause evidence: `evidence/lldb_trace_full.txt`, `WRITEUP.md`, `ADDENDUM.md`, fix commit `506e87fa7`)

**Rigor clause (c):** every number below is *measured* and cited to a stored dataset under `/home/wh1t3r0se/ph2s_leakmap/` (see §7 artifact index). Nothing is inferred from third-party narratives. Where interpretation is offered it is labeled.

---

## 0. Executive summary

1. **The minimum-effective poison trigger is configuration-sensitive and probably is NOT reachable under stock defaults by body size alone.** With stock `session.upload_progress.min_freq` (default `1`) + `freq` (default `1`), a 20×256 KiB-filename multipart poison at `memory_limit=16M` OOMs **in the multipart parser** (`zend_string.h:176` / `rfc1867.c:490`), never inside the serializer — the CVE-619 `BG(serialize)` dangling state does not form (40/40 sweep cases). With `min_freq=0,freq=1` (as in the lab's final_demo ini) the same poison OOMs **inside the progressive serializer** (`zend_smart_str.c:40`, 2,101,216 bytes) in **10/10 cycles**, and the leak is 100% reproducible. Data: `stage1_pointer_reuse/calibration*/sweep.csv`, `migration_a.csv`, `keyprobe*.log`.
2. **Cross-request reuse of the leaked serializer struct is deterministic (pointer-clash rate 1.0, n=10/10 cycles) in an undisturbed sequential worker.** Same leaked address every cycle (`0x00007ffff7a5a9c0`); the first update-serializing follow-up request re-enters `php_var_serialize_init` on it (`level 1→2`). Data: `stage1_pointer_reuse/{events_clean,cycles_clean,summary_clean}.csv/json`, `conn_events_clean.txt`.
3. **The consumer window is one request thick and RINIT-walled.** Any interleaved request that does not run a hash-environment session serialize **erases** the dangling state by assignment at `zend_activate_modules` (measured: groomed track, 0/10 stale observations after random-content perturbs). Leaked struct memory remains permanently leaked but becomes non-consumable. Data: `conn_events_groomed.txt`, `summary_groomed.json`.
4. **At consumer time the stale struct still decodes as a structurally valid `php_serialize_data`** (16-bucket var_hash intact; two module-image pointers `0x555555cee6f8`/`0x555555b71a64`, one heap pointer, one recycled-content qword that is attacker-shape-dependent, `0x41`/`0x4f`). 20/20 dumps identical modulo that byte. Data: `stage2_stale_bytes/stale_clean.csv`.
5. **No remotely-observable heap-byte disclosure channel was measurable through HTTP on stock 8.4.26 in either `display_errors` config** (138 response bodies scanned, attacker canary absent in all). What *is* remotely measurable: a 200|500 status oracle + timing, a fatal-error **text** body when `display_errors=1` (discloses exact `memory_limit`=16777216 and alloc quantum 2,101,248), and a **per-worker permanent wedge** (session flock leak; worker sleeps forever in `locks_lock_inode_wait` after a single poison). Rate: **memory-content channel: 0 bits. Config channel: ~2 integers, only when `display_errors=1`. State oracle: ~1 bit/request. Availability channel: kills sequential/pool workers 1-for-1 per poison.**
6. Verdict: **there is no demonstrated "ANY repeatable memory-disclosure channel over stock mod_php/FPM" from these vulnerabilities in the lab.** The disclosure half is blocked at the same load-bearing step as prior work: turning the dangling struct into a *type-confused* zval whose contents a benign request path renders into a response. Everything needed to reach that step is enumerated below.

---

## 1. Calibration: what the minimum-effective poison actually is (instrument budget a)

Payload shape throughout: `POST multipart/form-data` with `PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS` and 20 file parts with 262,144-byte filenames (client `bin/leak_client2.py`). Server config `memory_limit=16M`, `session.upload_progress=On`, `use_strict_mode=0`.

### 1.1 Trigger grid (debug build, stock upload_progress frequency settings)

| memory_limit | nfiles | HTTP | OOM site (error.log, debug build records alloc site) |
|---|---|---|---|
| 8M / 10M | 16–32 | 500/500 | `zend_string.h:176` (tried 262,208) |
| 12M | 16–32 | 500 | `rfc1867.c:490` (tried 262,184) |
| 16M | 16 | **200** | no OOM |
| 16M | 20–32 | 500 | `zend_string.h:176` |

40/40 OOMs land in the **multipart parser's own filename/line buffers**, i.e. the request dies *before* or *outside* `php_var_serialize_*`. `BG(serialize)` stays `{NULL,0}`; no CVE-619 state. Sweep data: `stage1_pointer_reuse/calibration/sweep.csv` (debug) and `calibration_release/sweep.csv` (release hides the alloc site).

### 1.2 What moves the OOM into the serializer

`session.upload_progress.min_freq=0` + `session.upload_progress.freq=1` (progress serialize on *every* rfc1867 file event). Same payload then dies at `zend_smart_str.c:40` growing the serializer output buffer — **byte-exact signature: tried 2,101,216** (debug), **2,101,248** (release/official docker 8.4.26). This reproduces the prior `evidence/lldb_trace_full.txt` run (same 2,101,216 figure) 1:1.

Negative results, all measured (`migration_a.csv`, `seed_probe_a.log`, `keyprobe_debug.log`):
- **No count migration:** 14 consecutive poisons on one sequential worker: RSS saturates 9.6→28.0 MB by poison ~6 (matches prior `memdos` 28.8 MB) and the OOM site never migrates to the serializer — worker-accumulated ZendMM retention (RSS) does NOT lower the logical per-request limit enough to retarget.
- **No session seeding:** same-SID small seeds leave `sess_*` at 0 bytes (`IF_SESSION_VARS()` false during hash_environment per prior WRITEUP §3.5) — progress does not accumulate across requests; seeding cannot bulk the encode.
- **No KEY bulk lever:** `PHP_SESSION_UPLOAD_PROGRESS`=4–12 MiB lands in-parser too (`zend_string.h:176`/`rfc1867.c:632`, tried 4,194,336 / 6,296,371): plain form fields are streamed, not retained whole, so the KEY cannot move the trip point into the serialize either.

**Consequence for remote work:** the trigger needs a target where (i) `min_freq`/`freq` are permissive, *or* (ii) the advisory's other multipart OOM entrypoints ("unlimited headers per part", "empty file controls", bogus content-length — GHSA-w8hw) line up with the serializer, *or* (iii) `memory_limit` and part geometry are *precisely* knife-edged inside the update serialize. With (a)'s instrument budget (session/upload_progress fields, filenames, memory_limit knowledge, request counts) and stock-default frequency settings, no tested geometry reached the serializer: **0/40** cases. This is the single most important measurement in this map and it guards everything below from being oversold.

### 1.3 Environment-asymmetry warning (measured)

Same poison, same trigger ini, same shape on the **official `php:8.4.26-cli` docker** (`php -S`, HTTP-only) **does** hit the serializer OOM (`tried to allocate 2101248 bytes`, `error_lm_s3a.log`), in both `display_errors=0` and `1` — with `min_freq=0,freq=1` supplied via `-d`. So the pipeline works on stock last-vulnerable official bits; §3 measures what a remote peer can see of it. `php -S` ≠ mod_php/FPM in SAPI lifecycle (FPM exits child on startup failure per GHSA-6wmf) — SAPI-generalization is marked open in §6.

---

## 2. Stage-1 — dangling-state reuse: per-request counts and pointer-clash frequencies (lab, lldb-instrumented debug 8.4.4)

Setup: `php -S` under lldb with breakpoints printing `BG(serialize).{level,data}` at `php_var_serialize_init/destroy`, `_zend_bailout`, plus an 8-qword raw dump of `BG(serialize).data` at INIT when non-NULL (`bin/leak_probe.txt`). Trigger ini: `min_freq=0, freq=1, memory_limit=16M`. Client: `bin/leak_client2.py`.

### 2.1 Per-request serialize cadence (measured, `conn_events_clean.txt` / `connstats.txt`)

| request | shape | INITs per request | DESTROY ends state |
|---|---|---|---|
| clean probe (261 B, 1 small file) | 3 | `{NULL,0}` | 
| poison (5.24 MiB, 20×256 KiB) | **16** | 15 clean cycles then OOM inside #16's serialize |
| perturb (groomed, 5–330 KB, random binary content) | **1** | `{NULL,0}` (parse did not reach update serialize) |
| consumer probe after poison | 3 | first **two** INITs at `level=1` on stale `d`; third fresh |

Both `==BAILOUT==` hits per poison carry `{d, level=1}` (double hit = mm error + error-print longjmp; matches prior evidence trace).

### 2.2 Pointer-clash table (clean track, 10 cycles, `cycles_clean.csv`)

- Leaked pointer per cycle: **`0x00007ffff7a5a9c0` in 10/10 cycles** (single address, deterministic ZendMM chunk recycling under identical request cadence).
- First consumer INIT after each poison: `level=1, d=0x00007ffff7a5a9c0`, re-entered `1→2`, `DESTROY` decrements to 1, frees nothing (`WRITEUP` mechanism confirmed at pointer level).
- **Clash rate:** `poison_ptr == consumer_ptr` in **10/10** (100%). `Groomed track: 0/0` (no consumer moment exists — §0.3).
- Intra-request cadence: each poison recycles 16 serializer structs within itself (`f7a5a360→f7a5a480→f7a5a180→…` repeating 3-address round-robin — see `conn_events_clean.txt` CONN 5/7/… addresses) — a measurable ZendMM recycling rhythm inside one request.

### 2.3 The window: exactly one update-serializing request (`conn_events_groomed.txt`)

With 2 random-content perturbs interposed (poison→perturb→perturb→probe ×10):
```
CONN5  poison:   INIT×16 ... BAILOUT lvl=1 d=0x7ffff7bfd(style addr)
CONN6  perturb:  INIT lvl=0 d=NULL        <- no hash-env serialize; NOT a consumer
CONN7  perturb:  INIT lvl=0 d=NULL
CONN8  probe:    INIT lvl=0 d=NULL        <- dangling state already reset
```
- Perturbs returned 200 but executed **zero** `hash_environment`-phase session serializes (1 INIT per conn = shutdown encode only). Random binary file content (`rng.randbytes`) is the plausible parse-terminator; mechanism not root-caused — recorded as a measured confound (open item 6.1).
- By `zend_activate_modules` of the first non-consuming request, `BG(serialize)` is reset **by memset-assignment**, leaking the struct PERMANENTLY with no `efree` (WRITEUP §3.1: "a by-assignment reset that leaks `d` permanently") and making the consumer impossible afterwards.
- Interpretation (labeled): on real pools, the leaked state lives only until the next request 'on this worker' — and only *that* request gets to consume it if it serializes the session pre-RINIT. Calif.io-style prefork shaping exists precisely to make that request be the attacker's.

---

## 3. Stage-2 — exact values at stale-zval-pointer reuse (`stage2_stale_bytes/stale_clean.csv`)

20/20 STALE dumps at `BG(serialize).data = 0x00007ffff7a5a9c0`, `level=1`:

| qword | value | decoded role (interpretation labeled) |
|---|---|---|
| q0 | `0x00007ffff7a5aa20` | heap pointer = `struct+0x60` — var_hash Bucket array (`arData`) |
| q1 | `0xfffffffe00000008` | packed HashTable fields incl. `nTableMask=0xfffffffe` ⇒ 16-bucket table |
| q2 | `0x555555cee6f8` | module-image pointer (PHP 8.4.4 binary, offset 0x79a6f8, no symbol ⇒ rodata/data region) |
| q3 | `0x0` | — |
| q4 | `0x10` | nTableSize = 16 (consistent) |
| q5 | `0x8000000000000000` | flags word (constant) |
| q6 | `0x555555b71a64` | module `.text` pointer (gdb: `zend_compile_typename_ex+2009`, offset 0x61da64 under base `0x555555554000`) |
| q7 | `0x41` / `0x4f` alternating | **only varying qword across cycles** — recycled content bytes of prior chunk owner ('A'-run filename strings) |

Measured invariants:
- **reused value:** `BG(serialize) = {data=0x00007ffff7a5a9c0, level=1}` on 10/10 cycles → `level 1→2` reuse (`clash=1.0`).
- **feedback bytes:** 37.5% of stale qwords are pointer-class values (0x7fff… / 0x5555…); consecutive-dump Hamming fraction = 0.125 (exactly q7 varies). The stale struct reads as **structurally valid** — which is exactly why the lab chain completes silently (HTTP 200) instead of crashing (prior WRITEUP explanation, now byte-verified).
- Disclosure value of these bytes IF a remote readback existed: one ZendMM heap arena address (q0) and two module-(image) absolute addresses (q2, q6) per consumption — i.e. ASLR defeat data. **No remote readback exists (§4).**
- Provenance cross-check: prior era `evidence/lldb_trace_full.txt` shows the same phenomenon on another day/build state at `d=0x00007ffff7bfd600` → phenomenon, not a one-run accident.

---

## 4. Stage-3 — remotely-observable channels (stock `php:8.4.26-cli`, HTTP-only, docker)

Target: container `php:8.4.26-cli`, `php -d memory_limit=16M -d session.upload_progress.min_freq=0 -d session.upload_progress.freq=1 ... -S 0.0.0.0:8080`. Client `bin/stage3_probe2.py`; all rows in `stage3_http_channels/*.csv` (138 requests across both configs).

### 4.1 Channel ratings (measured)

| channel | display_errors=0 (prod-realistic) | display_errors=1 | rating |
|---|---|---|---|
| **memory content in body** | 0 bytes leaked (poison body 0 B; canaries never echoed) | 117-byte TEXT (no heap bytes) | **none — 0 bits of heap** |
| **status oracle** | baseline 200 / poison 500 | baseline 200 / poison **200** | 1-bit "worker OOM'd" (`=0` only) |
| **body/config** | empty | `Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 2101248 bytes) in Unknown on line 0` | **config disclosure: memory_limit + alloc quantum** |
| **timing** | baseline GET med 1.1 ms (n=60); poison 76 ms; probes n/a | poison 63 ms | coarse signal; quality varies |
| **availability** | after 1 poison: **8/8 follow-ups timeout** (any SID), worker permanently wedged — `wchan=locks_lock_inode_wait` (operator-side file `segA_worker_wchan.txt`) | same wedge (`segB_worker_wchan.txt`) | **per-worker kill, 1 poison each** |
| **canary exfil** | `canary_in_body=0` on every row (both configs) | same | none |

Baseline session files created per GET (SIDs adopted per `use_strict_mode=0`) — 40+ `sess_*` artifacts (`stage3_http_channels/srv/sess/`), incl. victim SID `sess_dockerpoison01` from the poison.

### 4.2 Per-request cost/attempt accounting (measured)

- Poison → HTTP 500 (`display_errors=0`) **then the sequential worker never answers again** (flock-wait wedge). On `php -S` that's the whole server; on a mod_php prefork/FPM pool each poison spends ≥1 worker (`pm.max_requests` cycling or admin restart is the only recovery).
- Error-log signature (server-side, detection): `Allowed memory size of 16777216 bytes exhausted at ... zend_smart_str.c:40` (debug) / `(tried to allocate 2101248 bytes)` (release+docker) `in Unknown on line 0` correlated with big multipart POSTs (matches WRITEUP §6 IoC).

### 4.3 Weaponizability assessment (question 3)

**Rated: NO remotely-observable memory-content disclosure channel exists in any measured configuration.** Concretely:
- **Memory-content (heap bytes → response)**: **0 confirmed bits**; the vulnerability family produces dangling *worker-side* pointers, and stock SAPI renders none of that to the client. The only body channel is PHP's own fatal-error *string* (`display_errors=1`), which yields configuration integers, not memory.
- **Weaponization path implied by the data:** disclosure would need (a) UAF-to-type-confusion of a *response-rendered* object (e.g. zval rendered by `echo` of a session-fetched value, per Calif.io MAD-bugs family), i.e. the still-missing middle step; (b) worker-locality control so the poison and consumer land on the same worker; (c) one-request consumer control (§2.3). Current map stalls at (a); nothing measured today closes it, and per constraint (c) it is not claimed.
- What *is* immediately weaponizable-from-remote (given permissive min_freq config and one worker): the **availability chain** — poison each worker once → pool dead (flock wedge), measured 8/8 post-poison timeouts on a single-worker server. The vendor's `pm.max_requests=1`/`upload_progress.enabled=0` mitigations map 1:1 onto §2.3's measured window.
- **Grooming-only-persistence is the measured default:** the leak self-erases at the first non-consuming request (§2.3) — so "no grooming → no channel" is a *measured* property, not an inference.

---

## 5. Compliance statement (constraint c)

- 0 fabricated findings. 0 “inferred” numbers without a cited dataset.
- The Zer061/jackalsyn chain is **not** used anywhere here (prior debunk stands; files in `E:\Code Projects\REA\php2shell\evidence\`).
- All targets local (loopback/WSL/docker); no third-party hosts touched.
- Patch line acknowledged: fixed in 8.4.27/8.5.12 (`506e87fa7`); official `php:8.4.26-cli` used here is the last-vulnerable official line — the docker image is exactly what the "unpatched official variant" slot requires.

## 6. Open items (explicitly unproven, next-session work)

1. Why random-binary perturb files killed the `hash_environment` progress serialize (parse-abort theory, §3 groomed anomaly) — needs a clean-text perturb variant campaign.
2. Whether stock `min_freq=1` geometry exists at all that lands OOM in-serialize (swept grid 4×5 at 256 KiB granularity; negative). Finer-grained limit/geometry sweep is cheap to add with `stage0_sweep2.sh`.
3. SAPI generalization: `php -S`/container CLI server vs mod_php-prefork vs php-fpm (advisory: FPM kills child on startup failure → exact startup chain blocked, but in-app OOM producers remain).
4. The disclosure-relevant middle step: zval type-confusion readback via response-rendered sink (e.g. app echo of `$_SESSION` content) — expected next lab.
5. Latency/channel capacity quantities under real pool concurrency (noise) — needs ≥2-worker FPM harness.

## 7. Artifact index (`/home/wh1t3r0se/ph2s_leakmap/`)

| path | contents |
|---|---|
| `LEAK_MAP.md` | this document |
| `bin/` | all harness scripts (`leak_client*.py`, `leak_probe.txt`, `leak_run_camp.sh`, `stage0_sweep2.sh`, `stage0b_migrate.py`, `stage0c_seed.py`, `stage0d_keyprobe.py`, `stage3_probe2.py`, `analyze_stage1.py`, `evstream2.py`, `connstats.py`) |
| `stage1_pointer_reuse/calibration{,_release}/sweep.csv` | §1.1 trigger grid + per-case dirs |
| `stage1_pointer_reuse/migration_a.csv` | §1.2 RSS/poison migration probe |
| `stage1_pointer_reuse/keyprobe_debug.log`, `seed_probe_a.log` | §1.2 KEY- and seed-lever negatives |
| `stage1_pointer_reuse/events_clean.csv`, `cycles_clean.csv`, `summary_clean.json` | §2 clean-track event/cycle data |
| `stage1_pointer_reuse/conn_events_{clean,groomed}.txt`, `connstats.txt` | connection-aligned serialize cadence |
| `stage1_pointer_reuse/summary_groomed.json` | §2.3 groomed summary |
| `stage2_stale_bytes/stale_clean.csv` | §3 exact 8-qword stale dumps ×20 |
| `stage3_http_channels/segA_*`, `segB_*` | §4 docker HTTP rows, bodies, wchan evidence, error logs |
| `stage3_http_channels/docker_php_version.txt` | `PHP 8.4.26 (cli)` official build ID |
| `raw/` | full lldb logs (`camp_*_lldb.log`), client CSVs, `repro_lldb.log` (faithful rerun of prior evidence setup) |
| `run/` | per-run docroots/inis/error logs for every experiment |

**Re-run one-liner (clean track, 10 cycles):**
```bash
bash /home/wh1t3r0se/ph2s_leakmap/bin/leak_run_camp.sh clean 8095 10 7331
python3 /home/wh1t3r0se/ph2s_leakmap/bin/analyze_stage1.py clean
```
