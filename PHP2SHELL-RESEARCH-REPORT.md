# php2shell — CVE-2026-109618 / CVE-2026-109619: Final Research Report

**Date:** 2026-10-21 (research conducted 07:00–08:30 UTC; PHP security release due 14:00 UTC same day)
**Scope:** Threat-intel consolidation, public PoC landscape assessment, independent technical verification, dynamic root-cause confirmation — all analysis local to `~/php2shell-analysis/`; no traffic sent to any third-party host.
**Companion documents:** `REPORT.md` (deep technical analysis, §1–11), evidence in `run/logs4/`, `build/`, `debs/`, `upstream/`.

---

## 1. Executive summary

| # | Finding | Confidence |
|---|---|---|
| 1 | Two critical PHP-core RCE vulnerabilities (CVSS v4.0 9.2 each, per PHP's security team) leaked pre-embargo on 2026-10-20. Emergency release scheduled 2026-10-21 14:00 UTC. Both CVE IDs remain Reserved/`CVE_RECORD_DNE` at MITRE/NVD as of writing. | High (vendor announcement) |
| 2 | **No verified public RCE exploit exists.** The one full chain published (jackalsyn/Zer061 bundle) is refuted: its claimed `session.upload_progress` cached-pointer UAF does not exist in any stock PHP release. | High (source + dynamic A/B/A) |
| 3 | Most plausible true root cause: **cross-request `BG(serialize)` serializer-state lifecycle bug** (Calif.io-attributed research family), with `session.upload_progress` as the remote trigger vehicle — it forces session serialization during multipart parsing *before* request-init zeroes the serializer globals; a memory_limit bailout mid-serialize leaves `BG(serialize)={dangling, level=1}` for the next request on the same worker. | Medium-high (lldb-confirmed mechanism, §6) |
| 4 | The dangling-state mechanism is **real on stock PHP 8.4.4** — debugger-verified end-to-end on vanilla `php -S`. It does not crash in a two-request lab because ZendMM deterministically recycles the freed chunk into a valid lookalike; exploitation requires heap-layout control (prefork/FPM worker traffic), which is exactly the Calif.io remote-exploitation model. | High (mechanism), Medium (exploitability) |
| 5 | Bonus finding: the same OOM bailout **leaks the session file flock** → same-SID follow-up requests self-deadlock until `max_execution_time` kills the worker. Reproducible availability-only DoS on stock 8.4.4. | High (reproduced on 2 builds) |
| 6 | Stopgaps `session.upload_progress.enabled=0` and `session.use_strict_mode=1` (Sansec) are cheap, safe, and consistent with the confirmed trigger path. Apply now; patch at 14:00 UTC. EOL PHP (≤8.1) gets no official fix. | High |

---

## 2. Timeline of the incident

| When (UTC) | Event |
|---|---|
| 2026-10-20 morning | Hacker News post claims two critical PHP RCEs (leaked: both CVE IDs, "CVSS 10.0", "PHP 5 onward", embargo to Oct 22). Post removed; screenshots circulate. |
| 2026-10-20 ~19:33 | PHP publishes advance notice: two critical flaws, CVSS v4.0 **9.2**, emergency release 2026-10-21 14:00 UTC, earlier if details leak or attacks start. |
| 2026-10-20 | watchTowr confirms the leak is real; says it reproduced CVE-2026-109618. No technical details shared. |
| 2026-10-20/21 | Exploit-tool screenshot ("PHP2Shell", credited to Calif.IO, claims PHP 5.4.0+) circulates. Demo videos posted on X (one showing full-chain RCE on Ubuntu `8.5.4-0ubuntu1.3`); a SHA-256 commitment (`43717fa0…d0abd`) is published for a forthcoming writeup. |
| 2026-10-21 (early) | Wave of GitHub repos appears — mostly empty/README-only; one full bundle (Zer061/jackalsyn); one high-quality independent audit (xuehuolll). |
| 2026-10-21 ~07:30 | This investigation: dynamic debunk of the bundle + debugger confirmation of the BG(serialize) mechanism (see REPORT.md §7, §11). |
| 2026-10-21 14:00 | **Scheduled PHP security release** (fixed versions reported as 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 — note: tags 8.5.12/8.4.27 dated 2026-10-06 exist but contain no relevant fix; security commits expected at release time). |

---

## 3. Public PoC landscape (as of ~08:00 UTC)

| Artifact | Type | Assessment |
|---|---|---|
| `Zer061/CVE-2026-109618` (13★) — mirror of jackalsyn.com "PHP-UP-2026" (J4ck3LSyN) | Full exploit bundle | **Refuted.** Claimed UAF impossible in stock PHP (`Z_TRY_ADDREF` present since PHP 5.4); scripts syntax-invalid as shipped; mixes genuine work (exact LiteSpeed symbol deltas) with fabrication (wrong Ubuntu delta, wrong struct offset for its own target, line numbers matching no release). No malicious code, but live-fire against a hardcoded third-party URL by default. See REPORT.md §1–5. |
| `xuehuolll/CVE-2026-109618-109619-audit` | Independent audit | **High quality; central claims independently re-verified by us.** Debunks the bundle (ablation: removing the addref line reproduces ASAN UAF; restoring it is clean). Reproduced session-poisoning→include RCE (classic technique, needs app LFI sink) and the BG(serialize) OOM precondition on Ubuntu mod_php 8.5.4. |
| pastebin `kggc4q1T` — two-request BG(serialize) PoC | Crasher/precondition PoC | **Real and minimal.** Request 1: 20 × 256 KB filenames → ~5 MB session progress serialize → OOM bailout; request 2: small follow-up re-enters serializer on poisoned state. We confirmed the full mechanism under lldb (§6). Not an RCE by itself. |
| `Icex0/php2shell-poc`, `NeaByteLab/php2shell`, `Wenenu/php2shell`, `19h/CVE-2026-109618` | Empty repos | Name-squatting / content removed. |
| `0ldbaby/php2shell` | README-only | No code. |
| `mikensec/php2shell-lab`, `syhunt/php2shell-protection`, `break-the-build/php-uploadprogress-waf`, `yetDevs/php2shell-triage`, `FacundoGimenez/php2shell-mitigation`, `FulcanelliR/PHP2Shell-Emergency-Patch`, `ovtechnology/php2shell-check`, `cm-suzuki-ryo/aws-waf-php2shell-post-guard` | Defensive tooling | WAF rules, mitigations, triage/inventory scripts. |
| `r2qa/CVE-2026-17544` | Weaponized PoC — **different bug** | bcmath OOB write → sandbox escape (8.4.0–8.4.23 / 8.5.0–8.5.8). Post-exploitation primitive; unrelated to php2shell. Do not confuse. |
| Calif.io "MAD Bugs" research (calif.io/research/php-uaf) | Published research + open-source exploit | `unserialize()` UAF family; remote chain model (~2,000 requests, crash oracle, prefork workers, runtime ELF resolution). The strongest public reference for how this bug class reaches RCE; credited on the leaked PHP2Shell tool. |
| Mallory / RD Intelligence trackers | Threat intel | Mallory: "filtered out all candidate exploits as fakes/README-only"; ~884k internet-facing hosts banner-report PHP ≤8.1 (59% of version-reporting hosts). |

---

## 4. Debunk summary: the jackalsyn "upload_progress UAF" bundle

(Full detail: REPORT.md §2–5, §7.)

1. **The claimed bug cannot exist in stock PHP.** `php_session_rfc1867_update()` executes `Z_TRY_ADDREF(progress->data)` (8.4.4 session.c:3189) before `zend_hash_update`. The live progress array `P` is never freed mid-request; the free only reaches `P′`, a decoded copy the cached bucket pointers never reference. The protection exists in **every release since upload_progress shipped** (verified 5.6.40 → master).
2. **Dynamic A/B/A proof (ours, independent):** stock ASAN 8.4.4 + exact 258-byte trigger → clean 200, both stores execute, no ASAN report. Remove the single addref line → deterministic ASAN heap-use-after-free, frame-for-frame matching the audit. Restore → clean.
3. **The exploit chain is incoherent even granting the UAF:** the stale store is an 8-byte `Z_LVAL_P` write that cannot alter `type_info`; no engine path calls `zend_call_function` on session-tree contents.
4. **Fabrication indicators:** line numbers matching no released PHP; self-contradictory CVE↔bug mapping; `handler@88` wrong (+72) for the 8.2.34 target it hardcodes; headline Ubuntu delta `0x43EF0` disproven by its own `--syms` tool (true value `0xbe3f0`); all four scripts ship with a `SyntaxError` on line 1.
5. **Genuine parts:** the LiteSpeed `lsphp82` 8.2.34 delta table (bookworm `0xc930` / noble `0xcef0` / jammy `0xd060`) is byte-exact correct (recomputed from official `-dbg` packages), and the struct constants `FCI=64/param_count@48/IS_STRING_EX 0x106/IS_OBJECT_EX 0x308` are accurate for 8.4+.

---

## 5. The credible root-cause theory: `BG(serialize)` cross-request state

(Full detail: REPORT.md §6, §11.)

**Mechanism (all source-verified on PHP-8.4.4):**

1. `php_request_startup()` calls `php_hash_environment()` (main.c:1871) — multipart parsing runs here, and upload_progress **serializes the session** during it.
2. `zend_activate_modules()` (main.c:1872) — which zeroes `BG(serialize)` via basic RINIT (basic_functions.c:405-407) — runs **after**. A bailout inside `php_hash_environment` is caught by `zend_catch` (main.c:1874) and **skips module activation entirely**.
3. `BG(serialize)` (a process-global `{data, level}`) is zeroed **only** at RINIT and module init — **never at request shutdown**.
4. Attacker-sized progress data (20 × 256 KB filenames) + small `memory_limit` forces an OOM `zend_bailout` **inside `php_var_serialize`** → `PHP_VAR_SERIALIZE_DESTROY` never runs → `BG(serialize)={dangling data, level=1}` persists in the worker.
5. Next request on the same (prefork/FPM/`php -S`) process re-enters `php_var_serialize_init()`, takes the `level>0` **reuse path** on the dangling pointer → cross-request UAF/type confusion.

**Our dynamic confirmation (lldb, vanilla `php -S`, stock 8.4.4, localhost only):**

- Breakpoint `zend_mm_safe_error` captured request 1's OOM at exactly the theorized frame: `php_var_serialize_string` (var.c:795) ← `ps_srlzr_encode_php` (session.c:1070) ← `php_session_rfc1867_update` ← `rfc1867_post_handler` ← `php_hash_environment` ← `php_request_startup`. At bailout: `BG(serialize)={data=0x…36000, level=1}` — the poisoned state, verbatim.
- Scripted lldb probe on request 2's `php_var_serialize_init`: **reuse path taken on the identical stale pointer** (level 1→2). The UAF objectively occurred; it completed silently (HTTP 200, well-formed session) because ZendMM had deterministically recycled the freed chunk into a pristine empty HashTable — same-size allocations landing on the same chunk across two near-identical request startup sequences.
- 6-configuration matrix (ASAN+ZendMM / debug -O0; 8M/16M/32M; same/different SID): OOM precondition fires at 8M/16M, absent at 32M (precondition is load-bearing); no crash in any config → **unmet heap-layout preconditions, not negative evidence**.

**Corroboration from independent signals:**
- The leaked demo's runtime addresses imply delta `0xbe3f0` and module base offsets matching **Ubuntu mod_php 8.5.4-0ubuntu1.3 exactly** (recomputed from two official Ubuntu binaries) — mod_php prefork is precisely the sequential-same-process model this bug needs.
- The audit reproduced the OOM precondition on that exact Ubuntu build.
- Sansec credits Calif.IO; Calif.io's published research is the serializer-state UAF family.
- "21-year-old" framing fits request-startup ordering + bailout-prone globals (PHP-5-era design).

**Why `php -S` didn't crash but production might:** the lab replays two near-identical requests, so ZendMM hands request 2 the same chunk for the same type. A real worker serves varied traffic between requests 1 and 2; the freed chunk can be binned (freelist links overwrite `ht.gc`/`arData`), recycled into an incompatible type, or attacker-influenced — the standard exploit-primitive conditions.

---

## 6. Side finding: session-lock leak DoS (reproducible on stock 8.4.4)

Request 1's mid-startup bailout bypasses the session close path, leaving `LOCK_EX` held on the session file (`flock` ← `ps_files_open`, mod_files.c:210, confirmed by process sampling). A same-SID follow-up request self-deadlocks in `flock` until `max_execution_time` (~32 s) terminates the worker; the server is unavailable to that SID meanwhile. Reproduced on both ASAN and debug builds at memory_limit=8M. Availability-only, but a genuine stock-PHP robustness bug (startup bailout → leaked session lock), independent of the RCE question.

---

## 7. Defensive guidance

### Immediate stopgaps (pre-patch, safe per Sansec for Magento/Shopware/WooCommerce)
```ini
session.upload_progress.enabled = 0   ; kills the remote trigger vehicle (progress serialize pre-RINIT)
session.use_strict_mode = 1           ; blocks session-fixation assist (uninitialized SIDs rejected)
```
Reload php-fpm / web server after changing. Additional edge hardening: rate-limit or inspect large multipart POSTs (esp. many file parts / huge filenames) at WAF/reverse proxy.

### Patch (14:00 UTC)
- Upgrade to the security releases for supported branches (8.2–8.5); internet-facing first; restart workers; rebuild container images.
- **EOL (≤8.1) gets no official fix** — upgrade, isolate from the internet, or obtain vendor/distro backports. ~884k internet-facing hosts banner-report ≤8.1 (Mallory/Shodan, 2026-10-20).
- Fix is at the **interpreter level** — application updates (WordPress/Magento/etc.) do not address it.

### Detection / hunting (pre-IoC)
- Error-log signature: `Allowed memory size … exhausted … in Unknown on line 0` correlated with multipart POSTs (OOM inside serialize prints no file/line).
- PHP workers (`php-fpm`, `php-cgi`, `httpd`, `apache2`, `lsphp`) spawning `sh`/`bash`/`cmd.exe`/`powershell.exe`/`python`/`perl`/`curl`/`wget`/`nc`/`certutil.exe`; command lines containing `/dev/tcp/`, `fsockopen`, `mkfifo`; recon one-liners (`whoami`, `id`, `uname -a`) from web-server PIDs.
- Same-SID request hangs / worker timeouts on session `flock` (the §6 DoS signature).
- On unmonitored Linux servers: Florian Roth's `process-watcher` in observe mode.
- Post-incident triage: webshells/new files in webroot, new cron jobs/scheduled tasks/accounts; preserve web + PHP logs.

### If compromised
Isolate the host, preserve logs and session save_path contents, rebuild from known-good after patching.

---

## 8. What to watch in the 14:00 UTC patch diff

1. `main/main.c` — `php_request_startup` ordering: zeroing serializer globals **before** `php_hash_environment()`, or bailout-safe serializer cleanup.
2. `ext/standard/var.c` / `var_unserializer.re` — `php_var_serialize_init/destroy`, `BG(serialize)` level/lock handling, `php_add_var_hash` hardening.
3. `ext/session/session.c` — upload_progress encode path: dedicated var_hash, bailout protection, or deferring progress serialization until after RINIT. (A patch touching the *cached bucket pointers* would contradict this analysis — they are safe because of the addref.)
4. New `.phpt` tests referencing upload_progress + serialize/OOM/bailout.
5. Official CVE records (both IDs still `CVE_RECORD_DNE` at MITRE as of ~07:40 UTC) and the vendor's 618↔619 mechanism mapping.
6. Post-release: the beescoitu writeup (verify against SHA-256 `43717fa01ae5da8cdf5f8bba5811029badac86798f06682175785787951d0abd`), watchTowr FAQ update, Huntress blog update, Sansec research page.

---

## 9. Artifact index (this workspace)

| Path | Contents |
|---|---|
| `REPORT.md` | Deep technical analysis §1–11 (bundle audit, source verification, deltas, both dynamic test campaigns, repro commands) |
| `run/bgctx_run.py` | Cleaned two-request BG(serialize) PoC (localhost testing) |
| `run/bgctx.ini`, `run/lldb_probe.txt` | Test harness config |
| `run/logs4/` | Server/client/lldb/sample logs for the §11 matrix |
| `build/` | ASAN + debug PHP 8.4.4 builds; `asan-results.txt` (stock clean / ablated UAF) |
| `poc-bundle/`, `audit/` | Zer061 mirror + xuehuolll audit clones |
| `php-src-8.4.4/`, `upstream/` | Reference sources (8.2.34 → 8.5.12) |
| `debs/` | Ubuntu/LiteSpeed packages; recomputed symbol deltas |
| `pastebin-kggc4q1T.txt` | Original two-request PoC paste (raw, with line-number artifacts) |

## 10. Methodology & ethics note

All dynamic testing was performed against locally built PHP binaries on `127.0.0.1`. No exploit traffic was sent to any third-party or remote system; the bundle's hardcoded live target was never contacted. This report documents vulnerability mechanisms at the level already present in public sources (pastebin PoC, audit repo, Calif.io research) and is intended for defense, detection engineering, and patch verification. No weaponized exploit chain was developed, and none is included here.