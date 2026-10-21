# CVE-2026-109618 / CVE-2026-109619 minimal backport — verification matrix

Backport of upstream security fix commit `506e87fa7` ("Avoid state corruption via bailout") to EOL PHP lines.
Backport ID: **bd1cc**. Generated 2026-10-21.

Each patch implements:
- **(a)** new `php_basic_early_rinit()` (ext/standard/basic_functions.[ch]) zeroing `BG(serialize_lock)`, `BG(serialize)`, `BG(unserialize)`, called in `php_request_startup()` immediately after `zend_activate()` — i.e. **before** `sapi_activate()` / `php_hash_environment()` (main/main.c)
- **(b)** `PG(modules_activated) = 0;` appended at the end of `php_request_shutdown()` (main/main.c, vendor comment "May be accessed before php_request_startup()")
- **(c)** comment-only `MUST-NOT-EXECUTE-USERCODE` note in the rfc1867 upload-progress path of ext/session/session.c (`php_session_rfc1867_cleanup()`)

Source trees: GitHub tag tarballs under `src/php-<ver>/`. Verification commands per branch:
`patch -p1 --dry-run` and `git apply --check`, run in the pristine tree. Full transcripts: `TRANSCRIPTS.txt`.

| branch | patch file (patches/) | patch -p1 --dry-run | git apply --check | compiled |
|---|---|---|---|---|
| 8.1.33  | CVE-2026-109618-109619-bd1cc_backport-php-8.1.33.patch  | OK | OK | **OK** (see below) |
| 8.0.30  | CVE-2026-109618-109619-bd1cc_backport-php-8.0.30.patch  | OK | OK | n/a |
| 7.4.33  | CVE-2026-109618-109619-bd1cc_backport-php-7.4.33.patch  | OK | OK | n/a |
| 7.3.33  | CVE-2026-109618-109619-bd1cc_backport-php-7.3.33.patch  | OK | OK | n/a |
| 7.2.34  | CVE-2026-109618-109619-bd1cc_backport-php-7.2.34.patch  | OK | OK | n/a |
| 7.1.33  | CVE-2026-109618-109619-bd1cc_backport-php-7.1.33.patch  | OK | OK | n/a |
| 7.0.33  | CVE-2026-109618-109619-bd1cc_backport-php-7.0.33.patch  | OK | OK | n/a |
| 5.6.40  | CVE-2026-109618-109619-bd1cc_backport-php-5.6.40.patch  | OK | OK | n/a |
| 5.5.38  | CVE-2026-109618-109619-bd1cc_backport-php-5.5.38.patch  | OK | OK | n/a |
| 5.4.45  | CVE-2026-109618-109619-bd1cc_backport-php-5.4.45.patch  | OK | OK | n/a |

PHP 5.x patches carry `TSRMLS_FETCH()` inside `php_basic_early_rinit()` (ZTS-safety) and use the
`zend_activate(TSRMLS_C)` / `sapi_activate(TSRMLS_C)` call-site context; 7.x/8.x are plain.

## Compile test (php-8.1.33 + patch)

- Tree: `build-81/php-8.1.33` (php.net release tarball; the 4 patched files verified **byte-identical** to the GitHub tag tree before patching), build dir `build-81/bld`
- `./configure --disable-all --enable-session` + `make -j8` → **Build complete** (log: `build-81/build.log`, gcc 16.2.1)
- `build-81/bld/sapi/cli/php -v` → `PHP 8.1.33 (cli) (built: Oct 21 2026 20:50:26) (NTS)`
- `php -m` shows `session` loaded; `serialize()`/`unserialize()` smoke test OK
- Source check: `main/main.c:1742` calls `php_basic_early_rinit()` (before `php_hash_environment()` at 1779); `main/main.c:1911` has the new `PG(modules_activated) = 0;` at shutdown end; `basic_functions.c:573-575` contains the three zeroing statements

## Path coverage / scope note: why CVE-2026-109618's UnwindExit machinery is NOT in these patches

The upstream fix in 506e87fa7 has two layers:

1. **Engine-level OOM bailout rewrite (CVE-2026-109618 core fix)** — a deferred-OOM / UnwindExit
   subsystem touching `Zend/zend_alloc.c` (~+527/-124), `zend_hash`, `zend_smart_str`, fiber/VM
   unwind semantics and `EG(delayed_oom)` state tracking. This is a structural redesign of the
   8.4 memory manager; equivalent machinery simply does not exist on 8.1/7.x/5.x, and grafting
   it would be a full engine rewrite, not a surgical backport. **Deliberately out of scope.**
2. **Stale global state persistence (CVE-2026-109619)** — serializer globals, `PG(modules_activated)`,
   rfc1867 session state surviving a bailout into the next request. This is what these patches
   backport: the same `php_basic_early_rinit()` zeroing + shutdown reset the vendor added.

Effect: these patches fix CVE-2026-109619 outright and **remove the stale-state window that
CVE-2026-109618 relies on for cross-request corruption reuse**. The residual CVE-2026-109618
exposure on EOL lines (arbitrary OOM-longjmp corruption within a single request before shutdown)
cannot be closed minimally; full mitigation requires the 8.2+ vendor release line.
