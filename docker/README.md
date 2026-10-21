# Docker matrix — vanilla-image results (2026-10-21)

Run: `bash docker/run_matrix.sh` — spins `php:8.4.26-cli` (official image, unpatched
< `506e87fa7`); `php:8.4.27-cli` is not yet published on Docker Hub.

| Run | Image | session.serialize_handler / cleanup | Detector | Chain probe (pure-HTTP KEY-suffix forge + payload filename + `?c=id`) | Session-file evidence |
|---|---|---|---|---|---|
| 1 | php:8.4.26-cli | vanilla `php` + cleanup=1 | VULNERABLE | CHAIN_BROKEN (`NO_PAGE`, 0-byte sess files) | empty sess files; no `sess_vc01` with forged bytes — confirm memchr-pipe at session.c:1061 in stock code |
| 2 | php:8.4.26-cli | `php_serialize` + cleanup=0 | VULNERABLE | CHAIN_BROKEN (`NO_PAGE`) | progress KEY with forged suffix lands in file as one length-bound string (php_serialize container) — does NOT split into separate `page` var |
| 3 | php:8.4.27-cli | n/a (image unpublished) | n/a | n/a | n/a |

Raw logs: `docker/RESULTS/` (chain_*.log, detect_*.json/.txt, sess_*.txt, matrix.log).

## What this proves

1. **On stock vanilla unpatched PHP the pure-HTTP KEY-suffix forge is dead on
   BOTH session codecs** the binary ships by default:
   - `php` codec (default): `memchr(key, '|')` reject → encode NULL → zero-byte write.
   - `php_serialize` codec: the forged suffix becomes one long KEY inside a single
     `a:N:{...}` serialized array — it does not expand into a separate `page`
     variable at decode.
2. The only pure-HTTP working primitive for `$_SESSION['page']` injection on an
   unpatched binary therefore **requires a consumer-side forge** (the local
   byte-craft performed in `../poc/poc_session_include.py`'s `forge-craft`
   stage, which is documented inside PROOFS_session_include.md), or an entirely
   different primordium that isn't `PHP_SESSION_UPLOAD_PROGRESS` key-text.
3. The on-host detector is exact inside unmodified vanilla containers:
   `VULNERABLE` on `8.4.26-cli`. (Image `php:8.4.27-cli` is expected to flip to
   `PATCHED` once published and re-run.)
