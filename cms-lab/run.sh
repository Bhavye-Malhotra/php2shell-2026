#!/bin/bash
# cms-lab: start unpatched vanilla PHP container and serve the WP-shaped app.
set -e
cd "$(dirname "$0")"
IMG=php:8.4.26-cli
SESS=/tmp/ph2s_cms_lab_sess
mkdir -p "$SESS"
chmod 777 "$SESS"
PORT="${1:-8443}"
docker rm -f ph2s_cms 2>/dev/null >/dev/null || true
docker run -d --name ph2s_cms \
  -p 127.0.0.1:"$PORT":8080 \
  -v "$PWD/app":/app:ro \
  -v "$SESS":/tmp/sessions \
  -e PHP_CLI_SERVER_WORKERS=4 \
  "$IMG" php -n \
    -d session.save_path=/tmp/sessions \
    -d session.gc_probability=0 \
    -d session.upload_progress.enabled=1 \
    -d session.upload_progress.min_freq=0 \
    -d session.upload_progress.freq=1 \
    -d session.upload_progress.cleanup=0 \
    -d session.use_strict_mode=0 \
    -d session.serialize_handler=php \
    -d display_errors=1 \
    -S 0.0.0.0:8080 -t /app >/dev/null
for i in $(seq 1 60); do curl -s -m1 -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.3; done
echo "lab ready: http://127.0.0.1:$PORT (app routes: /, /wp-upload.php, /wp-content.php)"
