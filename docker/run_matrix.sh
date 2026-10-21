#!/usr/bin/env bash
# docker/run_matrix.sh - vanilla-image exploit/detector matrix for php2shell
# CVE-2026-109618 / CVE-2026-109619
#
# Runs each of the docker images in IMAGES array twice: once on the VANILLA
# codec (session.serialize_handler=php + default cleanup) and once on the
# proven binary codec recipe (php_serialize + upload_progress.cleanup=0).
# For each run it fires the session-include chain PoC (if an -able app side
# is mounted), then runs the on-host detector INSIDE the container.
# All output lands in ./RESULTS/.
set -u
unset IMAG
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$ROOT")"
OUT="$ROOT/RESULTS"
mkdir -p "$OUT"
: "${PORT_BASE:=8110}"
: "${PHP_REPO_ROOT:=$REPO}"

# images we probe; override with IMAGE_TAGS="php:8.4.26-cli php:8.4.27-cli" ./run_matrix.sh
: "${IMAGE_TAGS:=php:8.4.26-cli php:8.4.27-cli}"

PYEXEC=""
for cand in python py; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import http.client' >/dev/null 2>&1; then PYEXEC="$cand"; break; fi
done
[ -z "$PYEXEC" ] && PYEXEC="wsl -d Arch python3"
[ "$PYEXEC" = "py" ] && PYEXEC="py -3"

log(){ echo "[matrix] $*" | tee -a "$OUT/matrix.log"; }

docker_stop(){ docker rm -f "$1" >/dev/null 2>&1 || true; }

chain_test(){ # $1 container-name, $2 tcpport, $3 tag-consolidate-name
  local name="$1" port="$2" tag="$3"
  log "chain test on $name (port $port) [$tag]"
  (cd "$PHP_REPO_ROOT" && $PYEXEC docker/chain_probe.py "http://127.0.0.1:$port" "/tmp/sess_${name}/sess_vc01") \
     > "$OUT/chain_${tag}.log" 2>&1 || true
  if grep -q "CHAIN_WORKS" "$OUT/chain_${tag}.log"; then
    log "  CHAIN_WORKS=$tag"
  else
    log "  CHAIN_BROKEN=$tag"
  fi
}

detect_test(){
  local name="$1" tag="$2"
  docker exec -i "$name" sh -c 'cat > /tmp/detect.php' < "$PHP_REPO_ROOT/detector/php2shell_detect.php"
  docker exec -t "$name" php /tmp/detect.php --no-exit --json > "$OUT/detect_${tag}.json" 2>/dev/null || true
  docker exec -t "$name" php /tmp/detect.php --no-exit > "$OUT/detect_${tag}.txt" 2>/dev/null || true
  local verdict
  verdict=$(grep -o '"verdict"[[:space:]]*:[[:space:]]*"[^"]*"' "$OUT/detect_${tag}.json" | tail -1 | sed 's/.*"\([^"]*\)"$/\1/')
  log "  detector saved: detect_${tag}.json (verdict=${verdict:-?})"
}

run_case(){ # $1 image, $2 label, $3 codec-args
  local image="$1" label="$2"; shift 2
  local cname="ph2s_matrix_${label}"
  local port=$(( RANDOM%2000 + 20000 ))
  docker_stop "$cname"
  log "launching $image-> $cname on port $port with extra args: $*"
  # named-volume so sess_{sid} stays inspectable between steps but host sees nothing
  docker run -d --name "$cname" \
    -p 127.0.0.1:${port}:8080 \
    -v "$ROOT/app":/app:ro \
    -v ph2s_matrix_sess_${label}:/tmp/sess_${cname} \
    -e PHP_CLI_SERVER_WORKERS=4 \
    "$image" php -n \
      -d extension_dir=./ext \
      -d session.save_path=/tmp/sess_${cname} \
      -d session.gc_probability=0 \
      -d session.upload_progress.enabled=1 \
      -d session.upload_progress.min_freq=0 \
      -d session.upload_progress.freq=1 \
      -d session.use_strict_mode=0 \
      "$@" \
      -S 0.0.0.0:8080 -t /app \
      >/dev/null || { log "DOCKER RUN FAILED for $image"; return 1; }
  # wait for port
  for i in $(seq 1 30); do
    curl -s -m1 -o /dev/null "http://127.0.0.1:$port/" && break
    sleep 0.4
  done
  detect_test "$cname" "$label"
  chain_test "$cname" "$port" "$label"
  echo "===== sess_${cname} on after-case =====" | tee -a "$OUT/sess_${label}.txt"
  docker exec -t "$cname" sh -c "ls -la /tmp/sess_${cname}/ 2>/dev/null; for f in /tmp/sess_${cname}/sess_\*; do echo \"--- \$f\"; head -c 600 \$f | cat -v; done" >> "$OUT/sess_${label}.txt" 2>&1
  docker_stop "$cname"
  docker volume rm "ph2s_matrix_sess_${label}" >/dev/null 2>&1 || true
}

: > "$OUT/matrix.log"
log "matrix start $(date -u)"

VANILLA_ARGS="-d session.serialize_handler=php -d session.upload_progress.cleanup=1"
RECIPE_ARGS="-d session.serialize_handler=php_serialize -d session.upload_progress.cleanup=0"

for img in $IMAGE_TAGS; do
  b=$(echo "$img" | tr ':/.' '___')
  log "=== $img | VANILLA codec (${VANILLA_ARGS}) ==="
  run_case "$img" "vanilla_${b}" -d session.serialize_handler=php -d session.upload_progress.cleanup=1
  log "=== $img | RECIPE codec (${RECIPE_ARGS}) ==="
  run_case "$img" "recipe_${b}" -d session.serialize_handler=php_serialize -d session.upload_progress.cleanup=0
done

log "matrix done. results in $OUT"
