#!/usr/bin/env bash
# Stage-3 runner: launches stock php:8.4.26-cli in docker (php -S worker),
# runs stage3_probe.py twice: config A (display_errors=0) and B (display_errors=1).
set -euo pipefail
BASE=/home/wh1t3r0se/ph2s_leakmap
OUT=$BASE/stage3_http_channels
SRV=$OUT/srv
mkdir -p "$SRV/sess"
printf '<?php session_start(); echo "OK\n";' > "$SRV/index.php"
docker rm -f lm_s3a lm_s3b >/dev/null 2>&1 || true

run_config () {
  local NAME=$1 ERR=$2 LOGF=$3 PORT=$4
  docker run -d --name "$NAME" -p "$PORT":8080 \
    -v "$SRV":/srv \
    php:8.4.26-cli php \
      -d display_errors=$ERR \
      -d log_errors=1 \
      -d error_log=/srv/"$LOGF" \
      -d memory_limit=16M \
      -d session.upload_progress=On \
      -d session.upload_progress.min_freq=0 \
      -d session.upload_progress.freq=1 \
      -d session.save_path=/srv/sess \
      -d max_execution_time=60 \
      -S 0.0.0.0:8080 -t /srv >/dev/null
  sleep 2
  python3 "$BASE/bin/stage3_probe.py" "$PORT" "$OUT/summary_${NAME}.json" \
    "CNRY20261021deadbeefcafe" > "$OUT/rows_${NAME}.csv" 2>"$OUT/err_${NAME}.log"
  docker logs "$NAME" 2>&1 | tail -5 > "$OUT/dockerlog_${NAME}.txt" || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}

docker run --rm php:8.4.26-cli php -v > "$OUT/docker_php_version.txt" 2>&1
run_config lm_s3a 0 error_a.log 8890
run_config lm_s3b 1 error_b.log 8891
echo "== docker_php_version =="; cat "$OUT/docker_php_version.txt"
echo "== summaries =="
python3 - "$OUT" <<'PYEOF'
import json, sys
d = sys.argv[1]
for n in ("lm_s3a", "lm_s3b"):
    s = json.load(open("%s/summary_%s.json" % (d, n)))
    print(n, "canary_hits=", s["canary_found_in_responses"])
    for ps in s["phase_stats"]:
        print("  ", ps)
    for bv in s["body_variants"][:4]:
        print("  body:", bv["status"], bv["len"], repr(bv["hexdump_head"][:120]))
PYEOF
