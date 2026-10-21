#!/usr/bin/env bash
# Segmented stage-3 runner: two container configs, hang-resilient phases.
set -uo pipefail
BASE=/home/wh1t3r0se/ph2s_leakmap
OUT=$BASE/stage3_http_channels
SRV=$OUT/srv
mkdir -p "$SRV/sess"
printf '<?php session_start(); echo "OK\n";' > "$SRV/index.php"
docker rm -f lm_s3a lm_s3b >/dev/null 2>&1 || true

mkcontainer () { # name display_errors port
  docker run -d --name "$1" -p "$3":8080 \
    -v "$SRV":/srv \
    php:8.4.26-cli php \
      -d display_errors=$2 \
      -d html_errors=0 \
      -d log_errors=1 \
      -d error_log=/srv/error_$1.log \
      -d memory_limit=16M \
      -d session.upload_progress=On \
      -d session.upload_progress.min_freq=0 \
      -d session.upload_progress.freq=1 \
      -d session.save_path=/srv/sess \
      -d max_execution_time=60 \
      -S 0.0.0.0:8080 -t /srv >/dev/null
  sleep 1.5
}

echo "== config A: display_errors=0 (production-realistic) =="
mkcontainer lm_s3a 0 8890
python3 "$BASE/bin/stage3_probe2.py" baseline 8890 60 | tee "$OUT/segA_baseline.csv"
python3 "$BASE/bin/stage3_probe2.py" poison 8890 victimsidA CNRYsegAdeadbeef 2> "$OUT/segA_poison_body.txt" | tee "$OUT/segA_poison.csv"
sleep 1
python3 "$BASE/bin/stage3_probe2.py" followup 8890 8 victimsidA | tee "$OUT/segA_followup.csv"
python3 "$BASE/bin/stage3_probe2.py" multi 8890 otherSid 2> "$OUT/segA_multi_body.txt" | tee "$OUT/segA_multi.csv"
docker exec lm_s3a cat /proc/1/wchan > "$OUT/segA_worker_wchan.txt" 2>/dev/null || echo "(gone)" > "$OUT/segA_worker_wchan.txt"
docker logs lm_s3a --tail 3 > "$OUT/segA_dockerlog.txt" 2>&1 || true
rm -f "$SRV"/sess/sess_* 
docker rm -f lm_s3a >/dev/null 2>&1 || true

echo "== config B: display_errors=1 (error output in body) =="
mkcontainer lm_s3b 1 8891
python3 "$BASE/bin/stage3_probe2.py" baseline 8891 20 | tee "$OUT/segB_baseline.csv"
python3 "$BASE/bin/stage3_probe2.py" poison 8891 victimsidB CNRYsegBdeadbeef 2> "$OUT/segB_poison_body.txt" | tee "$OUT/segB_poison.csv"
sleep 1
python3 "$BASE/bin/stage3_probe2.py" followup 8891 8 victimsidB | tee "$OUT/segB_followup.csv"
python3 "$BASE/bin/stage3_probe2.py" multi 8891 otherSidB 2> "$OUT/segB_multi_body.txt" | tee "$OUT/segB_multi.csv"
docker exec lm_s3b cat /proc/1/wchan > "$OUT/segB_worker_wchan.txt" 2>/dev/null || echo "(gone)" > "$OUT/segB_worker_wchan.txt"
docker logs lm_s3b --tail 3 > "$OUT/segB_dockerlog.txt" 2>&1 || true
docker rm -f lm_s3b >/dev/null 2>&1 || true

cp "$SRV"/error_lm_s3a.log "$OUT/error_lm_s3a.log" 2>/dev/null || true
cp "$SRV"/error_lm_s3b.log "$OUT/error_lm_s3b.log" 2>/dev/null || true
echo "== stage3 done =="
ls -la "$OUT"
