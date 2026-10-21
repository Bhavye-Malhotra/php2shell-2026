#!/usr/bin/env bash
# Stage-1 campaign runner (min_freq=0 trigger config, debug build under lldb)
# usage: stage2_run.sh TRACK(clean|groomed) PORT NCYC SEED
set -uo pipefail
BASE=/home/wh1t3r0se/ph2s_leakmap
PHP=/home/wh1t3r0se/php2shell-lab/debug/sapi/cli/php
TRACK="$1"
PORT="$2"
NCYC="${3:-10}"
SEED="${4:-7331}"
D="$BASE/run/camp_$TRACK"
mkdir -p "$D/docroot/sess"
printf '<?php session_start(); echo "OK\\n";' > "$D/docroot/index.php"
cat > "$D/lab.ini" <<EOF
session.save_path=$D/docroot/sess
session.upload_progress=On
session.upload_progress.min_freq=0
session.upload_progress.freq=1
session.use_strict_mode=0
memory_limit=16M
display_errors=0
error_log=$D/error.log
log_errors=1
max_execution_time=60
EOF
rm -f "$D"/error.log "$D/docroot/sess"/sess_* 2>/dev/null
pkill -f "camp_${TRACK}/docroot" 2>/dev/null || true
pkill -f "php -S 127.0.0.1:$PORT" 2>/dev/null || true
sleep 0.5
LOG="$BASE/raw/camp_${TRACK}_lldb.log"
CSV="$BASE/raw/camp_${TRACK}_client.csv"
lldb -b \
  -o "target create $PHP" \
  -s "$BASE/bin/leak_probe.txt" \
  -o "process launch -- -S 127.0.0.1:$PORT -t $D/docroot -c $D/lab.ini" \
  -o "script import time; time.sleep(900)" \
  -o "process kill" \
  -o "quit" > "$LOG" 2>&1 &
LLDB_PID=$!
python3 - "$PORT" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(300):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2); s.close(); sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit("server never came up")
PYEOF
RC=$?
if [ $RC -ne 0 ]; then kill -9 $LLDB_PID 2>/dev/null; exit $RC; fi
python3 "$BASE/bin/leak_client2.py" "$PORT" "$TRACK" "$NCYC" "$SEED" > "$CSV" 2> "$CSV.err"
CRC=$?
sleep 2
kill $LLDB_PID 2>/dev/null
sleep 1
kill -9 $LLDB_PID 2>/dev/null
pkill -f "camp_${TRACK}/docroot" 2>/dev/null || true
wait $LLDB_PID 2>/dev/null
echo "client_rc=$CRC log=$LOG csv=$CSV"
