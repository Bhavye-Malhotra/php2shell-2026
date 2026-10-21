#!/usr/bin/env bash
# Stage-1 campaign runner: launches debug php -S under lldb with leak_probe.txt,
# drives leak_client.py, captures the full lldb log.
set -uo pipefail
BASE=/home/wh1t3r0se/ph2s_leakmap
PHP=/home/wh1t3r0se/php2shell-lab/debug/sapi/cli/php
TRACK="$1"      # s1clean | s1groomed
PORT="$2"
NPOISON="${3:-12}"
SEED="${4:-1337}"
MODE="${5:-clean}"

DOCROOT="$BASE/run/$TRACK/docroot"
INI="$BASE/run/lab.ini"
LOG="$BASE/raw/${TRACK}_lldb.log"
CSV="$BASE/raw/${TRACK}_client.csv"

# fresh session dir
rm -f "$DOCROOT/sess"/sess_* 2>/dev/null || true
# per-track save_path
cp "$INI" "$BASE/run/$TRACK/lab.ini"
echo "session.save_path=$DOCROOT/sess" >> "$BASE/run/$TRACK/lab.ini"
echo "error_log=$BASE/run/$TRACK/error.log" >> "$BASE/run/$TRACK/lab.ini"

export LLDB=/usr/sbin/lldb
"$LLDB" -b \
  -o "target create $PHP" \
  -s "$BASE/bin/leak_probe.txt" \
  -o "process launch -- -S 127.0.0.1:$PORT -t $DOCROOT -c $BASE/run/$TRACK/lab.ini" \
  -o "script import time; time.sleep(1200)" \
  -o "process kill" \
  -o "quit" > "$LOG" 2>&1 &
LLDB_PID=$!
# wait until the instrumented server is accepting connections
python3 - "$PORT" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(240):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit("server never came up on port %d" % port)
PYEOF
WAIT_RC=$?
if [ "$WAIT_RC" -ne 0 ]; then kill -9 "$LLDB_PID" 2>/dev/null; exit "$WAIT_RC"; fi
python3 "$BASE/bin/leak_client.py" "$PORT" "$MODE" "$NPOISON" "$SEED" > "$CSV" 2> "$CSV.err"
CLIENT_RC=$?
sleep 2
kill "$LLDB_PID" 2>/dev/null || true
sleep 1
kill -9 "$LLDB_PID" 2>/dev/null || true
pkill -9 -f "php_var_serialize" 2>/dev/null || true
wait "$LLDB_PID" 2>/dev/null
echo "client_rc=$CLIENT_RC log=$LOG csv=$CSV"
