#!/bin/bash
# lldb lifecycle trace of the poisoned sequence (debug build)
LAB=~/php2shell-lab
PHP=$LAB/debug/sapi/cli/php
PORT=8092

pkill -f "sapi/cli/php -S 127.0.0.1:$PORT" 2>/dev/null
sleep 0.3
rm -rf $LAB/lldb_run && mkdir -p $LAB/lldb_run/sess
cat > $LAB/lldb_run/lab.ini <<EOF
memory_limit = 16M
session.upload_progress = On
session.save_path = $LAB/lldb_run/sess
session.use_strict_mode = 0
display_errors = 1
max_execution_time = 20
error_log = $LAB/lldb_run/error.log
EOF
printf '<?php\nsession_start();\nif (isset($_SESSION["page"])) { include $_SESSION["page"]; }\nelse echo "HOME-OK " . PHP_VERSION . "\\n";\n' > $LAB/lldb_run/index.php

timeout 330 lldb -b \
  -o "target create $PHP" \
  -s $LAB/lldb_probe12.txt \
  -o "process launch -- -S 127.0.0.1:$PORT -t $LAB/lldb_run -c $LAB/lldb_run/lab.ini" \
  -o "script import time; time.sleep(260)" \
  -o "process kill" > $LAB/lldb_out.txt 2>&1 &
LLDB_PID=$!

sleep 8
python3 $LAB/client3.py $PORT
wait $LLDB_PID

echo "===== lldb output ====="
cat $LAB/lldb_out.txt
echo "===== session files ====="
for f in $LAB/lldb_run/sess/*; do [ -f "$f" ] && echo "--- $(basename $f) ($(stat -c%s $f) bytes) ---" && head -c 400 "$f"; echo; done
echo "===== error.log ====="
tail -5 $LAB/lldb_run/error.log 2>/dev/null
