import http.client, sys, time

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

sid = 'tinytest05'
body = mpart([('PHPSESSID', sid.encode()),
              ('PHP_SESSION_UPLOAD_PROGRESS', b'tinit')],
             [('f0', 'hello.txt', b'HELLO')])
print('body bytes:', len(body))
print(body.decode('latin-1')[:300])
c = http.client.HTTPConnection('127.0.0.1', 8099, timeout=15)
c.request('POST', '/', body, {'Content-Type': 'multipart/form-data; boundary=BND',
                              'Content-Length': str(len(body))})
r = c.getresponse()
print('HTTP', r.status, r.read())
c.close()
time.sleep(0.5)
import os
p = '/home/wh1t3r0se/php2shell-lab/rce_server/sess/sess_' + sid
print('file exists:', os.path.exists(p))
if os.path.exists(p):
    d = open(p, 'rb').read()
    print('file bytes:', len(d))
    print(d[:400])
