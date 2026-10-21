#!/usr/bin/env python3
import subprocess, re
for track in ("clean", "groomed"):
    out = subprocess.run(["python3", "/home/wh1t3r0se/ph2s_leakmap/bin/evstream2.py", track],
                         capture_output=True, text=True).stdout
    blocks = out.split("---- CONN ")
    counts = []
    for blk in blocks[1:]:
        num = blk.split(" ", 1)[0].split(" ----")[0]
        n_init = len(re.findall(r"^INIT", blk, re.M))
        n_des = len(re.findall(r"^DESTROY", blk, re.M))
        n_bo = len(re.findall(r"^BAILOUT", blk, re.M))
        n_st = len(re.findall(r"^STALE", blk, re.M))
        counts.append((num, n_init, n_des, n_bo, n_st))
    pois = [c for c in counts if c[3] > 0]
    print("TRACK", track, "total_conns=", len(counts))
    print("  poison conns:", [(c[0], "init", c[1], "bail", c[3]) for c in pois])
    staled = [c for c in counts if c[4] > 0]
    print("  stale-holding conns:", [(c[0], c[4]) for c in staled])
    innit = [c[1] for c in counts]
    print("  per-conn INIT histogram:", {v: innit.count(v) for v in sorted(set(innit))})
