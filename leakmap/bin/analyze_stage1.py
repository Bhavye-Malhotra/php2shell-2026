#!/usr/bin/env python3
"""Parse lldb campaign logs -> stage1/stage2 datasets.

Emits (relative to OUT dir):
  events_<track>.csv        one row per breakpoint event
  cycles_<track>.csv        per poison cycle: poison ptr, probe ptr, clash bit
  summary_<track>.json      aggregate frequencies
  stale_<track>.csv         (stage2) 8-qword dumps at stale-pointer reuse moments
"""
import csv, json, os, re, sys

BASE = "/home/wh1t3r0se/ph2s_leakmap"
MARKERS = ("INIT", "DESTROY", "BAILOUT", "STALEDUMP")

def parse_track(track):
    log = open("%s/raw/camp_%s_lldb.log" % (BASE, track), encoding="utf-8", errors="replace").read().splitlines()
    events = []
    cur = None
    memq = []
    mem_pending = 0
    for ln in log:
        m = re.match(r"^==(INIT|DESTROY|BAILOUT|STALEDUMP)==", ln)
        if m:
            if cur:
                cur["qwords"] = " ".join(memq)
                events.append(cur)
            cur = {"event": m.group(1), "level": None, "ptr": None}
            memq = []
            mem_pending = 0
            continue
        sm = re.match(r"^STALE (0x[0-9a-f]+) ((?:[0-9a-f]+ ){7}[0-9a-f]+) level=(\d+)", ln.strip())
        if sm:
            if cur:
                cur["qwords"] = " ".join(memq)
                events.append(cur)
                cur = None
            events.append({"event": "STALEDUMP", "level": int(sm.group(3)),
                           "ptr": sm.group(1), "qwords": sm.group(2).replace(" ", " 0x") if False else " 0x".join([""] + sm.group(2).split())[3:]})
            # normalize qwords to 0x-prefixed tokens
            events[-1]["qwords"] = " ".join("0x" + q for q in sm.group(2).split())
            continue
        if cur is None:
            continue
        if re.search(r"^\(unsigned int\) \d+", ln.strip()):
            cur["level"] = int(ln.strip().split()[-1])
        elif "php_serialize_data *)" in ln:
            part = ln.split(")")[1].strip()
            cur["ptr"] = None if part == "NULL" else part
        elif mem_pending > 0:
            mm = re.findall(r"0x[0-9a-f]+:\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", ln)
            for pair in mm:
                memq.extend(pair)
                mem_pending -= 2
    if cur:
        cur["qwords"] = " ".join(memq)
        events.append(cur)
    return events

def analyze(track, events):
    out_rows = []
    poison_ptrs = []  # (cycle_idx, ptr) from BAILOUT with level>=1
    # find probe INIT right after each BAILOUT(level>=1)
    cyc = []
    for i, ev in enumerate(events):
        if ev["event"] == "BAILOUT" and ev["level"] and ev["level"] >= 1:
            pptr = ev["ptr"]
            # next INIT event = consumer moment
            nxt = None
            for j in range(i + 1, len(events)):
                if events[j]["event"] == "INIT":
                    nxt = events[j]
                    break
                if events[j]["event"] == "BAILOUT":
                    break
            clash = None
            if nxt is not None and pptr is not None and nxt["ptr"] is not None:
                clash = (nxt["ptr"] == pptr)
            cyc.append({"cycle": len(cyc), "poison_ptr": pptr,
                        "probe_ptr": nxt["ptr"] if nxt else None,
                        "probe_level": nxt["level"] if nxt else None,
                        "clash": clash})
    n_clash = sum(1 for c in cyc if c["clash"] is True)
    n_no = sum(1 for c in cyc if c["clash"] is False)
    inits = [e for e in events if e["event"] == "INIT"]
    init_lvl = {}
    for e in inits:
        init_lvl[e["level"]] = init_lvl.get(e["level"], 0) + 1
    dumps = [e for e in events if e["event"] == "STALEDUMP"]
    # per-qword pointer-likeness across dumps
    ptrlike = 0
    total_q = 0
    for d in dumps:
        for q in d["qwords"].split():
            total_q += 1
            try:
                v = int(q, 16)
                if 0x100000000000 <= v <= 0x800000000000:
                    ptrlike += 1
            except ValueError:
                pass
    # consecutive dump diff rate
    diff_rates = []
    for a, b in zip(dumps, dumps[1:]):
        qa, qb = a["qwords"].split(), b["qwords"].split()
        if len(qa) == 8 and len(qb) == 8:
            diff = sum(1 for x, y in zip(qa, qb) if x != y)
            diff_rates.append(diff / 8.0)
    summary = {
        "track": track,
        "n_events": len(events),
        "n_init": len(inits),
        "init_level_dist": init_lvl,
        "n_bailout": len([e for e in events if e["event"] == "BAILOUT"]),
        "n_poison_confirmed": len(cyc),
        "n_staledump": len(dumps),
        "cycles": cyc,
        "clash_true": n_clash,
        "clash_false": n_no,
        "clash_rate": (n_clash / (n_clash + n_no)) if (n_clash + n_no) else None,
        "stale_qword_ptr_fraction": (ptrlike / total_q) if total_q else None,
        "stale_consec_diff_mean": (sum(diff_rates) / len(diff_rates)) if diff_rates else None,
        "stale_consec_diff_n": len(diff_rates),
    }
    return summary, cyc, dumps

def main():
    os.makedirs("%s/stage1_pointer_reuse" % BASE, exist_ok=True)
    os.makedirs("%s/stage2_stale_bytes" % BASE, exist_ok=True)
    results = {}
    for track in sys.argv[1:]:
        events = parse_track(track)
        with open("%s/stage1_pointer_reuse/events_%s.csv" % (BASE, track), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["idx", "event", "level", "ptr", "n_qwords"])
            for i, e in enumerate(events):
                w.writerow([i, e["event"], e["level"], e["ptr"], len(e["qwords"].split())])
        summary, cyc, dumps = analyze(track, events)
        with open("%s/stage1_pointer_reuse/cycles_%s.csv" % (BASE, track), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["cycle", "poison_ptr", "probe_ptr", "probe_level", "clash"])
            for c in cyc:
                w.writerow([c["cycle"], c["poison_ptr"], c["probe_ptr"], c["probe_level"], c["clash"]])
        with open("%s/stage2_stale_bytes/stale_%s.csv" % (BASE, track), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["dump_idx", "level_at_init", "ptr", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"])
            for i, d in enumerate(dumps):
                q = d["qwords"].split()
                w.writerow([i, d["level"], d["ptr"]] + (q + [""] * 8)[:8])
        with open("%s/stage1_pointer_reuse/summary_%s.json" % (BASE, track), "w") as f:
            json.dump(summary, f, indent=2)
        results[track] = summary
    for t, s in results.items():
        print("TRACK %s: events=%d poison_confirmed=%d clash=%s (%s/%s) init_lvl_dist=%s staledumps=%d ptrlike_frac=%s consec_diff=%s" % (
            t, s["n_events"], s["n_poison_confirmed"], s["clash_rate"],
            s["clash_true"], s["clash_true"] + s["clash_false"], s["init_level_dist"],
            s["n_staledump"], s["stale_qword_ptr_fraction"], s["stale_consec_diff_mean"]))

if __name__ == "__main__":
    main()
