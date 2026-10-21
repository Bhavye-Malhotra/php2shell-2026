#!/usr/bin/env python3
import re, sys
which = sys.argv[1] if len(sys.argv) > 1 else "clean"
log = open("/home/wh1t3r0se/ph2s_leakmap/raw/camp_%s_lldb.log" % which, errors="replace").read().splitlines()
out = []
i = 0
conn = 0
while i < len(log):
    l = log[i]
    if "Accepted" in l:
        conn += 1
        out.append("---- CONN %d ----" % conn)
    m = re.match(r"^==(INIT|DESTROY|BAILOUT)==", l)
    sm = re.match(r"^STALE (0x[0-9a-f]+) (.*) level=(\d+)", l.strip())
    if m:
        lvl = ptr = None
        for j in range(i + 1, min(i + 10, len(log))):
            if re.match(r"^\(unsigned int\) \d+", log[j].strip()):
                lvl = log[j].strip().split()[-1]
            if "php_serialize_data *)" in log[j]:
                p = log[j].split(")")[1].strip()
                ptr = "NULL" if p == "NULL" else p[-8:]
            if "continue" in log[j]:
                break
        out.append("%s lvl=%s d=%s" % (m.group(1), lvl, ptr))
    elif sm:
        out.append("STALE lvl=%s d=%s qw0=%s" % (sm.group(3), sm.group(1)[-8:], sm.group(2).split()[0]))
    i += 1
print("\n".join(out))
