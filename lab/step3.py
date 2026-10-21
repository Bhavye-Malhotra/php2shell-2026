import subprocess, os, sys, glob

sess = sys.argv[1]
pid = int(sys.argv[2])
# find fds of server open on sess
fds = []
for fd in os.listdir('/proc/%d/fd' % pid):
    try:
        if os.readlink('/proc/%d/fd/%s' % (pid, fd)) == sess:
            fds.append(fd)
    except OSError:
        pass
print('server still holds fds %s on %s' % (fds, sess))

# locks table lookup
locks = [l for l in open('/proc/locks').read().splitlines() if str(pid) + ':' in l]
for l in locks:
    print('lock: %s' % l)

# Step B: independent process flock attempt
php = '/home/wh1t3r0se/php2shell-lab/release/sapi/cli/php'
code = '$f=fopen("%s","r"); if ($f===false) { fwrite(STDERR,"openfail\n"); exit(1);} echo "B: open ok, flocking\n"; flock($f, LOCK_EX); echo "B: GOT LOCK\n";' % sess
b = subprocess.Popen([php, '-r', code], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    out, _ = b.communicate(timeout=8)
    print('B finished rc=%d: %s' % (b.returncode, out.strip()))
except subprocess.TimeoutExpired:
    b.kill(); b.wait()
    print('B BLOCKED > 8s waiting for lock -> cross-process DoS CONFIRMED')
