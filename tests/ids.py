# Ids: the guest runs as root and can become another user.
import ctypes
import errno
import fcntl
import os
import shutil
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


def error_of(f):
    try:
        f()
    except OSError as e:
        return e.errno
    return 0


d = tempfile.mkdtemp(prefix="burrow-ids.")
os.chmod(d, 0o777)
ok(os.getuid() == 0 and os.geteuid() == 0 and os.getgid() == 0, "root")
with open(d + "/root-file", "w"):
    pass
ok(os.stat(d + "/root-file").st_uid == 0, "a new file is root's")
ok("Uid:\t0\t0\t0\t0\n" in open("/proc/%d/status" % os.getpid()).read(), "/proc/<pid>/status has root's uid")
fd = os.open("/proc/%d/status" % os.getpid(), os.O_RDONLY)
ok(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY, "/proc/<pid>/status opens read-only (Electron)")
os.close(fd)
ok(open("/proc/sys/kernel/overflowuid").read() == open("/proc/sys/kernel/overflowgid").read() == "65534\n",
   "overflowuid and overflowgid (bwrap)")
ok(error_of(lambda: os.chown(d + "/root-file", 1000, 1000)) == 0, "chown")
ok(ctypes.CDLL(None, use_errno=True).prctl(8, 1, 0, 0, 0) == 0, "prctl(PR_SET_KEEPCAPS)")
libc = ctypes.CDLL(None, use_errno=True)
ok(libc.syscall(220, 0x20000000 | 17, 0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EINVAL,
   "clone(CLONE_NEWPID): EINVAL (Chromium's sandbox helper)")

with open(d + "/setuid-file", "w"):
    pass
os.chmod(d + "/setuid-file", 0o4755)

r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    out = []

    def check(cond, what):
        out.append(("ok   " if cond else "FAIL ") + what)

    os.setgroups([1000, 24])
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)
    check(os.getresuid() == (1000, 1000, 1000), "setresuid")
    check(os.getresgid() == (1000, 1000, 1000), "setresgid")
    check(sorted(os.getgroups()) == [24, 1000], "setgroups")
    with open(d + "/user-file", "w"):
        pass
    check(os.stat(d + "/user-file").st_uid == 1000, "a new file is the user's")
    check(os.stat(d + "/setuid-file").st_uid == 0, "a set-user-ID file is root's (Chromium's sandbox helper)")
    status = open("/proc/self/status").read()
    check("Uid:\t1000\t1000\t1000\t1000\n" in status, "/proc/self/status has the user's uid")
    check("Gid:\t1000\t1000\t1000\t1000\n" in status, "/proc/self/status has the user's gid")
    check(error_of(lambda: os.setuid(0)) == errno.EPERM, "back to root: EPERM")
    check(error_of(lambda: os.chroot("/")) == errno.EPERM, "chroot as a user: EPERM")
    os.write(w, "\n".join(out).encode())
    os._exit(0)
os.close(w)
child = b""
while True:
    b = os.read(r, 4096)
    if not b:
        break
    child += b
os.waitpid(pid, 0)
for line in child.decode().splitlines():
    ok(line.startswith("ok"), "child: " + line[5:])

# The saved set-uid: a set-uid program is allowed back to its owner
pid = os.fork()
if pid == 0:
    os.setresuid(1000, 1000, 0)
    os.setuid(0)
    os._exit(0 if os.getresuid() == (1000, 0, 0) else 1)
ok(os.waitpid(pid, 0)[1] == 0, "setresuid with a saved 0, then setuid(0)")

try:
    name = open("/etc/hostname").read().split()[0][:64]
except (OSError, IndexError):
    name = None
ok(name is None or os.uname().nodename == name, "uname()'s nodename is /etc/hostname's")

# A guest root drops to another user the way util-linux's setpriv does (man-db's trigger): keep the
# capabilities across setresuid(), raise the effective set again with capset(), then set the groups and the
# group ids. The same steps as a user, or without PR_SET_KEEPCAPS, fail.
def capget(libc):
    hdr = (ctypes.c_uint32 * 2)(0x20080522, 0)
    data = (ctypes.c_uint32 * 6)()
    libc.syscall(90, hdr, data)
    return data


def capset_effective_from_permitted(libc):
    data = capget(libc)
    data[0], data[3] = data[1], data[4]
    hdr = (ctypes.c_uint32 * 2)(0x20080522, 0)
    return libc.syscall(91, hdr, data)


def drop_like_setpriv(keep):
    libc.prctl(8, 1 if keep else 0, 0, 0, 0)  # (set above: an earlier check leaves it on)
    os.setresuid(6, 6, 6)
    if keep:
        ok_caps = capset_effective_from_permitted(libc)
        if ok_caps != 0:
            return "capset"
    try:
        os.setresgid(12, 12, 12)
        os.setgroups([12])
    except OSError as e:
        return "EPERM" if e.errno == errno.EPERM else "errno %d" % e.errno
    return "ok" if os.getresgid() == (12, 12, 12) and os.getresuid() == (6, 6, 6) else "ids"


def in_child(f):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.write(w, f().encode())
        finally:
            os._exit(0)
    os.close(w)
    out = os.read(r, 100).decode()
    os.waitpid(pid, 0)
    return out


ok(in_child(lambda: drop_like_setpriv(True)) == "ok", "root drops uid then gid with KEEPCAPS and capset (setpriv)")
ok(in_child(lambda: drop_like_setpriv(False)) == "EPERM", "without KEEPCAPS the group ids can no longer be set")


def user_cannot():
    libc.prctl(8, 0, 0, 0, 0)
    os.setgroups([1000])
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)
    libc.prctl(8, 1, 0, 0, 0)  # too late: the capabilities went with the uid change
    capset_effective_from_permitted(libc)  # accepted, but a user has nothing to raise
    try:
        os.setresgid(12, 12, 12)
    except OSError as e:
        return "EPERM" if e.errno == errno.EPERM else "errno %d" % e.errno
    return "no error"


ok(in_child(user_cannot) == "EPERM", "a user cannot set another group id, whatever capset() was asked")


def effective_back():  # root's euid dropped and restored keeps what root has
    os.seteuid(1000)
    os.seteuid(0)
    os.setgroups([5])
    return "ok"


ok(in_child(effective_back) == "ok", "root's seteuid(user) then seteuid(0) keeps the ability to set groups")

# capset() lowers (Linux's rules): the permitted pair is kept only when the new permitted set has both bits, the
# effective pair only when the new effective set has them as well
def capset_words(libc, eff, perm):
    data = (ctypes.c_uint32 * 6)()
    data[0], data[1], data[3], data[4] = eff, perm, eff, perm
    hdr = (ctypes.c_uint32 * 2)(0x20080522, 0)
    return libc.syscall(91, hdr, data)


def groups_result():
    try:
        os.setgroups([5])
    except OSError as e:
        return "EPERM" if e.errno == errno.EPERM else "errno %d" % e.errno
    return "ok"


def capset_keep():
    capset_words(libc, 0xffffffff, 0xffffffff)
    return groups_result()


def capset_drop_effective():  # the permitted pair stays, the effective pair goes, and comes back from permitted
    r = capset_words(libc, 0, 0xffffffff)
    before = groups_result()
    capset_effective_from_permitted(libc)
    return "%d %s %s" % (r, before, groups_result())


def capset_empty():
    r = capset_words(libc, 0, 0)
    after = groups_result()
    capset_effective_from_permitted(libc)  # nothing is permitted any more: still nothing to raise
    return "%d %s %s" % (r, after, groups_result())


def capset_empty_then_full():
    capset_words(libc, 0, 0)
    capset_words(libc, 0xffffffff, 0xffffffff)
    return groups_result()


def capset_empty_then_root():
    libc.prctl(8, 1, 0, 0, 0)
    os.setresuid(6, 6, 6)
    capset_effective_from_permitted(libc)
    capset_words(libc, 0, 0)
    try:
        os.setresuid(0, 0, 0)
    except OSError as e:
        return "EPERM" if e.errno == errno.EPERM else "errno %d" % e.errno
    return "no error"


def raised_then_root():  # the control: without the empty capset the same steps get root back
    libc.prctl(8, 1, 0, 0, 0)
    os.setresuid(6, 6, 6)
    capset_effective_from_permitted(libc)
    os.setresuid(0, 0, 0)
    return "ok"


ok(in_child(capset_keep) == "ok", "capset with both capabilities keeps them")
ok(in_child(capset_drop_effective) == "0 EPERM ok", "capset without them in the effective set drops that set only")
ok(in_child(capset_empty) == "0 EPERM EPERM", "capset with an empty permitted set drops both, and returns 0")
ok(in_child(capset_empty_then_full) == "EPERM", "capset cannot raise what an earlier capset dropped")
ok(in_child(capset_empty_then_root) == "EPERM", "after an empty capset setresuid(0, 0, 0) is EPERM")
ok(in_child(raised_then_root) == "ok", "without it setresuid(0, 0, 0) works after raising the effective set")


def exec_after_seteuid():  # exec with ruid 0 and euid 1000 keeps the permitted set
    import subprocess
    os.seteuid(1000)
    code = "import os; os.seteuid(0); os.setgroups([5]); print('ok')"
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    return p.stdout.strip() or "failed"


def exec_as_user():  # a program started with every id 1000 has nothing
    import subprocess
    os.setgroups([1000])
    os.setresgid(1000, 1000, 1000)
    os.setresuid(1000, 1000, 1000)
    code = "import os\ntry:\n os.setgroups([5]); print('ok')\nexcept OSError as e: print('EPERM' if e.errno == 1 else e.errno)"
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    return p.stdout.strip() or "failed"


ok(in_child(exec_after_seteuid) == "ok", "exec with seteuid(1000) done: seteuid(0) and setgroups still work")
ok(in_child(exec_as_user) == "EPERM", "exec with every id 1000: no capabilities")

import pwd
if shutil.which("setpriv") and shutil.which("id") and "man" in [u.pw_name for u in pwd.getpwall()]:
    import subprocess
    p = subprocess.run(["setpriv", "--reuid", "man", "--regid", "man", "--init-groups", "id", "-u"],
                       capture_output=True, text=True)
    ok(p.returncode == 0 and p.stdout.strip() == "6", "as root: setpriv --reuid man --regid man --init-groups id")
    p = subprocess.run(["setpriv", "--reuid", "man", "--regid", "man", "--init-groups", "setpriv",
                        "--reuid", "daemon", "--regid", "daemon", "id", "-u"], capture_output=True, text=True)
    ok(p.returncode != 0, "as the man user the same call fails")

shutil.rmtree(d)
sys.exit(1 if fails else 0)
