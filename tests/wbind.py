# -W bindings (wbind.sh starts the guest): read-only, and the symlinks below are guest paths.
import ctypes
import errno
import os
import sys
import time

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


if not os.path.isdir("/opt/wbind1"):
    print("skip no -W bindings (run wbind.sh)")
    sys.exit(0)

W1, W2, B1, RW = "/opt/wbind1", "/opt/wbind2", "/opt/wbind-b", "/wbind-rw"
# Root mode (a chroot with real read-only bind mounts, run by hand): the kernel's rules, so the checks of
# Burrow's own emulation (how -B resolves links, what umount() and mount() do to a binding) do not apply.
ROOT = os.environ.get("KESTREL_BACKEND") == "root"


def error_of(f):
    try:
        f()
    except OSError as e:
        return e.errno
    return 0


def text(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return errno.errorcode[e.errno]


def host_switch(n, target):
    """The host renames a new link over /opt/wbind1/current (wbind.sh); returns when it is done."""
    with open(RW + "/want-%d" % n, "w") as f:
        f.write(target + "\n")
    for _ in range(200):
        if os.path.exists(RW + "/done-%d" % n):
            return True
        time.sleep(0.05)
    return False


def warm():
    for _ in range(50):
        os.stat("/tmp/wb-into/ORDER")  # symlinks of the rootfs whose text the path cache holds, leading into the binding
        os.stat("/tmp/wb-into2/ORDER")
        os.stat(W1 + "/current/ORDER")
        os.stat(W2 + "/apps/ORDER")
        open(W1 + "/current/ORDER").close()
        os.listdir(W2 + "/chain")
        os.chdir(W1 + "/current")
    os.chdir("/")


# links resolve as guest paths
ok(text(W1 + "/abs/ORDER") == "SHARE", "absolute link to the other -W binding: open")
ok("ORDER" in os.listdir(W1 + "/abs"), "absolute link: list")
ok(os.path.isdir(W1 + "/abs") and os.path.realpath(W1 + "/abs") == W2 + "/share", "absolute link: isdir, realpath")
os.chdir(W1 + "/abs")
ok(os.getcwd() == W2 + "/share" and text("ORDER") == "SHARE", "absolute link: chdir")
os.chdir("/")
ok(text(W2 + "/apps/ORDER") == "AAAA", "link into the other binding's link (tools/apps -> catalog/current)")
ok(text(W2 + "/chain/ORDER") == "AAAA", "link -> link -> folder")
ok(text(W1 + "/rel/ORDER") == "AAAA", "relative link")
ok(os.readlink(W2 + "/apps") == "/opt/wbind1/current" and os.readlink(W1 + "/rel") == "current"
   and os.readlink(W1 + "/current") == "a", "readlink: the text is unchanged")
ok(text(W2 + "/apps/x/y/z/file") == "deep", "a file four folders below, through a link")
ok(text(W2 + "/procself/status").find("Name:") >= 0, "a link to /proc/self (a -b binding) works")
ok(open("/proc/self/exe", "rb").read(4) == b"\x7fELF", "/proc/self/exe opens")
keep = open("/etc/hostname")
ok(error_of(lambda: os.close(os.open("/dev/fd/%d" % keep.fileno(), os.O_RDONLY))) == 0, "/dev/fd/N opens")
e = error_of(lambda: os.close(os.open("/dev/fd/0", os.O_RDONLY)))
ok(e in (0, errno.ENXIO, errno.EACCES), "/dev/fd/0 opens, or is refused as by the kernel (%s)" % errno.errorcode.get(e, e))
ok(text(W1 + "/../wbind2/share/ORDER") == "SHARE" and os.path.realpath(W1 + "/..") == "/opt",
   "..: from the top of a binding, the guest's parent")
ok(os.path.realpath(W1 + "/current/..") == W1, "..: below a link")

# -B stays as it was: a link there is read by the host kernel
ok(text(B1 + "/file") == "bfile", "-B: a file opens")
if not ROOT:
    ok(error_of(lambda: open(B1 + "/link/ORDER")) == errno.ENOENT, "-B: a link naming a guest path still gives ENOENT (unchanged)")

# chroot into it
pid = os.fork()
if pid == 0:
    try:
        os.chroot(W1)
        os.chdir("/")
        # Writes after chroot() are checked below (chroot_inside and the others).
        good = text("/a/ORDER") == "AAAA" and text("/current/ORDER") == "AAAA" and text("/rel/ORDER") == "AAAA"
    except Exception as e:
        print("     " + repr(e))
        good = False
    os._exit(0 if good else 1)
ok(os.waitpid(pid, 0)[1] == 0, "chroot into a -W binding: its links resolve")

# read-only
tests = {
    "create": lambda: open(W1 + "/new", "w"),
    "create below a link": lambda: open(W2 + "/apps/new", "w"),
    "write": lambda: open(W1 + "/a/ORDER", "w"),
    "append": lambda: open(W1 + "/b/ORDER", "a"),
    "truncate": lambda: os.truncate(W1 + "/a/ORDER", 0),
    "unlink": lambda: os.unlink(W1 + "/a/only-a"),
    "unlink the link": lambda: os.unlink(W1 + "/current"),
    "rmdir": lambda: os.rmdir(W1 + "/a/x/y/z"),
    "mkdir": lambda: os.mkdir(W1 + "/dir"),
    "rename": lambda: os.rename(W1 + "/a/ORDER", W1 + "/a/ORDER2"),
    "rename the link": lambda: os.rename(W1 + "/current", W1 + "/current2"),
    "chmod": lambda: os.chmod(W1 + "/a/ORDER", 0o600),
    "chown": lambda: os.chown(W1 + "/a/ORDER", 1234, 1234),
    "utime": lambda: os.utime(W1 + "/a/ORDER", (1, 1)),
    "symlink": lambda: os.symlink("b", W1 + "/current.new"),
    "link": lambda: os.link(W1 + "/a/ORDER", W1 + "/a/hard"),
    "mkfifo": lambda: os.mkfifo(W1 + "/fifo"),
}
for name, f in tests.items():
    e = error_of(f)
    ok(e == errno.EROFS, "-W: %s gives EROFS (%s)" % (name, errno.errorcode.get(e, e)))
os.symlink("b", "/tmp/wb-new")
e = error_of(lambda: os.rename("/tmp/wb-new", W1 + "/current"))
ok(e in (errno.EROFS, errno.EXDEV), "-W: a new link renamed over `current` fails (%s)" % errno.errorcode.get(e, e))
os.unlink("/tmp/wb-new")
ok(text(W1 + "/current/ORDER") == "AAAA", "nothing changed")

# descriptors: a file or folder opened first, then changed through the descriptor
EROFS = errno.EROFS
fd = os.open(W1 + "/a/ORDER", os.O_RDONLY)
dfd = os.open(W1 + "/a", os.O_RDONLY | os.O_DIRECTORY)
pfd = os.open(W1 + "/a/ORDER", os.O_PATH)
fd_tests = {
    "fchmod": lambda: os.fchmod(fd, 0o600),
    "fchown": lambda: os.fchown(fd, 1234, 1234),
    "futimens": lambda: os.utime(fd, (1, 1)),
    "fsetxattr": lambda: os.setxattr(fd, "user.wb", b"1"),
    "openat(dirfd) create": lambda: os.open("new", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=dfd),
    "openat(dirfd) write": lambda: os.open("ORDER", os.O_WRONLY, dir_fd=dfd),
    "unlinkat(dirfd)": lambda: os.unlink("only-a", dir_fd=dfd),
    "unlinkat(dirfd) rmdir": lambda: os.rmdir("x/y/z", dir_fd=dfd),
    "mkdirat(dirfd)": lambda: os.mkdir("d", dir_fd=dfd),
    "renameat(dirfd)": lambda: os.rename("ORDER", "ORDER2", src_dir_fd=dfd, dst_dir_fd=dfd),
    "symlinkat(dirfd)": lambda: os.symlink("b", "ln", dir_fd=dfd),
    "fchmodat(dirfd)": lambda: os.chmod("ORDER", 0o600, dir_fd=dfd),
    "fchownat(dirfd)": lambda: os.chown("ORDER", 1234, 1234, dir_fd=dfd),
    "utimensat(dirfd)": lambda: os.utime("ORDER", (1, 1), dir_fd=dfd),
    "O_PATH descriptor reopened for writing through /proc/self/fd": lambda: os.open("/proc/self/fd/%d" % pfd, os.O_WRONLY),
    "folder descriptor: create through /proc/self/fd": lambda: os.open("/proc/self/fd/%d/new" % dfd, os.O_CREAT | os.O_WRONLY, 0o644),
    "write through /proc/self/cwd": lambda: (os.chdir(W1 + "/a"), os.open("/proc/self/cwd/new", os.O_CREAT | os.O_WRONLY, 0o644)),
}
for name, f in fd_tests.items():
    e = error_of(f)
    ok(e == EROFS, "-W: %s gives EROFS (%s)" % (name, errno.errorcode.get(e, e)))
os.chdir("/")
e = error_of(lambda: os.link("ORDER", "/tmp/wb-hard", src_dir_fd=dfd))
ok(e == errno.EXDEV, "-W: a hard link from it to a writable folder gives EXDEV (%s)" % errno.errorcode.get(e, e))
e = error_of(lambda: os.link(W1 + "/a/ORDER", "/tmp/wb-hard"))
ok(e == errno.EXDEV, "-W: linkat by path to a writable folder gives EXDEV (%s)" % errno.errorcode.get(e, e))
ok(text(W1 + "/a/ORDER") == "AAAA" and not os.path.exists(W1 + "/a/new"), "descriptor writes changed nothing")

# mount, umount and chroot: what a guest root does cannot make the files writable
libc = ctypes.CDLL(None, use_errno=True)
MS_BIND = 4096


def mount(src, dst, flags=MS_BIND):
    return 0 if libc.mount(src.encode(), dst.encode(), None, flags, None) == 0 else ctypes.get_errno()


def umount(dst):
    return 0 if libc.umount2(dst.encode(), 0) == 0 else ctypes.get_errno()


def in_child(fn):
    """fn runs in a child (bindings and root are per process); its failures count here."""
    global fails
    sys.stdout.flush()
    pid = os.fork()
    if pid == 0:
        fails = 0
        try:
            fn()
        except BaseException as e:
            print("     " + repr(e))
            fails += 1
        sys.stdout.flush()
        os._exit(1 if fails else 0)
    fails += os.waitpid(pid, 0)[1] != 0


def create_in(d):
    return lambda: os.open("new", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=d)


def bind_inside():
    os.makedirs("/mnt/wb", exist_ok=True)
    e = mount(W1, "/mnt/wb")
    ok(e == 0, "mount --bind of a -W folder (%s)" % errno.errorcode.get(e, e))
    ok(text("/mnt/wb/a/ORDER") == "AAAA" and text("/mnt/wb/rel/ORDER") == "AAAA", "the new mount reads, links resolve")
    for name, f in {"create": lambda: open("/mnt/wb/a/new", "w"), "write": lambda: open("/mnt/wb/a/ORDER", "w"),
                    "unlink": lambda: os.unlink("/mnt/wb/a/only-a"), "mkdir": lambda: os.mkdir("/mnt/wb/d"),
                    "rename": lambda: os.rename("/mnt/wb/a/ORDER", "/mnt/wb/a/O2")}.items():
        e = error_of(f)
        ok(e == EROFS, "the bind mount of a -W folder: %s gives EROFS (%s)" % (name, errno.errorcode.get(e, e)))
    e = mount(W1 + "/a", "/mnt/wb")
    ok(e == 0 and error_of(lambda: open("/mnt/wb/ORDER", "w")) == EROFS, "a bind of a folder inside it is read-only too")
    e = umount("/mnt/wb")
    ok(e == 0, "umount of the guest's own mount (%s)" % errno.errorcode.get(e, e))


def umount_launch():
    d = os.open(W1 + "/a", os.O_RDONLY | os.O_DIRECTORY)
    f = os.open(W1 + "/a/ORDER", os.O_RDONLY)
    e = umount(W1)
    ok(e in (0, errno.EBUSY), "umount of the launch's -W binding is refused or has no effect (%s)" % errno.errorcode.get(e, e))
    ok(text(W1 + "/a/ORDER") == "AAAA", "the binding is still there after umount")
    ok(error_of(create_in(d)) == EROFS, "create through a descriptor held across umount")
    ok(error_of(lambda: os.open("/proc/self/fd/%d" % f, os.O_WRONLY)) == EROFS, "reopen for writing through /proc/self/fd across umount")
    ok(error_of(lambda: os.open("/proc/self/fd/%d/new" % d, os.O_CREAT | os.O_WRONLY, 0o644)) == EROFS, "create via /proc/self/fd/N/ across umount")
    umount(B1)
    ok(error_of(lambda: os.open(B1 + "/new", os.O_CREAT | os.O_WRONLY, 0o644)) == EROFS, "the same for the -B binding")


def mount_over():
    d = os.open(W1 + "/a", os.O_RDONLY | os.O_DIRECTORY)
    e = mount(RW, W1)
    ok(e in (0, errno.EBUSY), "a mount of a writable folder over the -W binding (%s)" % errno.errorcode.get(e, e))
    ok(error_of(create_in(d)) == EROFS, "create through a descriptor opened before the mount")
    umount(W1)
    ok(error_of(create_in(d)) == EROFS, "and after umount of that mount")


def chroot_after():
    d = os.open(W1 + "/a", os.O_RDONLY | os.O_DIRECTORY)
    f = os.open(W1 + "/a/ORDER", os.O_RDONLY)
    os.chroot("/opt")
    os.chdir("/")
    ok(error_of(create_in(d)) == EROFS, "chroot to /opt: create through a descriptor opened before")
    ok(error_of(lambda: os.open("/proc/self/fd/%d" % f, os.O_WRONLY)) in (errno.ENOENT, EROFS), "chroot to /opt: reopen through /proc/self/fd (no /proc there, or read-only)")
    ok(error_of(lambda: os.fchmod(f, 0o600)) == EROFS, "chroot to /opt: fchmod through a descriptor opened before")


def chroot_inside():
    d = os.open(W1 + "/a", os.O_RDONLY | os.O_DIRECTORY)
    os.chroot(W1)
    os.chdir("/")
    ok(error_of(lambda: open("/a/ORDER", "w")) == EROFS, "chroot into the -W binding: write by path gives EROFS")
    ok(error_of(lambda: open("/a/new", "w")) == EROFS, "chroot into the -W binding: create by path gives EROFS")
    ok(error_of(lambda: os.unlink("/a/only-a")) == EROFS, "chroot into the -W binding: unlink gives EROFS")
    ok(error_of(lambda: os.mkdir("/dir")) == EROFS, "chroot into the -W binding: mkdir gives EROFS")
    ok(error_of(create_in(d)) == EROFS, "chroot into the -W binding: create through a descriptor")
    ok(text("/rel/ORDER") == "AAAA", "chroot into the -W binding: links still resolve")


def chroot_into_b():
    os.chroot(B1)
    os.chdir("/")
    ok(error_of(lambda: open("/file", "w")) == EROFS, "chroot into the -B binding: write gives EROFS")
    ok(error_of(lambda: open("/new", "w")) == EROFS, "chroot into the -B binding: create gives EROFS")


def chroot_below():
    os.chroot(W1 + "/a/x")
    os.chdir("/")
    ok(error_of(lambda: open("/y/z/file", "w")) == EROFS, "chroot into a folder below the -W binding: write gives EROFS")


in_child(bind_inside)
if not ROOT:
    in_child(umount_launch)
    in_child(mount_over)
in_child(chroot_after)
in_child(chroot_inside)
in_child(chroot_into_b)
in_child(chroot_below)
ok(text(W1 + "/a/ORDER") == "AAAA" and not os.path.exists(W1 + "/a/new"), "nothing below the binding changed")

# the host switches the link under running processes whose path cache is warm; /tmp/wb-into and /tmp/wb-into2 are
# links of the rootfs (cached) that lead into the binding: only the part inside it may change
for l in ("/tmp/wb-into", "/tmp/wb-into2"):
    if os.path.lexists(l):
        os.unlink(l)
os.symlink(W1 + "/current", "/tmp/wb-into")
os.symlink("wb-into", "/tmp/wb-into2")
pr, pw = os.pipe()  # child -> parent
cr, cw = os.pipe()  # parent -> child
held = os.fork()
if held == 0:
    os.chdir(W1 + "/current")  # the folder a
    os.write(pw, b"r")
    os.read(cr, 1)
    os.write(pw, (text("ORDER") + " " + text("only-a") + " " + os.getcwd()).encode())
    os._exit(0)
os.read(pr, 1)
warm()
stages = [("b", "BBBB"), ("/opt/wbind2/share", "SHARE"), ("/opt/wbind1/b", "BBBB"), ("a", "AAAA")]
for n, (target, want) in enumerate(stages, 1):
    done = host_switch(n, target)
    ok(done, "stage %d: the host renamed a new link `%s` over current" % (n, target))
    ok(os.readlink(W1 + "/current") == target, "stage %d: readlink shows the new text" % n)
    ok(text(W1 + "/current/ORDER") == want, "stage %d: the next open (cache warm) reads %s" % (n, want))
    ok(text(W2 + "/apps/ORDER") == want, "stage %d: the same through tools/apps -> catalog/current" % n)
    ok(text(W2 + "/chain/ORDER") == want, "stage %d: link -> link -> link" % n)
    ok(text("/tmp/wb-into/ORDER") == want and text("/tmp/wb-into2/ORDER") == want,
       "stage %d: cached links of the rootfs into the binding follow the switch" % n)
    os.chdir(W1 + "/current")
    ok(os.getcwd() == os.path.normpath(target if target[0] == "/" else W1 + "/" + target) and text("ORDER") == want,
       "stage %d: cd current && pwd -P" % n)
    os.chdir("/")
    child = os.fork()
    if child == 0:
        os.execv("/bin/sh", ["sh", "-c", 'test "$(cat %s/current/ORDER)" = %s' % (W1, want)])
    ok(os.waitpid(child, 0)[1] == 0, "stage %d: a new process reads %s at its first open" % (n, want))
os.unlink("/tmp/wb-into")
os.unlink("/tmp/wb-into2")
os.write(cw, b"g")
res = os.read(pr, 100).decode()
ok(res == "AAAA only-a " + W1 + "/a", "a process whose working directory is the old folder keeps it (%s)" % res)
os.waitpid(held, 0)
sys.exit(1 if fails else 0)
