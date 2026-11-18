# The guest's own seccomp filters (Chromium's sandbox, Firefox's) nested over Burrow's:
# - a filter that denies a call Burrow traps (ERRNO) decides it, as Chromium's start-up check
#   fchmod(-1, 07777) expects (an unfiltered call gets EBADF from the emulation);
# - the calls Burrow makes itself (path walks, owner records) are not subject to it;
# - its traps (RET_TRAP) reach the guest's SIGSYS handler, with its own data, also for calls Burrow traps;
# - the same through prctl(PR_SET_SECCOMP).
# - Android's own traps (SysV IPC, unshare, mount) under a filter behave as without one;
# - the filter's reach: across execve and fork, stacked, per thread and with TSYNC;
# - the gadget lets through only the calls Burrow makes for itself: a connect or an execve made from it is
#   denied by a guest ERRNO filter;
# - the filter's own validation (NULL, bad pointer, empty, too long), NEW_LISTENER's descriptor, ERRNO with 0,
#   the kills.
# (Android already puts a filter on the app, so prctl(PR_GET_SECCOMP) is 2 here with or without.)
import ctypes
import mmap
import shutil
import threading
import errno
import os
import signal
import struct
import sys
import tempfile

fails = 0


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


libc = ctypes.CDLL(None, use_errno=True)

if sys.argv[1:] == ["exec-child"]:  # the program test 5 execs into
    try:
        os.fchmod(-1, 0o7777)
    except OSError as e:
        sys.exit(0 if e.errno == errno.EPERM else 2)
    sys.exit(1)
NR = {"fchmod": 52, "getuid": 174, "newfstatat": 79, "openat2": 437, "fgetxattr": 10, "fsetxattr": 7,
      "fstat": 80, "openat": 56, "faccessat": 48, "execve": 221, "connect": 203, "shmget": 194, "unshare": 97}
ALLOW, TRAP, ERRNO = 0x7fff0000, 0x00030000, 0x00050000
KILL_THREAD, KILL_PROCESS = 0x00000000, 0x80000000


def program(rules, pad=0):
    """cBPF: for each syscall name -> return value, else allow (arm64 only); pad: extra no-op instructions."""
    ins = [struct.pack("HBBI", 0x20, 0, 0, 0)] * (1 + pad)  # ld nr
    for name, ret in rules.items():
        ins.append(struct.pack("HBBI", 0x15, 0, 1, NR[name]))  # jeq nr, next, skip
        ins.append(struct.pack("HBBI", 0x06, 0, 0, ret))
    ins.append(struct.pack("HBBI", 0x06, 0, 0, ALLOW))
    return b"".join(ins), len(ins)


def install(rules, how="seccomp", flags=0, pad=0):
    blob, n = program(rules, pad)
    buf = ctypes.create_string_buffer(blob, len(blob))
    prog = struct.pack("HxxxxxxQ", n, ctypes.addressof(buf))
    pbuf = ctypes.create_string_buffer(prog, len(prog))
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    arg = ctypes.c_void_p(ctypes.addressof(pbuf))  # not an int: ctypes would pass 32 bits
    if how == "seccomp":
        r = libc.syscall(ctypes.c_long(277), ctypes.c_long(1), ctypes.c_long(flags), arg)
    else:
        r = libc.prctl(ctypes.c_long(22), ctypes.c_long(2), arg, ctypes.c_long(0), ctypes.c_long(0))
    if r < 0 or (r > 0 and not flags & 8):
        os._exit(90)
    return r


def child(f):
    pid = os.fork()
    if pid == 0:
        try:
            f()
        except OSError as e:
            os._exit(60 + e.errno % 30)
        os._exit(0)
    return os.waitpid(pid, 0)[1]


def passed(status):
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def errno_of(call):
    try:
        call()
    except OSError as e:
        return e.errno
    return 0


# 1. A denying filter decides a call Burrow traps.
def deny():
    if errno_of(lambda: os.fchmod(-1, 0o7777)) != errno.EBADF:
        os._exit(91)  # unfiltered: the emulation's EBADF
    install({"fchmod": ERRNO | errno.EPERM})
    os._exit(0 if errno_of(lambda: os.fchmod(-1, 0o7777)) == errno.EPERM else 92)


ok(passed(child(deny)), "a filter's ERRNO for a trapped call (fchmod(-1, 07777)) is the call's result")


# 2. Burrow's own calls pass the filter: it denies the ones a path walk and an owner record make.
d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-seccomp."))
os.makedirs(d + "/a/b/c")
with open(d + "/a/b/c/f", "w") as out:
    out.write("data")


def own_calls():
    install({"newfstatat": ERRNO | errno.EPERM, "openat2": TRAP | 1, "fgetxattr": ERRNO | errno.EPERM,
             "fsetxattr": ERRNO | errno.EPERM})
    fd = os.open(d + "/a/b/c/f", os.O_RDONLY)
    os._exit(0 if os.read(fd, 4) == b"data" else 93)


ok(passed(child(own_calls)), "path walks and owner records are not subject to the guest's filter")


# 3. The guest's traps reach its handler, from a call Burrow traps too.
class Sigaction(ctypes.Structure):  # glibc's struct sigaction on arm64
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_uint64 * 16), ("flags", ctypes.c_int),
                ("restorer", ctypes.c_void_p)]


HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
seen = []


@HANDLER
def emulate(sig, info, uc):
    # siginfo: signo, errno (SECCOMP_RET_DATA), code, pad, call_addr, syscall
    seen.append((ctypes.c_int.from_address(info + 4).value, ctypes.c_int.from_address(info + 24).value))
    ctypes.c_uint64.from_address(uc + 184).value = 4242  # uc_mcontext.regs[0]


def trap(how):
    def run():
        act = Sigaction(ctypes.cast(emulate, ctypes.c_void_p), flags=4 | 0x40000000)  # SA_SIGINFO | SA_NODEFER
        libc.sigaction(signal.SIGSYS, ctypes.byref(act), None)
        install({"getuid": TRAP | 7}, how)
        r = os.getuid()
        os._exit(0 if r == 4242 and seen == [(7, NR["getuid"])] else 94)
    return run


ok(passed(child(trap("seccomp"))), "a filter's TRAP for a call Burrow traps (getuid) reaches the guest's handler")
ok(passed(child(trap("prctl"))), "the same with prctl(PR_SET_SECCOMP)")


# 4. Android's own traps (Burrow emulates these) are not taken for the guest's verdict under a filter.
def sysv_unshare():
    shm = libc.syscall(ctypes.c_long(NR["shmget"]), ctypes.c_long(0), ctypes.c_long(4096), ctypes.c_long(0o1600))
    e1 = ctypes.get_errno()
    if shm >= 0:
        libc.syscall(ctypes.c_long(195), ctypes.c_long(shm), ctypes.c_long(0), ctypes.c_long(0))  # shmctl(IPC_RMID)
    un = libc.syscall(ctypes.c_long(NR["unshare"]), ctypes.c_long(0x20000))  # CLONE_NEWNS
    return (shm >= 0, e1 if shm < 0 else 0, un, ctypes.get_errno() if un < 0 else 0)


with tempfile.TemporaryFile() as note:
    def baseline():
        note.write(repr(sysv_unshare()).encode())
        note.flush()
    child(baseline)
    note.seek(0)
    expected = note.read().decode()

    def filtered():
        install({"getuid": ERRNO | errno.EACCES})
        os._exit(0 if repr(sysv_unshare()) == expected else 96)
    ok(passed(child(filtered)), "shmget and unshare under a trivial filter act as without one " + expected)


# 5. The filter reaches the execve'd program and the forked child.
def after_exec():
    install({"fchmod": ERRNO | errno.EPERM})
    os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), "exec-child"])


def after_fork():
    install({"fchmod": ERRNO | errno.EPERM})
    pid = os.fork()
    if pid == 0:
        os._exit(0 if errno_of(lambda: os.fchmod(-1, 0o7777)) == errno.EPERM else 97)
    os._exit(0 if passed(os.waitpid(pid, 0)[1]) else 98)


def denied_exec():
    install({"execve": ERRNO | errno.EPERM})
    os._exit(0 if errno_of(lambda: os.execv(sys.executable, [sys.executable, "-c", "pass"])) == errno.EPERM else 99)


ok(passed(child(after_exec)), "a filter, then execve: the next program is still filtered (a trapped call is denied)")
ok(passed(child(after_fork)), "a filter, then fork: the child is filtered")
ok(passed(child(denied_exec)), "a filter's ERRNO for execve is the call's result")


# 6. Two filters, the newer one's errno first; both in force.
def stacked():
    install({"fchmod": ERRNO | errno.EPERM})
    install({"fchmod": ERRNO | errno.EACCES, "getuid": ERRNO | errno.EBUSY})
    if errno_of(lambda: os.fchmod(-1, 0o7777)) != errno.EACCES:
        os._exit(91)
    libc.syscall(ctypes.c_long(NR["getuid"]))
    os._exit(0 if ctypes.get_errno() == errno.EBUSY else 92)


ok(passed(child(stacked)), "two stacked filters: the newer one's errno, and each one's own rule")


# 7. A filter of one thread, with and without TSYNC.
def threads(flags):
    def run():
        out = {}

        def worker():
            install({"fchmod": ERRNO | errno.EPERM}, flags=flags)
            out["worker"] = errno_of(lambda: os.fchmod(-1, 0o7777))
        t = threading.Thread(target=worker)
        t.start()
        t.join()
        out["main"] = errno_of(lambda: os.fchmod(-1, 0o7777))
        want = errno.EPERM if flags & 1 else errno.EBADF
        os._exit(0 if out == {"worker": errno.EPERM, "main": want} else 93)
    return run


ok(passed(child(threads(0))), "a filter set by a thread filters that thread only")
ok(passed(child(threads(1))), "a filter set with TSYNC filters every thread")


# 8. NEW_LISTENER gives a descriptor; the filter still works.
def listener():
    fd = install({"fchmod": ERRNO | errno.EPERM}, flags=8)
    os._exit(0 if fd > 2 and errno_of(lambda: os.fchmod(-1, 0o7777)) == errno.EPERM else 94)


ok(passed(child(listener)), "NEW_LISTENER returns a descriptor, and the filter is in force")


# 9. ERRNO with 0 is success: the call is not emulated.
def errno_zero():
    install({"fchmod": ERRNO | 0})
    try:
        os.fchmod(-1, 0o7777)
    except OSError:
        os._exit(95)
    os._exit(0)


ok(passed(child(errno_zero)), "RET_ERRNO with 0 makes the trapped call succeed")


# 10. The kills.
def killed(ret):
    def run():
        install({"fchmod": ret})
        os.fchmod(-1, 0o7777)
        os._exit(0)
    status = child(run)
    return os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGSYS


ok(killed(KILL_THREAD), "RET_KILL_THREAD on a trapped call kills with SIGSYS")
ok(killed(KILL_PROCESS), "RET_KILL_PROCESS on a trapped call kills with SIGSYS")


# 11. The filter's validation.
def invalid():
    libc.prctl(38, 1, 0, 0, 0)
    seccomp = lambda arg, flags=0: (libc.syscall(ctypes.c_long(277), ctypes.c_long(1), ctypes.c_long(flags),
                                                 ctypes.c_void_p(arg)), ctypes.get_errno())
    prctl = lambda arg: (libc.prctl(ctypes.c_long(22), ctypes.c_long(2), ctypes.c_void_p(arg), ctypes.c_long(0),
                                    ctypes.c_long(0)), ctypes.get_errno())
    empty = ctypes.create_string_buffer(struct.pack("HxxxxxxQ", 0, 0), 16)
    nofilter = ctypes.create_string_buffer(struct.pack("HxxxxxxQ", 1, 0), 16)
    wild = ctypes.create_string_buffer(struct.pack("HxxxxxxQ", 1, 0x1000), 16)
    got = [seccomp(0), prctl(0), seccomp(0x1000), seccomp(ctypes.addressof(empty)), seccomp(ctypes.addressof(nofilter)),
           seccomp(ctypes.addressof(wild)), prctl(ctypes.addressof(wild))]
    want = [(-1, errno.EFAULT), (-1, errno.EFAULT), (-1, errno.EFAULT), (-1, errno.EINVAL), (-1, errno.EFAULT),
            (-1, errno.EFAULT), (-1, errno.EFAULT)]
    os._exit(0 if got == want else 80 + [g == w for g, w in zip(got, want)].index(False))


ok(passed(child(invalid)), "NULL, a bad pointer, no instructions: EFAULT or EINVAL, and nothing installed")


# 12. Long filters: with the prologue, without room for it, and past the kernel's limit.
def long_filter(length, want):
    def run():
        if want == 0:  # ld nr (padded), the rule's jeq and ret, the final allow
            install({"fchmod": ERRNO | errno.EPERM}, pad=length - 4)
            os._exit(0 if errno_of(lambda: os.fchmod(-1, 0o7777)) == errno.EPERM and
                     os.read(os.open(d + "/a/b/c/f", os.O_RDONLY), 4) == b"data" else 70)
        blob, n = program({}, length - 2)
        buf = ctypes.create_string_buffer(blob, len(blob))
        pbuf = ctypes.create_string_buffer(struct.pack("HxxxxxxQ", n, ctypes.addressof(buf)), 16)
        libc.prctl(38, 1, 0, 0, 0)
        r = libc.syscall(ctypes.c_long(277), ctypes.c_long(1), ctypes.c_long(0), ctypes.c_void_p(ctypes.addressof(pbuf)))
        os._exit(0 if r == -1 and ctypes.get_errno() == want else 71)
    return run


ok(passed(child(long_filter(3990, 0))), "a filter of about 4000 instructions (with the prologue): ERRNO and Burrow's own calls")
ok(passed(child(long_filter(4090, 0))), "a filter with no room for the prologue is installed as it is")
ok(passed(child(long_filter(4200, errno.EINVAL))), "a filter over 4096 instructions: EINVAL")


# 13. The gadget lets through only what Burrow makes for itself: a connect or an execve from it is denied.
def find_gadget():
    base = 0x5600000000  # Burrow's image base
    pattern = struct.pack("<II", 0xd4000001, 0xd65f03c0)  # svc #0; ret
    with open("/proc/self/mem", "rb", buffering=0) as mem:
        for off in range(0, 0x100000, 0x1000):
            try:
                mem.seek(base + off)
                page = mem.read(0x1000)
            except OSError:
                continue
            for at in range(0, len(page) - 7, 16):
                if page[at:at + 8] == pattern:
                    return base + off + at
    return 0


def from_gadget():
    gadget = find_gadget()
    if gadget == 0:
        sys.stderr.write("gadget not found\n")
        os._exit(81)
    code = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    code.write(struct.pack("<II", 0xAA0603E8, 0xD61F00E0))  # mov x8, x6; br x7
    tramp = ctypes.CFUNCTYPE(ctypes.c_long, *[ctypes.c_long] * 6, ctypes.c_long, ctypes.c_void_p)(
        ctypes.addressof(ctypes.c_char.from_buffer(code)))
    gate = lambda nr, *a: tramp(*(list(a) + [0] * (6 - len(a))), nr, ctypes.c_void_p(gadget))
    path = ctypes.create_string_buffer(b"/nonexistent")
    before = (gate(NR["connect"], -1, 0, 0), gate(NR["execve"], ctypes.addressof(path), 0, 0))
    if before != (-errno.EBADF, -errno.ENOENT):
        sys.stderr.write("before the filter: %r\n" % (before,))
        os._exit(82)
    install({"connect": ERRNO | errno.EPERM, "execve": ERRNO | errno.EPERM, "openat": ERRNO | errno.EPERM,
             "newfstatat": ERRNO | errno.EPERM})
    after = (gate(NR["connect"], -1, 0, 0), gate(NR["execve"], ctypes.addressof(path), 0, 0))
    dot = ctypes.create_string_buffer(b"/proc/self/status")  # the host's: the gadget makes raw calls
    opened = gate(NR["openat"], -100, ctypes.addressof(dot), 0)  # Burrow's own: let through
    if not (after == (-errno.EPERM, -errno.EPERM) and opened >= 0):
        sys.stderr.write("under the filter: %r, openat %r\n" % (after, opened))
        os._exit(83)
    os._exit(0)


ok(passed(child(from_gadget)), "a connect and an execve made from the gadget are denied by a guest filter; its openat is not")


shutil.rmtree(d, ignore_errors=True)
sys.exit(1 if fails else 0)
