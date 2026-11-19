# mprotect(PROT_EXEC) on a private file mapping that was written (SELinux "execmod": Android refuses it to apps).
# Wine does this for every PE module it loads: map the file, relocate, then make the code executable.
# - the call succeeds and the written content stays;
# - the code runs (arm64 only: a function returning 42 and one returning the argument plus one);
# - the same through a range that covers several pages, one of them never touched;
# - other protections and errors keep their meaning: ENOMEM for an unmapped range, a read-only mapping stays read-only;
# - the pages that are not the file's any more do not write through to it.
# PROT_BTI (arm64 branch protection) is dropped for Wine's programs only (a path below a wine/ directory, wine64 and the
# like by base name, or BURROW_NO_BTI=1 in the environment) and kept for all others: after mprotect(PROT_EXEC|PROT_BTI)
# the "bt" flag shows in /proc/self/smaps in the one and not in the other; what Wine starts does not inherit it.
import ctypes
import ctypes.util
import errno
import mmap
import os
import platform
import struct
import sys
import tempfile

fails = 0
PROT_BTI = 0x10


def bti_flag():
    """mmap(PROT_EXEC|PROT_BTI) and mprotect(PROT_EXEC|PROT_BTI): is "bt" in the smaps flags of each?"""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    out = []
    a = libc.mmap(None, 4096, 3, 0x22, -1, 0)
    r1 = libc.mprotect(a, 4096, 5 | PROT_BTI)
    b = libc.mmap(None, 4096, 5 | PROT_BTI, 0x22, -1, 0)
    smaps = open("/proc/self/smaps").read()
    for addr in (a, b):
        i = smaps.index("%x-" % addr)
        j = smaps.index("VmFlags", i)
        out.append("bt" in smaps[j:smaps.index("\n", j)].split())
    return r1, out


if sys.argv[1:] == ["bti-child"]:
    r, flags = bti_flag()
    print("bti", r, int(flags[0]), int(flags[1]))
    sys.exit(0)
if sys.argv[1:] == ["wine-then-other"]:  # run as a Wine program: starts a program that is not
    import subprocess
    sys.exit(subprocess.call([os.path.realpath(sys.executable), __file__, "bti-child"]))


def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    fails += not cond


libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
PAGE = 4096
RW, RX, RWX = 3, 5, 7
RET42 = struct.pack("<II", 0x52800540, 0xD65F03C0)  # mov w0, #42; ret
INC = struct.pack("<II", 0x11000400, 0xD65F03C0)  # add w0, w0, #1; ret
arm = platform.machine() in ("aarch64", "arm64")

d = tempfile.mkdtemp()
path = d + "/image"
with open(path, "wb") as f:
    f.write(b"\0" * (3 * PAGE))
fd = os.open(path, os.O_RDWR)

# written private file mapping, then executable
m = libc.mmap(None, 3 * PAGE, RW, mmap.MAP_PRIVATE, fd, 0)
ok(m not in (None, ctypes.c_void_p(-1).value), "map a file privately, read-write")
ctypes.memmove(m, RET42, 8)
ctypes.memmove(m + PAGE, INC, 8)
ctypes.memset(m + 2 * PAGE, 0x5A, 16)
ok(libc.mprotect(m, 2 * PAGE, RX) == 0, "mprotect(PROT_READ|PROT_EXEC) of written file pages")
ok(ctypes.string_at(m, 8) == RET42 and ctypes.string_at(m + PAGE, 8) == INC, "the written content is still there")
if arm:
    f0 = ctypes.CFUNCTYPE(ctypes.c_int)(m)
    f1 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(m + PAGE)
    ok(f0() == 42, "the code runs")
    ok(f1(9) == 10, "the second page runs")
else:
    print("skip the code runs (not arm64)")
ok(ctypes.string_at(m + 2 * PAGE, 4) == b"\x5a" * 4, "the page beyond the range is untouched and still writable")
ctypes.memset(m + 2 * PAGE, 0x5B, 1)
ok(open(path, "rb").read() == b"\0" * (3 * PAGE), "nothing was written through to the file")

# a read-write-execute request on a fresh written mapping, and back to read-only
m2 = libc.mmap(None, PAGE, RW, mmap.MAP_PRIVATE, fd, 0)
ctypes.memmove(m2, RET42, 8)
ok(libc.mprotect(m2, PAGE, RWX) == 0, "mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)")
ctypes.memmove(m2 + 8, b"abcd", 4)
ok(ctypes.string_at(m2 + 8, 4) == b"abcd", "still writable after it")
ok(libc.mprotect(m2, PAGE, 1) == 0, "mprotect(PROT_READ) afterwards")

# a mapping that was never written
m3 = libc.mmap(None, PAGE, 1, mmap.MAP_PRIVATE, fd, 0)
ok(libc.mprotect(m3, PAGE, RX) == 0, "mprotect(PROT_READ|PROT_EXEC) of an untouched file mapping")

# anonymous memory (a JIT) keeps working
a = libc.mmap(None, PAGE, RW, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
ctypes.memmove(a, RET42, 8)
ok(libc.mprotect(a, PAGE, RX) == 0, "mprotect(PROT_READ|PROT_EXEC) of anonymous memory")
if arm:
    ok(ctypes.CFUNCTYPE(ctypes.c_int)(a)() == 42, "anonymous code runs")

# errors
ok(libc.mprotect(m, 2 * PAGE, 1) == 0 and libc.mprotect(m, PAGE, RW) == 0, "executable pages can be made writable again")
libc.munmap(m3, PAGE)
ctypes.set_errno(0)
r = libc.mprotect(m3, PAGE, RX)
ok(r == -1 and ctypes.get_errno() == errno.ENOMEM, "mprotect(PROT_EXEC) of an unmapped range: ENOMEM")
ctypes.set_errno(0)
r = libc.mprotect(m + 1, PAGE, RX)
ok(r == -1 and ctypes.get_errno() == errno.EINVAL, "an unaligned address: EINVAL")

def run(argv, env=None):
    import subprocess
    p = subprocess.run(argv, env=env, capture_output=True, text=True)
    return p.stdout.strip().split("\n")[-1] if p.returncode == 0 else "exit %d" % p.returncode


if arm:
    me = os.path.abspath(__file__)
    plain = run([sys.executable, me, "bti-child"])
    ok(plain == "bti 0 1 1", "an ordinary program keeps PROT_BTI in mprotect and mmap (%s)" % plain)
    env = dict(os.environ, BURROW_NO_BTI="1")
    forced = run([sys.executable, me, "bti-child"], env)
    ok(forced == "bti 0 0 0", "BURROW_NO_BTI=1 drops it (%s)" % forced)
    os.makedirs(d + "/opt/wine/bin")
    for name in ("python3", "wine64"):
        os.symlink(sys.executable, d + "/opt/wine/bin/" + name)
    below = run([d + "/opt/wine/bin/python3", me, "bti-child"])
    ok(below == "bti 0 0 0", "a program below a wine/ directory has it dropped (%s)" % below)
    named = run([d + "/opt/wine/bin/wine64", me, "bti-child"])
    ok(named == "bti 0 0 0", "wine64 has it dropped (%s)" % named)
    os.makedirs(d + "/bin2")
    os.symlink(sys.executable, d + "/bin2/wine64")
    named = run([d + "/bin2/wine64", me, "bti-child"])
    ok(named == "bti 0 0 0", "wine64 outside a wine/ directory has it dropped (%s)" % named)
    other = run([d + "/bin2/wine64", me, "wine-then-other"])
    ok(other == "bti 0 1 1", "what Wine starts keeps PROT_BTI (%s)" % other)
    for n in ("python3", "wine64"):
        os.unlink(d + "/opt/wine/bin/" + n)
    os.rmdir(d + "/opt/wine/bin"); os.rmdir(d + "/opt/wine"); os.rmdir(d + "/opt")
    os.unlink(d + "/bin2/wine64"); os.rmdir(d + "/bin2")

os.close(fd)
os.unlink(path)
os.rmdir(d)
sys.exit(1 if fails else 0)
