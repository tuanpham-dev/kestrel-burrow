# The path cache's symlink entries: a process remembers the text of the symlinks it has read, and
# must never use it after the link changed. Every check warms the cache (many stats and opens through the link), changes
# the link the way a program does, and reads again:
# - unlink + symlink, symlink to a temporary name + rename over it (ln -sf, dpkg), a file or a folder renamed over a link,
#   a link replaced by a file or a folder (rm + mkdir), a link in the middle of a chain, a link inside a folder that is
#   renamed away and made again, RENAME_EXCHANGE, rmdir + mkdir below a link;
# - the change made by another process while this one's cache is warm (the counter is shared), and by a thread;
# - the long chains of an icon theme ("actions/actions" -> "."): thirty links in a row resolve, forty-one are ELOOP, and
#   the files below them are the real ones;
# - relative and absolute links, a link to a link, ".." after a link, a trailing slash, no-follow stat of the link itself.
import ctypes
import errno
import os
import shutil
import sys
import tempfile
import threading

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


def text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError as e:
        return errno.errorcode[e.errno]


def warm(path, n=40):
    for _ in range(n):
        try:
            os.stat(path)
            os.stat(path, follow_symlinks=False)
            open(path).close()
        except OSError:
            pass


d = os.path.realpath(tempfile.mkdtemp(prefix="burrow-linkcache."))
os.chdir(d)
for name in ("a", "b", "c"):
    os.makedirs("%s/%s/sub" % (d, name))
    for f in ("F", "sub/G"):
        with open("%s/%s/%s" % (d, name, f), "w") as out:
            out.write(name.upper() * 3)


def check(label, path, want):
    got = text(path)
    ok(got == want, "%s: %s reads %s (got %s)" % (label, path.replace(d, "."), want, got))


# unlink and symlink again
os.symlink("a", d + "/L")
warm(d + "/L/F"); check("warm", d + "/L/F", "AAA")
os.unlink(d + "/L"); os.symlink("b", d + "/L")
check("unlink + symlink", d + "/L/F", "BBB")
check("unlink + symlink", d + "/L/sub/G", "BBB")

# a new link renamed over the old one (ln -sf; dpkg)
warm(d + "/L/F")
os.symlink("c", d + "/L.tmp"); os.rename(d + "/L.tmp", d + "/L")
check("rename a link over a link", d + "/L/F", "CCC")
warm(d + "/L/F")
os.symlink("a", d + "/L.tmp"); os.rename(d + "/L.tmp", d + "/L")
check("rename a link over a link (again)", d + "/L/sub/G", "AAA")

# an absolute link, switched
os.symlink(d + "/a", d + "/ABS")
warm(d + "/ABS/F"); check("absolute", d + "/ABS/F", "AAA")
os.unlink(d + "/ABS"); os.symlink(d + "/b", d + "/ABS")
check("absolute, unlink + symlink", d + "/ABS/F", "BBB")

# a regular file renamed over a link: the name is a file now
warm(d + "/L/F")
with open(d + "/L.file", "w") as out:
    out.write("plain")
os.rename(d + "/L.file", d + "/L")
check("a file renamed over a link", d + "/L", "plain")
ok(error_of(lambda: os.stat(d + "/L/F")) == errno.ENOTDIR, "a file renamed over a link: L/F is ENOTDIR")
os.unlink(d + "/L")

# a folder renamed over a link is impossible (ENOTDIR); the link removed and a folder made: the folder's files
os.symlink("a", d + "/L")
warm(d + "/L/F")
os.unlink(d + "/L"); os.mkdir(d + "/L")
with open(d + "/L/F", "w") as out:
    out.write("DIR")
check("link replaced by a folder", d + "/L/F", "DIR")
shutil.rmtree(d + "/L")

# a link removed: ENOENT below it, then made again
os.symlink("a", d + "/L")
warm(d + "/L/F")
os.unlink(d + "/L")
ok(error_of(lambda: os.stat(d + "/L/F")) == errno.ENOENT, "unlink: L/F is ENOENT at once")
os.symlink("c", d + "/L")
check("unlink, ENOENT, symlink", d + "/L/F", "CCC")

# a chain A -> B -> C: change the middle one, then the last
os.symlink("b2", d + "/A"); os.symlink("c2", d + "/b2"); os.symlink("a", d + "/c2")
warm(d + "/A/F"); check("chain", d + "/A/F", "AAA")
os.unlink(d + "/c2"); os.symlink("b", d + "/c2")
check("chain, last link changed", d + "/A/F", "BBB")
os.unlink(d + "/b2"); os.symlink("c3", d + "/b2"); os.symlink("c", d + "/c3")
check("chain, middle link changed", d + "/A/F", "CCC")
os.unlink(d + "/A"); os.symlink("a", d + "/A")
check("chain, first link changed", d + "/A/F", "AAA")

# a link inside a folder that is renamed away, and the folder made again with another link
os.makedirs(d + "/p/q")
os.symlink("../../a", d + "/p/q/lk")
warm(d + "/p/q/lk/F"); check("below folders", d + "/p/q/lk/F", "AAA")
os.rename(d + "/p", d + "/p.old")
ok(error_of(lambda: os.stat(d + "/p/q/lk/F")) == errno.ENOENT, "the folder renamed away: ENOENT at once")
os.makedirs(d + "/p/q"); os.symlink("../../b", d + "/p/q/lk")
check("folder made again with another link", d + "/p/q/lk/F", "BBB")
warm(d + "/p.old/q/lk/F")  # the old folder's link: ../../a from p.old/q is not d/a (d/p.old/q/../../a = d/a, same)
os.rename(d + "/p", d + "/p.new"); os.rename(d + "/p.old", d + "/p")
check("two folders swapped by rename", d + "/p/q/lk/F", "AAA")

# RENAME_EXCHANGE of two links
libc = ctypes.CDLL(None, use_errno=True)
os.symlink("a", d + "/X"); os.symlink("b", d + "/Y")
warm(d + "/X/F"); warm(d + "/Y/F")
AT_FDCWD = -100
r = libc.renameat2(AT_FDCWD, (d + "/X").encode(), AT_FDCWD, (d + "/Y").encode(), 2)
if r == 0:
    check("RENAME_EXCHANGE", d + "/X/F", "BBB")
    check("RENAME_EXCHANGE", d + "/Y/F", "AAA")
else:
    print("skip RENAME_EXCHANGE (%s)" % os.strerror(ctypes.get_errno()))

# rmdir and mkdir below a link
os.symlink("sub2", d + "/S"); os.mkdir(d + "/sub2"); os.makedirs(d + "/sub2/in")
with open(d + "/sub2/in/F", "w") as out:
    out.write("one")
warm(d + "/S/in/F"); check("below a link", d + "/S/in/F", "one")
shutil.rmtree(d + "/sub2"); os.makedirs(d + "/sub2/in")
with open(d + "/sub2/in/F", "w") as out:
    out.write("two")
check("folder below the link made again", d + "/S/in/F", "two")

# ".." after a link, trailing slash, the link itself
os.symlink("a/sub", d + "/D")
warm(d + "/D/G")
ok(text(d + "/D/../F") == "AAA", "'..' after a link folder reads a/F")
ok(os.path.isdir(d + "/D/"), "trailing slash after a link to a folder")
ok(os.path.islink(d + "/D") and os.readlink(d + "/D") == "a/sub", "no-follow stat and readlink of the link")
ok(error_of(lambda: os.stat(d + "/F/")) == errno.ENOENT, "trailing slash on a plain missing name still ENOENT")
os.unlink(d + "/D"); os.symlink("b/sub", d + "/D")
ok(text(d + "/D/../F") == "BBB", "'..' after the link folder, link changed")

# another process changes the link while this one's cache is warm (the counter is shared)
os.symlink("a", d + "/M")
warm(d + "/M/F")
for target, want in (("b", "BBB"), ("c", "CCC"), ("a", "AAA")):
    pid = os.fork()
    if pid == 0:
        os.unlink(d + "/M"); os.symlink(target, d + "/M")
        os._exit(0)
    os.waitpid(pid, 0)
    check("changed by another process", d + "/M/F", want)
    warm(d + "/M/F", 5)
# a child with a warm cache, the parent changes the link
r, w = os.pipe(); r2, w2 = os.pipe()
pid = os.fork()
if pid == 0:
    warm(d + "/M/F")
    os.write(w, b"x"); os.read(r2, 1)
    os._exit(0 if text(d + "/M/F") == "BBB" else 1)
os.read(r, 1)
os.unlink(d + "/M"); os.symlink("b", d + "/M")
os.write(w2, b"y")
ok(os.waitpid(pid, 0)[1] == 0, "a child's warm cache follows a change made by the parent")

# another thread
os.symlink("a", d + "/T")
warm(d + "/T/F")
def flip():
    os.unlink(d + "/T"); os.symlink("c", d + "/T")
t = threading.Thread(target=flip); t.start(); t.join()
check("changed by a thread", d + "/T/F", "CCC")

# the icon theme's shape: a folder that links to itself
os.makedirs(d + "/theme/actions/64")
with open(d + "/theme/actions/64/f.svg", "w") as out:
    out.write("SVG")
os.symlink(".", d + "/theme/actions/actions")
os.symlink("f.svg", d + "/theme/actions/64/g.svg")
for depth in (1, 2, 10, 30):
    path = d + "/theme/actions" + "/actions" * depth + "/64/f.svg"
    ok(text(path) == "SVG", "%d folder links to '.' in a row" % depth)
    warm(path, 3)
    ok(text(path) == "SVG", "%d folder links to '.' in a row, warm" % depth)
path = d + "/theme/actions" + "/actions" * 41 + "/64/f.svg"
ok(error_of(lambda: os.stat(path)) == errno.ELOOP, "41 links in a row: ELOOP")
ok(error_of(lambda: os.stat(path)) == errno.ELOOP, "41 links in a row: ELOOP, warm")
path = d + "/theme/actions" + "/actions" * 20 + "/64/g.svg"
ok(text(path) == "SVG" and os.path.islink(path) and os.readlink(path) == "f.svg", "a file link below 20 folder links")
# switch the link of the middle: "actions" now leads to the other folder
os.makedirs(d + "/theme/other/64")
with open(d + "/theme/other/64/f.svg", "w") as out:
    out.write("OTHER")
warm(d + "/theme/actions/actions/64/f.svg")
os.unlink(d + "/theme/actions/actions"); os.symlink("../other", d + "/theme/actions/actions")
ok(text(d + "/theme/actions/actions/64/f.svg") == "OTHER", "the self link switched to another folder")
ok(error_of(lambda: os.stat(d + "/theme/actions/actions/actions/64/f.svg")) == errno.ENOENT,
   "... and nothing below it is the old chain (ENOENT: other/actions does not exist)")

shutil.rmtree(d, ignore_errors=True)
sys.exit(1 if fails else 0)
