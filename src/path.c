/*
 * Guest paths to host paths and back.
 *
 * A guest path is resolved as the kernel would resolve it if the rootfs were
 * "/": one component at a time, symlink contents read as guest paths, ".."
 * stopping at the root. A binding maps a guest directory (or file) to a host
 * one; once the path enters a binding with no other binding below it, the
 * kernel resolves the rest on the host side (/proc's magic links need that).
 * Most paths have no symlink at all: one openat2(RESOLVE_NO_SYMLINKS) proves
 * it, and the walk is skipped.
 */

#include "burrow.h"

/* The binding holding the resolved guest path @p (@n bytes), if any. */
static const struct bind* binding_of(const char* p, long n) {
    const struct bind* best = 0;
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        long g = b->guest_length;
        if (g <= n && memcmp(p, b->guest, g) == 0 && (p[g] == 0 || p[g] == '/') &&
            (best == 0 || g > best->guest_length))
            best = b;
    }
    return best;
}

/* Whether a binding lies strictly below the guest directory @p (@n bytes). */
static int binds_below(const char* p, long n) {
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        if (b->guest_length > n && memcmp(b->guest, p, n) == 0 && b->guest[n] == '/') return 1;
    }
    return 0;
}

/* Joins @a (@an bytes) and the string @b into @to. */
static long join(char* to, const char* a, long an, const char* b) {
    long bn = length_of(b);
    if (an + bn >= PATH_MAX) return -ENAMETOOLONG;
    memmove(to, a, an);
    memmove(to + an, b, bn + 1);
    return an + bn;
}

/* The host path of the resolved guest path @p (@n bytes), as the kernel would
 * find it without symlinks. */
static long host_of(const char* p, long n, char* host) {
    const struct bind* b = binding_of(p, n);
    if (b != 0) return join(host, b->host, b->host_length, p + b->guest_length);
    return join(host, cfg.root, cfg.root_length, n == 1 ? "" : p);
}

/* Whether the host path @s starts with the directory @prefix (@n bytes). */
static int under(const char* s, const char* prefix, long n) {
    return n > 0 && memcmp(s, prefix, n) == 0 && (s[n] == 0 || s[n] == '/');
}

/* The guest path of @host: its directory there in @guest, the rest of it in
 * @rest, null when the guest cannot see it. */
/* @p (@n bytes) under the app data directory's other name (see set_root_alias()) in @out;
 * the length, or -1 when @p is under neither name or does not fit. */
static long other_name(const char* p, long n, char* out, long size) {
    static const char* const pairs[][2] = {{"/data/user/0/", "/data/data/"}, {"/data/data/", "/data/user/0/"}};
    for (unsigned i = 0; i < 2; i++) {
        long from = length_of(pairs[i][0]), to = length_of(pairs[i][1]);
        if (n < from || memcmp(p, pairs[i][0], from) != 0) continue;
        if (to + n - from >= size) return -1;
        memcpy(out, pairs[i][1], to);
        memcpy(out + to, p + from, n - from);
        out[to + n - from] = 0;
        return to + n - from;
    }
    return -1;
}

static const char* guest_part(const char* host, const char** guest) {
    const char* rest = 0;
    long best = 0;
    *guest = "";
    if (under(host, cfg.root, cfg.root_length)) best = cfg.root_length, rest = host + best;
    if (cfg.root_alias_length > best && under(host, cfg.root_alias, cfg.root_alias_length))
        best = cfg.root_alias_length, rest = host + best;
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        long n = b->host_length;
        if (n > best && under(host, b->host, n)) {
            best = n, rest = host + n, *guest = b->guest;
        } else {
            /* The binding's directory named by the data directory's other path: Android shows
             * the app's data both as /data/user/0/<package> and /data/data/<package>, and the
             * kernel may give either (getcwd() inside the session gave the other one for a
             * binding beside the rootfs, so relative paths there resolved outside it). */
            char alias[PATH_MAX];
            long a = other_name(b->host, n, alias, sizeof(alias));
            if (a > best && under(host, alias, a)) best = a, rest = host + a, *guest = b->guest;
        }
    }
    return rest;
}

static int under_read_only(const char* host) {
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        if (b->readonly && under(host, b->host, b->host_length)) return 1;
    }
    return 0;
}

/* Whether @host is in a read-only binding. A /proc path through a descriptor, the working
 * directory or the root (/proc/self/fd/N, .../cwd, .../root, with a rest or not) is judged by
 * the file it leads to. */
int read_only_host(const char* host) {
    if (under_read_only(host)) return 1;
    if (!starts_with(host, "/proc/")) return 0;
    const char* p = host + 6;
    while (*p && *p != '/') p++; /* the pid or "self" */
    if (*p != '/') return 0;
    p++;
    const char* end = p;
    if (starts_with(p, "fd/")) {
        end = p + 3;
        while (*end && *end != '/') end++;
    } else if (starts_with(p, "cwd") && (p[3] == 0 || p[3] == '/')) {
        end = p + 3;
    } else if (starts_with(p, "root") && (p[4] == 0 || p[4] == '/')) {
        end = p + 4;
    } else {
        return 0;
    }
    long prefix = end - host, rest = length_of(end);
    if (prefix >= PATH_MAX) return 0;
    char link[PATH_MAX], target[PATH_MAX];
    memcpy(link, host, prefix);
    link[prefix] = 0;
    long n = sys(NR_readlinkat, AT_FDCWD, link, target, sizeof(target) - 1);
    if (n <= 0 || target[0] != '/' || n + rest >= PATH_MAX) return 0;
    memcpy(target + n, end, rest + 1);
    return under_read_only(target);
}

/* Whether descriptor @fd is a file in a read-only binding (the host path of its file). */
int read_only_fd(long fd) {
    char host[PATH_MAX];
    return fd_path(fd, host, PATH_MAX) > 0 && host[0] == '/' && under_read_only(host);
}

long ro_guard(const char* host) { return read_only_host(host) ? -EROFS : 0; }

int guest_sees(const char* host) {
    const char* guest;
    return guest_part(host, &guest) != 0;
}

long host_to_guest(const char* host, char* out, long size) {
    const char* guest;
    const char* rest = guest_part(host, &guest);
    if (rest == 0) return copy(out, size, host);
    long g = length_of(guest), r = length_of(rest);
    if (g == 0 && r == 0) return copy(out, size, "/");
    if (g + r >= size) return -ENAMETOOLONG;
    memmove(out, guest, g); /* guest is never out */
    memmove(out + g, rest, r + 1);
    return g + r;
}

/* Symlink content naming a host path in the rootfs (link2symlink's links)
 * becomes the guest path, in place. */
static long unhost(char* t, long n) {
    const char* roots[] = {cfg.root, cfg.root_alias};
    long lengths[] = {cfg.root_length, cfg.root_alias_length};
    for (int i = 0; i < 2; i++) {
        long l = lengths[i];
        if (l > 0 && n >= l && memcmp(t, roots[i], l) == 0 && (n == l || t[l] == '/')) {
            if (n == l) {
                t[0] = '/';
                t[1] = 0;
                return 1;
            }
            memmove(t, t + l, n - l + 1);
            return n - l;
        }
    }
    return n;
}

/* Drops the empty and "." components of the absolute path @p, in place:
 * they mean the same whatever the symlinks. A "." at the end leaves a slash,
 * which keeps its meaning (a directory). */
static int only_slashes(const char* s) {
    while (*s == '/') s++;
    return *s == 0;
}

static void tidy(char* p) {
    long to = 1;
    for (long at = 1; p[at];) {
        if (p[at] == '/') {
            at++;
            continue;
        }
        int dot = p[at] == '.' && (p[at + 1] == '/' || p[at + 1] == 0);
        if (!dot) {
            if (to > 1) p[to++] = '/';
            while (p[at] && p[at] != '/') p[to++] = p[at++];
        } else {
            at++;
        }
        if (only_slashes(p + at) && (p[at] == '/' || dot) && to > 1) p[to++] = '/';
        if (only_slashes(p + at)) break;
    }
    p[to] = 0;
}

/* guest_absolute(); with @outside, a path relative to a directory the guest
 * cannot see (opened before a chroot(): Chromium's sandbox keeps /proc so)
 * becomes its host path in @out, which the kernel resolves as from that
 * directory, and *@outside is 1. */
static long absolute(long dirfd, const char* path, char* out, int* outside) {
    if (outside) *outside = 0;
    if (path[0] == '/') {
        long r = copy(out, PATH_MAX, path);
        if (r >= 0) tidy(out);
        return r < 0 ? r : 0;
    }
    char host[PATH_MAX];
    long r;
    if (dirfd == AT_FDCWD) {
        r = sys(NR_getcwd, host, PATH_MAX, 0, 0);
        if (r < 0) return r;
    } else {
        if ((int) dirfd < 0) return -EBADF;
        r = fd_path((int) dirfd, host, PATH_MAX);
        if (r < 0) return -EBADF;
        if (host[0] != '/') return -ENOTDIR; /* a pipe, a socket... */
    }
    const char* guest;
    if (outside && dirfd != AT_FDCWD && guest_part(host, &guest) == 0) {
        long n = length_of(host);
        if (n > 1) host[n++] = '/';
        *outside = 1;
        return join(out, host, n, path) < 0 ? -ENAMETOOLONG : 0;
    }
    long n = host_to_guest(host, out, PATH_MAX);
    if (n < 0) return n;
    if (n > 1) out[n++] = '/';
    r = join(out, out, n, path);
    if (r >= 0) tidy(out);
    return r < 0 ? r : 0;
}

long guest_absolute(long dirfd, const char* path, char* out) { return absolute(dirfd, path, out, 0); }

/* Whether the absolute guest path @p has no empty, "." or ".." component (a
 * trailing slash apart): the kernel resolves it as we would, symlinks apart. */
static int plain(const char* p) {
    if (p[0] != '/') return 0;
    for (long i = 1; p[i];) {
        long start = i;
        while (p[i] != 0 && p[i] != '/') i++;
        long n = i - start;
        if (n == 0 || (n == 1 && p[start] == '.') || (n == 2 && p[start] == '.' && p[start + 1] == '.')) return 0;
        if (p[i] == '/') i++;
    }
    return 1;
}

/* Android 14 and 15 (some devices at least) trap openat2 in apps: the SIGSYS
 * handler makes it ENOSYS, and every path then takes the walk. */
static int no_openat2;

/* openat2() of @host, -ELOOP (walk it) where the kernel or Android lacks it. */
static long open_how_host(const char* host, struct open_how* how) {
    if (no_openat2) return -ELOOP;
    long r = sys(NR_openat2, AT_FDCWD, host, how, sizeof(*how));
    if (r != -ENOSYS) return r;
    no_openat2 = 1;
    return -ELOOP;
}

/* Whether the host path @host exists without any symlink (the last component
 * is not followed unless @follow). */
static long no_symlinks(const char* host, int follow, long extra) {
    struct open_how how = {O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW) | extra, 0, RESOLVE_NO_SYMLINKS};
    long fd = open_how_host(host, &how);
    if (fd >= 0) sys(NR_close, fd, 0, 0, 0);
    return fd < 0 ? fd : 0;
}

/* to_host() of the absolute guest path @guest when the kernel resolves it
 * as we would: a plain path, no binding left to the kernel, no symlink.
 * -ELOOP if not. */
static long probe(const char* guest, int follow, char* host, char* resolved) {
    long n = length_of(guest);
    const struct bind* b = plain(guest) ? binding_of(guest, n) : 0;
    if (!plain(guest) || (b != 0 && !b->walked)) return -ELOOP;
    long h = host_of(guest, n, host);
    if (h < 0) return h;
    long r = no_symlinks(host, follow, 0);
    if (r == -ENOENT) {
        /* Missing: fine if its directory has no symlink (a file to create). */
        long slash = h - 1; /* past a trailing slash */
        while (host[slash] != '/' || slash == h - 1) slash--;
        if (slash <= cfg.root_length) {
            r = 0;
        } else {
            char kept = host[slash];
            host[slash] = 0;
            r = no_symlinks(host, 1, O_DIRECTORY);
            host[slash] = kept;
        }
    }
    /* ENOENT, ENOTDIR: met before any symlink, so the walk would too. */
    if (r == 0) memcpy(resolved, guest, n + 1);
    return r == 0 || r == -ENOENT || r == -ENOTDIR || r == -EACCES ? r : -ELOOP;
}

/* to_host() of the plain guest path @guest outside the bindings, its symlinks
 * followed by the kernel as from the guest's root (RESOLVE_IN_ROOT): soname
 * links, /lib -> usr/lib, icon themes. -ELOOP for the walk: a missing file
 * (maybe one to create, or behind a binding), a result in a binding, a link
 * written as a host path. shortcut: a link inside the rootfs directory that a
 * binding hides (an image's own /dev/stdin) is followed; the walk would take
 * the binding's. */
static long in_root(const char* guest, int follow, char* host, char* resolved) {
    long n = length_of(guest);
    if (no_openat2 || n < 2 || guest[n - 1] == '/' || binding_of(guest, n) != 0) return -ELOOP;
    long root = sys(NR_openat, AT_FDCWD, cfg.root, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (root < 0) return -ELOOP;
    struct open_how how = {O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW), 0, RESOLVE_IN_ROOT};
    long fd = sys(NR_openat2, root, guest, &how, sizeof(how));
    sys(NR_close, root, 0, 0, 0);
    if (fd < 0) return -ELOOP;
    long h = fd_path(fd, host, PATH_MAX);
    sys(NR_close, fd, 0, 0, 0);
    const char* g = host + cfg.root_length;
    if (h <= cfg.root_length || memcmp(host, cfg.root, cfg.root_length) != 0 || *g != '/' ||
        binding_of(g, h - cfg.root_length) != 0)
        return -ELOOP;
    memcpy(resolved, g, h - cfg.root_length + 1);
    return 0;
}

/* Whether @rest has a ".." component: it may leave a binding (/sdcard/..)
 * or reach another (/dev/pts/../shm), which the host would not know. */
static int has_parent(const char* rest) {
    for (long i = 0; rest[i]; i++)
        if (rest[i] == '.' && rest[i + 1] == '.' && (i == 0 || rest[i - 1] == '/') && (rest[i + 2] == 0 || rest[i + 2] == '/'))
            return 1;
    return 0;
}

/* -- Directory cache (Kestrel) ------------------------------------------------------------
 * The walk checks every component with lstat(). Each process remembers the resolved guest
 * directories it has already seen to be real directories (no symlink, no binding), and skips
 * their lstat() while a counter shared by all guest processes is unchanged. Anything that can
 * turn a directory into something else bumps the counter: renaming a directory or symlink,
 * removing a directory, mount, umount, chroot. Changes made from outside the guest (another app,
 * Android's Files) are not seen; they are rare for directories. */
#define DIRCACHE_SLOTS 4096
struct dirslot { uint64_t key, meta, check; }; /* meta: generation << 16 | length */
static struct dirslot dircache[DIRCACHE_SLOTS];
static uint64_t* volatile pathgen; /* shared counter; 0 until mapped, (uint64_t*) 1 if unavailable */

/* The counter lives in a file given with -g (the app's private state directory, outside the
 * rootfs, so no guest program can truncate or remove it). Without -g there is no cache. */
static uint64_t* map_counter(void) {
    if (cfg.pathgen[0] == 0) return 0;
    long fd = sys(NR_openat, AT_FDCWD, (long) cfg.pathgen, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    struct kstat st;
    if (sys(NR_fstat, fd, &st, 0, 0) < 0 || (st.size < 4096 && sys(46 /* NR_ftruncate */, fd, 4096, 0, 0) < 0)) {
        sys(NR_close, fd, 0, 0, 0);
        return 0;
    }
    long m = sys6(NR_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    sys(NR_close, fd, 0, 0, 0);
    return m < 0 && m > -4096 ? 0 : (uint64_t*) m;
}

static uint64_t* gen_counter(void) {
    uint64_t* g = pathgen;
    if (g == (uint64_t*) 1) return 0;
    if (g) return g;
    g = map_counter();
    pathgen = g ? g : (uint64_t*) 1; /* no cache in this process if the counter cannot be mapped */
    return g;
}

/* Bumps reach every process: one that cannot map the counter retries here (bumps are rare). */
void pathcache_invalidate(void) {
    uint64_t* g = gen_counter();
    if (!g && cfg.pathgen[0]) {
        g = map_counter();
        if (g) pathgen = g;
        else say("burrow: cannot update the path cache counter ", cfg.pathgen, 0);
    }
    if (g) __atomic_add_fetch(g, 1, __ATOMIC_RELEASE);
}

void pathcache_reset_local(void) { memset(dircache, 0, sizeof(dircache)); }

static uint64_t gen_now(void) {
    uint64_t* g = gen_counter();
    return g ? __atomic_load_n(g, __ATOMIC_ACQUIRE) : 0;
}

static uint64_t fnv(const char* s, long n) {
    uint64_t h = 1469598103934665603ull;
    for (long i = 0; i < n; i++) h = (h ^ (unsigned char) s[i]) * 1099511628211ull;
    return h;
}

static int dircache_has(const char* p, long n) {
    uint64_t* g = gen_counter();
    if (!g) return 0;
    uint64_t key = fnv(p, n), gen = __atomic_load_n(g, __ATOMIC_ACQUIRE);
    struct dirslot* s = &dircache[key % DIRCACHE_SLOTS];
    uint64_t k = __atomic_load_n(&s->key, __ATOMIC_RELAXED), m = __atomic_load_n(&s->meta, __ATOMIC_RELAXED),
             c = __atomic_load_n(&s->check, __ATOMIC_RELAXED);
    return k == key && c == (k ^ m ^ 0x9e3779b97f4a7c15ull) && m == (gen << 16 | (uint64_t) (n & 0xffff));
}

/* @gen: the counter read BEFORE the lstat() that saw the directory, so a change racing with
 * that lstat() (bumped after it) makes this entry stale at once. */
static void dircache_put(const char* p, long n, uint64_t gen) {
    if (!gen_counter()) return;
    uint64_t key = fnv(p, n), meta = gen << 16 | (uint64_t) (n & 0xffff);
    struct dirslot* s = &dircache[key % DIRCACHE_SLOTS];
    __atomic_store_n(&s->check, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&s->key, key, __ATOMIC_RELAXED);
    __atomic_store_n(&s->meta, meta, __ATOMIC_RELAXED);
    __atomic_store_n(&s->check, key ^ meta ^ 0x9e3779b97f4a7c15ull, __ATOMIC_RELEASE);
}

/* The slow path: resolves @path one component at a time. */
static long walk(const char* path, int follow, char* host, char* out) {
    char rest[PATH_MAX], target[PATH_MAX];
    long rest_length = copy(rest, PATH_MAX, path);
    if (rest_length < 0) return rest_length;
    int slash = rest_length > 1 && rest[rest_length - 1] == '/'; /* the last component must be a directory */
    if (slash) follow = 1;
    long n = 1, at = 0, links = 0;
    out[0] = '/';
    out[1] = 0;
    for (;;) {
        while (rest[at] == '/') at++;
        if (rest[at] == 0) break;
        long start = at;
        while (rest[at] != 0 && rest[at] != '/') at++;
        long length = at - start;
        const char* c = rest + start;
        if (length == 1 && c[0] == '.') continue;
        if (length == 2 && c[0] == '.' && c[1] == '.') {
            while (n > 1 && out[n - 1] != '/') n--;
            if (n > 1) n--;
            out[n] = 0;
            continue;
        }
        if (n + 1 + length >= PATH_MAX) return -ENAMETOOLONG;
        long previous = n;
        if (n > 1) out[n++] = '/';
        memcpy(out + n, c, length);
        n += length;
        out[n] = 0;
        long after = at;
        while (rest[after] == '/') after++;
        int last = rest[after] == 0;

        const struct bind* b = binding_of(out, n);
        if (b != 0 && !b->walked && !binds_below(out, n) && !has_parent(rest + at)) {
            /* The host resolves the rest: /proc's magic links, /dev's... */
            long h = join(host, b->host, b->host_length, out + b->guest_length);
            if (h < 0) return h;
            h = join(host, host, h, rest + at);
            if (h < 0) return h;
            return join(out, out, n, rest + at) < 0 ? -ENAMETOOLONG : 0;
        }
        if (last && !follow) break;
        if (!last && b == 0 && dircache_has(out, n)) continue; /* a directory seen before */

        struct kstat st;
        long r = host_of(out, n, host);
        if (r < 0) return r;
        uint64_t gen = gen_now();
        r = sys(NR_newfstatat, AT_FDCWD, host, &st, AT_SYMLINK_NOFOLLOW);
        if (r == -ENOENT && last) break; /* to be created */
        if (r < 0) return r;
        if ((st.mode & S_IFMT) == S_IFLNK) {
            if (++links > 40) return -ELOOP;
            long t = sys(NR_readlinkat, AT_FDCWD, host, target, PATH_MAX - 1);
            if (t < 0) return t;
            target[t] = 0;
            long u = unhost(target, t);
            if (u == t && l2s_target(target)) {
                /* A faked hard link made under another root (a walked binding
                 * after chroot): its file is a host path, and no directory. */
                return join(host, target, t, rest + at) < 0 || join(out, out, n, rest + at) < 0 ? -ENAMETOOLONG : 0;
            }
            t = u;
            long tail = rest_length - at;
            if (t + tail >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(target + t, rest + at, tail + 1);
            rest_length = t + tail;
            memcpy(rest, target, rest_length + 1);
            at = 0;
            n = target[0] == '/' ? 1 : previous;
            out[n] = 0;
            /* What is left most often has no symlink (/lib -> usr/lib): try it whole. */
            long w = rest[0] == '/' ? 0 : n;
            memcpy(target, out, w);
            if (w > 1) target[w++] = '/';
            if (w + rest_length < PATH_MAX) {
                memcpy(target + w, rest, rest_length + 1);
                tidy(target);
                long whole = probe(target, follow, host, out);
                if (whole != -ELOOP) return whole;
            }
            continue;
        }
        if (!last && (st.mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
        if (!last && b == 0) dircache_put(out, n, gen);
        if (last) break;
    }
    long h = host_of(out, n, host);
    if (h < 0) return h;
    if (slash && n > 1) {
        if (h + 1 >= PATH_MAX) return -ENAMETOOLONG;
        host[h] = '/';
        host[h + 1] = 0;
    }
    return 0;
}

/* /proc/self/exe, while the root has /proc bound (not after a chroot() into a
 * directory without it: Chromium tells its sandbox's chroot() by this). */
static int is_self_exe(const char* p) {
    if (!same(p, "/proc/self/exe") && !same(p, "/proc/thread-self/exe")) return 0;
    for (int i = 0; i < cfg.bind_count; i++)
        if (same(cfg.binds[i].guest, "/proc")) return 1;
    return 0;
}

/* The rest of @p after /proc/<pid>/root (self and thread-self too), "" if
 * none; 0 if @p is no such path. */
static const char* proc_root_rest(const char* p) {
    if (!starts_with(p, "/proc/")) return 0;
    const char* q = p + 6;
    if (starts_with(q, "self/")) {
        q += 5;
    } else if (starts_with(q, "thread-self/")) {
        q += 12;
    } else {
        const char* digits = q;
        while (*q >= '0' && *q <= '9') q++;
        if (q == digits || *q++ != '/') return 0;
    }
    if (!starts_with(q, "root") || (q[4] != 0 && q[4] != '/')) return 0;
    return q + 4;
}

/* Fields 4 (parent) and 22 (start time) of /proc/<@pid>/stat, "self" for 0. */
static int pid_stat(unsigned long pid, unsigned long* parent, unsigned long* start) {
    char path[40] = "/proc/self";
    memcpy(pid ? format_unsigned(path + 6, pid) : path + 10, "/stat", 6);
    static const int fields[] = {4, 22}; /* the parent, the start time */
    unsigned long values[2];
    if (!stat_fields(path, 2, fields, values)) return 0;
    *parent = values[0], *start = values[1];
    return 1;
}

/* The record of a chroot()ed process, <first root>/tmp/.burrow-roots/<pid>-<start
 * time>, a symlink to its root (host path): the start time tells a reused pid. */
static long root_record(char* out, unsigned long pid, unsigned long start) {
    long n = length_of(cfg.ipc) - 3; /* "/tmp/.burrow-ipc" -> "/tmp/.burrow-" */
    if (n < 0 || n + 6 + 48 > PATH_MAX) return -ENAMETOOLONG;
    memcpy(out, cfg.ipc, n);
    memcpy(out + n, "roots", 6);
    if (pid == 0) return 0;
    char* e = out + n + 5;
    *e++ = '/';
    e = format_unsigned(e, pid);
    *e++ = '-';
    format_unsigned(e, start);
    return 0;
}

void record_root(void) {
    unsigned long parent, start;
    char path[PATH_MAX];
    if (!pid_stat(0, &parent, &start) || root_record(path, 0, 0) < 0) return;
    sys(NR_mkdirat, AT_FDCWD, path, 0700, 0);
    root_record(path, (unsigned long) sys(NR_getpid, 0, 0, 0, 0), start);
    sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
    sys(NR_symlinkat, cfg.root, AT_FDCWD, path, 0);
}

/* The record of the root a child of clone(CLONE_FS) chroot()ed into, for its
 * parent: <first root>/tmp/.burrow-roots/fs-<pid>, a symlink to it. */
static long shared_root_record(char* out, unsigned long pid) {
    long r = root_record(out, 0, 0);
    if (r < 0) return r;
    char* e = out + length_of(out);
    memcpy(e, "/fs-", 4);
    format_unsigned(e + 4, pid);
    return 0;
}

void record_shared_root(void) {
    char path[PATH_MAX];
    if (shared_root_record(path, 0) < 0) return;
    path[length_of(path) - 5] = 0; /* the directory, without "/fs-0" */
    sys(NR_mkdirat, AT_FDCWD, path, 0700, 0);
    shared_root_record(path, (unsigned long) sys(NR_getpid, 0, 0, 0, 0));
    sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
    sys(NR_symlinkat, cfg.root, AT_FDCWD, path, 0);
}

long take_shared_root(long pid, char* root, long size) {
    char path[PATH_MAX];
    if (shared_root_record(path, (unsigned long) pid) < 0) return 0;
    long n = sys(NR_readlinkat, AT_FDCWD, path, root, size - 1);
    if (n <= 0 || n >= size - 1) return 0;
    root[n] = 0;
    sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
    return n;
}

/* The guest path, in this process's root, of the root of process @pid (or of
 * its nearest ancestor that called chroot()) into @out; 0 if none is known or
 * this root does not hold it. shortcut: bindings of that root are not seen
 * below it; enough for the files chroot()'s caller put there (.flatpak-info). */
static int other_root(unsigned long pid, char* out) {
    char path[PATH_MAX], root[PATH_MAX];
    for (int depth = 0; depth < 32 && pid > 1; depth++) {
        unsigned long parent = 0, start = 0;
        if (!pid_stat(pid, &parent, &start) || root_record(path, pid, start) < 0) return 0;
        long n = sys(NR_readlinkat, AT_FDCWD, path, root, sizeof(root) - 1);
        if (n > 0) {
            root[n] = 0;
            if (n <= cfg.root_length || memcmp(root, cfg.root, cfg.root_length) != 0 || root[cfg.root_length] != '/')
                return 0;
            return copy(out, PATH_MAX, root + cfg.root_length) >= 0;
        }
        pid = parent;
    }
    return 0;
}

long to_host(const char* guest, int follow, char* host, char* resolved) {
    char scratch[PATH_MAX];
    if (resolved == 0) resolved = scratch;
    /* A guest process's root is the rootfs, not Android's "/", or the directory
     * it chroot()ed into (xdg-desktop-portal and flatpak-portal open it to tell
     * sandboxed apps by their /.flatpak-info). The link itself stays one:
     * readlink() gives "/". shortcut: Android's own processes get the rootfs too. */
    const char* rest = proc_root_rest(guest);
    if (rest != 0 && (rest[0] != 0 || follow)) {
        char from_root[PATH_MAX];
        const char* q = guest + 6;
        long n = 0;
        if (*q >= '0' && *q <= '9' && other_root(parse_unsigned(&q), from_root)) n = length_of(from_root);
        if (n + length_of(rest) + 2 > PATH_MAX) return -ENAMETOOLONG;
        memcpy(from_root + n, rest[0] ? rest : "/", length_of(rest[0] ? rest : "/") + 1);
        return to_host(from_root, follow, host, resolved);
    }
    if (is_self_exe(guest) && follow) {
        long r = copy(host, PATH_MAX, cfg.host_exe);
        if (r >= 0) r = copy(resolved, PATH_MAX, cfg.exe);
        return r < 0 ? r : 0;
    }
    uint64_t start = stats_start();
    long r = probe(guest, follow, host, resolved);
    if (r != -ELOOP) {
        stats_step(STATS_PROBE, start);
        return r;
    }
    r = in_root(guest, follow, host, resolved);
    if (r != -ELOOP) {
        stats_step(STATS_PROBE, start);
        return r;
    }
    r = walk(guest, follow, host, resolved);
    stats_step(STATS_WALK, start);
    return r;
}

/* Whether the kernel resolves the absolute guest path @guest as we would:
 * no binding, no "." or "..", and symlinks refused (RESOLVE_NO_SYMLINKS). */
static int direct(const char* guest) {
    return plain(guest) && !starts_with(guest, "/proc/") && binding_of(guest, length_of(guest)) == 0;
}

long host_fd(long dirfd, const char* path, int follow, char* host, long* fd) {
    char guest[PATH_MAX], resolved[PATH_MAX];
    *fd = -1;
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    int outside;
    long r = absolute(dirfd, path, guest, &outside);
    if (r < 0) return r;
    if (outside) return copy(host, PATH_MAX, guest) < 0 ? -ENAMETOOLONG : 0;
    if (!direct(guest)) return to_host(guest, follow, host, 0);
    uint64_t start = stats_start();
    r = host_of(guest, length_of(guest), host);
    if (r < 0) return r;
    struct open_how how = {O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW), 0, RESOLVE_NO_SYMLINKS};
    r = open_how_host(host, &how);
    if (r != -ELOOP) {
        /* ENOENT, ENOTDIR, EACCES: met before any symlink, so the walk would too. */
        if (r >= 0) *fd = r;
        stats_step(STATS_PROBE, start);
        return r < 0 ? r : 0;
    }
    r = walk(guest, follow, host, resolved);
    stats_step(STATS_WALK, start);
    return r;
}

long open_direct(long dirfd, const char* path, long flags, long mode) {
    char guest[PATH_MAX], host[PATH_MAX];
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    int outside;
    long r = absolute(dirfd, path, guest, &outside);
    if (r < 0) return r;
    if (outside || !direct(guest)) return -ELOOP; /* host_path() then */
    uint64_t start = stats_start();
    r = host_of(guest, length_of(guest), host);
    if (r < 0) return r;
    struct open_how how = {(uint64_t) flags, flags & O_CREAT ? (uint64_t) mode & 07777 : 0, RESOLVE_NO_SYMLINKS};
    r = open_how_host(host, &how);
    stats_step(STATS_OPEN, start);
    return r;
}

long host_path(long dirfd, const char* path, int follow, char* host) {
    char guest[PATH_MAX];
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    int outside;
    long r = absolute(dirfd, path, guest, &outside);
    if (r < 0) return r;
    if (outside) return copy(host, PATH_MAX, guest) < 0 ? -ENAMETOOLONG : 0;
    return to_host(guest, follow, host, 0);
}
