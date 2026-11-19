/*
 * The seccomp filter and the SIGSYS handler that emulates the trapped
 * syscalls in the guest process.
 *
 * The handler runs on the trapping thread with the syscall's registers in the
 * signal frame: it makes the real syscalls through the gadget and writes the
 * result into x0. The kernel resets a blocked or ignored SIGSYS to the
 * default action (death) before delivering a trap, so the guest never gets to
 * block it: masks are filtered (also the ones signal frames bring back at
 * rt_sigreturn) and the guest's own SIGSYS disposition is only
 * recorded (its handler gets the traps of its own filters).
 */

#include "burrow.h"

extern char burrow_gadget[], burrow_probe[], burrow_sigreturn[];

/* -- The filter --------------------------------------------------------------------- */

static const uint16_t trapped[] = {
    NR_setxattr, NR_lsetxattr, NR_getxattr, NR_lgetxattr, NR_listxattr, NR_llistxattr, NR_removexattr,
    NR_lremovexattr, NR_getcwd, NR_inotify_add_watch, NR_mknodat, NR_mkdirat, NR_unlinkat, NR_symlinkat,
    NR_linkat, NR_renameat, NR_statfs, NR_fstatfs, NR_truncate, NR_faccessat, NR_chdir, NR_fchmodat, NR_fchownat, NR_fchown,
    NR_openat, NR_readlinkat, NR_getdents64, NR_newfstatat, NR_fstat, NR_utimensat, NR_rt_sigaction, NR_rt_sigprocmask,
    NR_rt_sigreturn,
    NR_setregid, NR_setgid, NR_setreuid, NR_setuid, NR_setresuid, NR_getresuid, NR_setresgid, NR_getresgid,
    NR_setfsuid, NR_setfsgid, NR_getgroups, NR_setgroups, NR_uname, NR_getuid, NR_geteuid, NR_getgid, NR_getegid, NR_bind, NR_connect,
    NR_execve, NR_renameat2, NR_execveat, NR_statx, NR_openat2, NR_faccessat2, NR_fchmodat2, NR_sendmsg,
    NR_sendto, NR_getsockname, NR_getpeername, NR_shmget, NR_shmctl, NR_shmat, NR_shmdt, NR_chroot,
    NR_semget, NR_semctl, NR_semtimedop, NR_semop, NR_msgget, NR_msgctl, NR_msgrcv, NR_msgsnd,
    NR_capget, NR_capset,
    NR_fchmod, NR_fsetxattr, NR_fremovexattr, /* descriptors of a read-only binding's files */
    NR_clone3, /* ENOSYS, as under Android: CLONE_CLEAR_SIGHAND would drop our handler */
    NR_mount, NR_umount2, NR_unshare,
    /* ENOSYS: the new mount API takes paths we would not translate (libglnx,
     * Flatpak's, opened the host's root with open_tree()), and falls back. */
    NR_open_tree, NR_move_mount, NR_fsopen, NR_fsconfig, NR_fsmount, NR_fspick, NR_mount_setattr,
};

struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter* filter;
};

#define LD_ABS 0x20 /* BPF_LD | BPF_W | BPF_ABS */
#define JEQ 0x15    /* BPF_JMP | BPF_JEQ | BPF_K */
#define JSET 0x45   /* BPF_JMP | BPF_JSET | BPF_K */
#define RET 0x06    /* BPF_RET | BPF_K */
#define RET_ALLOW 0x7fff0000u
#define RET_TRAP 0x00030000u
#define RET_ERRNO 0x00050000u
#define AUDIT_ARCH_AARCH64 0xc00000b7u
#define DRM_IOCTL_VERSION 0xc0406400u
#define TCGETS2 0x802c542au /* the termios2 ioctls glibc 2.42 uses for tcgetattr()/tcsetattr() */
#define TCSETS2 0x402c542bu
#define TCSETSW2 0x402c542cu
#define TCSETSF2 0x402c542du
#define PR_SET_SECCOMP 22
#define SECCOMP_SET_MODE_FILTER 1
#define N_TRAPPED (sizeof(trapped) / sizeof(*trapped))
#define TO_TRAP 0xff /* a jump to the trap, its distance set once the trap is placed */

/* The syscall number first, the caller only for the syscalls that may trap:
 * what a filter answers from the number alone the kernel remembers (since
 * 5.11), and it runs no filter at all for those syscalls, Android's neither. */
long install_filter(void) {
    uint64_t gadget = (uint64_t) burrow_gadget;
    struct sock_filter f[N_TRAPPED + 100];
    int i = 0;
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 4}; /* arch */
    f[i++] = (struct sock_filter){JEQ, 1, 0, AUDIT_ARCH_AARCH64};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 0}; /* nr */
    /* ioctl(DRM_IOCTL_VERSION) only: the render node is KGSL, see do_drm_version(). The termios2
     * requests too, see do_termios2(). */
    f[i++] = (struct sock_filter){JEQ, 0, 7, NR_ioctl};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 24}; /* args[1], low half */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, DRM_IOCTL_VERSION};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, TCGETS2};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, TCSETS2};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, TCSETSW2};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, TCSETSF2};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* lseek(fd, 0, SEEK_SET) only: made-up /proc files read again (proc_rewind()). */
    f[i++] = (struct sock_filter){JEQ, 0, 5, NR_lseek};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 24}; /* args[1], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 2, 0};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, 0 /* SEEK_SET */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* mprotect() asking for PROT_EXEC or PROT_BTI only, see do_mprotect(). */
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_mprotect};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JSET, TO_TRAP, 0, PROT_EXEC | PROT_BTI};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* mmap() asking for PROT_BTI only (glibc 2.40 and later maps libraries so), see NR_mmap in the handler. */
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_mmap};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JSET, TO_TRAP, 0, PROT_BTI};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* getsockopt(), only for SO_PEERCRED: the ids it reports are real. */
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_getsockopt};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, 17 /* SO_PEERCRED */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* socket(AF_NETLINK, *, NETLINK_AUDIT): SELinux says EACCES, which PAM
     * takes for a broken audit system (su and sudo fail); a kernel without
     * audit says EPROTONOSUPPORT. Burrow makes no such socket itself. */
    /* socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT) traps, see do_uevent_socket(). */
    f[i++] = (struct sock_filter){JEQ, 0, 7, NR_socket};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 3, 16 /* AF_NETLINK */};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, 2, 0, 9 /* NETLINK_AUDIT */};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, 15 /* NETLINK_KOBJECT_UEVENT */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | 93 /* EPROTONOSUPPORT */};
    /* clone(CLONE_NEWPID) is EINVAL, as from a kernel without PID namespaces
     * (Android gives no /proc/self/ns/pid): Chromium's sandbox helper then goes
     * on without one, where Android's EPERM stops it. A process sharing the
     * root but not the memory (CLONE_FS alone) traps, see do_clone(). */
    f[i++] = (struct sock_filter){JEQ, 0, 6, NR_clone};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JSET, 0, 1, 0x20000000 /* CLONE_NEWPID */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | EINVAL};
    f[i++] = (struct sock_filter){JSET, 1, 0, 0x100 /* CLONE_VM */};
    f[i++] = (struct sock_filter){JSET, TO_TRAP, 0, 0x200 /* CLONE_FS */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* prctl(PR_SET_KEEPCAPS) succeeds: Android locks the bit (ping keeps
     * capabilities across setuid()), and the guest's capabilities are fake. */
    f[i++] = (struct sock_filter){JEQ, 0, 5, NR_prctl};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 1, PR_SET_KEEPCAPS};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | 0};
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, PR_SET_SECCOMP}; /* the guest's own filter, see do_guest_filter() */
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_seccomp};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, SECCOMP_SET_MODE_FILTER};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* recvfrom() traps only with an address (the DNS proxy's answers): recv()
     * passes (Firefox's and curl's network, PipeWire). */
    f[i++] = (struct sock_filter){JEQ, 0, 7, NR_recvfrom};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 48}; /* args[4], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 2, 0};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 52}; /* high half */
    f[i++] = (struct sock_filter){JEQ, 2, 0, 0};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 0}; /* nr again: a jump to the trap */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, NR_recvfrom};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* ptrace(PTRACE_TRACEME) only, see do_traceme(). */
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_ptrace};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, 0 /* PTRACE_TRACEME */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    for (unsigned t = 0; t < N_TRAPPED; t++) f[i++] = (struct sock_filter){JEQ, TO_TRAP, 0, trapped[t]};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* The trap, unless the call comes from Burrow's gadget (allowed) or its probe (an errno of ours). */
    uint64_t probe = (uint64_t) burrow_probe;
    int trap = i;
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 12}; /* instruction pointer, high half */
    f[i++] = (struct sock_filter){JEQ, 0, 7, (uint32_t) (gadget >> 32)};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 8};
    f[i++] = (struct sock_filter){JEQ, 4, 0, (uint32_t) gadget + 4};
    f[i++] = (struct sock_filter){JEQ, 3, 0, (uint32_t) gadget};
    f[i++] = (struct sock_filter){JEQ, 1, 0, (uint32_t) probe + 4};
    f[i++] = (struct sock_filter){JEQ, 0, 2, (uint32_t) probe};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | PROBE_ERRNO};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_TRAP | TRAP_DATA};
    for (int j = 0; j < trap; j++)
        if ((f[j].code == JEQ || f[j].code == JSET) && f[j].jt == TO_TRAP) f[j].jt = (uint8_t) (trap - j - 1);
    struct {
        unsigned short len;
        struct sock_filter* filter;
    } prog = {(unsigned short) i, f};
    long r = sys(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0);
    if (r < 0) return r;
    return sys(NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &prog, 0);
}

/* The guest's own filters (Chromium's sandbox, Firefox's) are checked for every call of ours, too: the
 * gadget's internal calls (the path walk's lstat and openat2, the owner store's xattrs) were trapped or
 * killed by them, and the guest's call failed with ENOSYS (every Chromium renderer died of it). Each
 * filter the guest installs gets a prologue that lets the gadget through for the calls Burrow makes for
 * itself, own[] below, and goes on with its own program for everything else; its traps for the guest's
 * own calls still reach the guest's handler, since those come from the guest's code.
 * What is left open (runtime/DELTA.md): a guest that jumps to the gadget itself passes its own filter
 * for the numbers in own[]; and a filter of more than BPF_MAXINSNS - PROLOGUE instructions gets no
 * prologue, so its verdicts reach Burrow's own calls too. The calls that forward the guest's own
 * (connect, bind, socket, sendto, sendmsg, execve, execveat, mount, unshare, clone, kill, ptrace, the ids and
 * the SysV calls) are not in the list: the probe has asked the guest's filters about the call itself, and
 * the forwarded one is judged by them again. */
static const uint16_t own[] = {
    /* the path walk, the owner store, the made-up /proc files, the SysV IPC files, the loader */
    NR_openat, NR_openat2, NR_newfstatat, NR_fstat, NR_statx, NR_readlinkat, NR_getdents64, NR_faccessat,
    NR_close, NR_read, NR_write, NR_pread64, 68 /* pwrite64 */, NR_lseek, NR_fcntl, 46 /* ftruncate */, 279 /* memfd_create */,
    NR_mmap, NR_munmap, NR_mprotect, NR_mremap, NR_mkdirat, NR_symlinkat, NR_unlinkat, NR_renameat, NR_renameat2,
    NR_getxattr, NR_lgetxattr, NR_fgetxattr, NR_setxattr, NR_lsetxattr, NR_fsetxattr,
    /* the handler itself */
    NR_rt_sigaction, NR_rt_sigprocmask, NR_rt_sigreturn, NR_sigaltstack, 98 /* futex */, NR_getpid, NR_gettid,
    NR_tgkill, 113 /* clock_gettime */, 278 /* getrandom */, 123 /* sched_getaffinity */, 179 /* sysinfo */, NR_uname, NR_prctl,
    NR_process_vm_readv, NR_exit_group,
};
#define N_OWN (sizeof(own) / sizeof(*own))
#define PROLOGUE (N_OWN + 8)
#define BPF_JA 0x05
#define BPF_MAXINSNS 4096

static void gadget_prologue(struct sock_filter* f) {
    uint64_t gadget = (uint64_t) burrow_gadget;
    unsigned end = PROLOGUE;  /* the guest's program */
    unsigned allow = end - 1; /* RET_ALLOW */
    f[0] = (struct sock_filter){LD_ABS, 0, 0, 12}; /* instruction pointer, high half */
    f[1] = (struct sock_filter){JEQ, 0, (uint8_t) (end - 2), (uint32_t) (gadget >> 32)};
    f[2] = (struct sock_filter){LD_ABS, 0, 0, 8};
    f[3] = (struct sock_filter){JEQ, 1, 0, (uint32_t) gadget + 4};
    f[4] = (struct sock_filter){JEQ, 0, (uint8_t) (end - 5), (uint32_t) gadget};
    f[5] = (struct sock_filter){LD_ABS, 0, 0, 0}; /* nr */
    for (unsigned i = 0; i < N_OWN; i++)
        f[6 + i] = (struct sock_filter){JEQ, (uint8_t) (allow - (6 + i) - 1), 0, own[i]};
    f[6 + N_OWN] = (struct sock_filter){BPF_JA, 0, 0, end - (6 + N_OWN) - 1};
    f[allow] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
}

static void* map(long size);

/* The guest's memory, copied without a fault in the handler: -EFAULT if it is not all there. */
static long guest_read(void* to, const void* from, long size) {
    struct {
        void* base;
        size_t length;
    } local = {to, (size_t) size}, remote = {(void*) from, (size_t) size};
    long r = sys6(NR_process_vm_readv, sys(NR_getpid, 0, 0, 0, 0), (long) &local, 1, (long) &remote, 1, 0);
    return r == size ? 0 : r < 0 ? r : -EFAULT;
}

/* seccomp(SECCOMP_SET_MODE_FILTER, flags, prog) and prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog). */
static long do_guest_filter(int nr, const uint64_t* x) {
    long flags = nr == NR_seccomp ? (long) x[1] : 0;
    if (nr == NR_prctl && x[1] != 2 /* SECCOMP_MODE_FILTER */) return sys(NR_prctl, x[0], x[1], x[2], x[3]);
    struct sock_fprog prog;
    long r = x[2] == 0 ? -EFAULT : guest_read(&prog, (const void*) x[2], sizeof(prog));
    if (r < 0) return r;
    if (prog.len == 0 || prog.len > BPF_MAXINSNS) return -EINVAL;
    if (prog.filter == 0) return -EFAULT;
    if (prog.len > BPF_MAXINSNS - PROLOGUE) {
        /* no room for the prologue: the guest's filter as it is */
        r = nr == NR_seccomp ? sys(NR_seccomp, x[0], x[1], x[2], 0) : sys(NR_prctl, x[0], x[1], x[2], x[3]);
    } else {
        long size = (long) (prog.len + PROLOGUE) * (long) sizeof(struct sock_filter);
        struct sock_filter* f = (struct sock_filter*) map(size);
        if (f == 0) return -ENOMEM;
        gadget_prologue(f);
        r = guest_read(f + PROLOGUE, prog.filter, (long) prog.len * (long) sizeof(struct sock_filter));
        if (r == 0) {
            struct sock_fprog ours = {(unsigned short) (prog.len + PROLOGUE), f};
            r = nr == NR_seccomp ? sys(NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &ours, 0)
                                 : sys(NR_prctl, PR_SET_SECCOMP, 2, &ours, 0);
        }
        sys(NR_munmap, f, size, 0, 0);
    }
    /* installed: 0, or the listener's descriptor (a positive result with TSYNC is the thread that failed) */
    if (r == 0 || (r > 0 && (flags & 8 /* NEW_LISTENER */) && !(flags & 1 /* TSYNC */)))
        __atomic_store_n(&cfg.guest_filtered, 1, __ATOMIC_RELAXED);
    return r;
}

/* -- Ids (proot's fake_id0) ------------------------------------------------------------ */

static uint32_t id(int which) { return __atomic_load_n(&cfg.ids[which], __ATOMIC_RELAXED); }
static void set_id(int which, uint32_t value) { __atomic_store_n(&cfg.ids[which], value, __ATOMIC_RELAXED); }

/* Files the app owns show as the saved set-ids': root until a program drops
 * its ids (apt's _apt then finds its own files). Set-user-ID and set-group-ID
 * programs show as root's, whose ids they run with (Chromium's sandbox helper
 * is refused otherwise). */
static void fake_owner(uint32_t* uid, uint32_t* gid, uint32_t mode) {
    int regular = (mode & S_IFMT) == S_IFREG;
    if (*uid == cfg.real_uid) *uid = regular && (mode & S_ISUID) ? 0 : id(SUID);
    if (*gid == cfg.real_gid) *gid = regular && (mode & S_ISGID) ? 0 : id(SGID);
}

static int one_of(uint32_t v, int base) { return v == id(base) || v == id(base + 1) || v == id(base + 2); }

/* setuid() and friends, @base RUID or RGID. -1 leaves an id as it is. */
static long set_ids(int base, uint32_t r, uint32_t e, uint32_t s, int kind) {
    int privileged = id(EUID) == 0;
    uint32_t none = (uint32_t) -1;
    if (kind == 1) { /* setuid */
        if (privileged) {
            set_id(base, r), set_id(base + 1, r), set_id(base + 2, r), set_id(base + 3, r);
        } else if (r == id(base) || r == id(base + 2)) {
            set_id(base + 1, r), set_id(base + 3, r);
        } else {
            return -EPERM;
        }
        return 0;
    }
    if (!privileged) {
        if (r != none && !one_of(r, base)) return -EPERM;
        if (e != none && !one_of(e, base)) return -EPERM;
        if (s != none && !one_of(s, base)) return -EPERM;
    }
    uint32_t old_r = id(base);
    if (r != none) set_id(base, r);
    if (e != none) set_id(base + 1, e);
    if (kind == 2) { /* setreuid: the saved id follows a new effective one */
        if (r != none || (e != none && e != old_r)) set_id(base + 2, id(base + 1));
    } else if (s != none) {
        set_id(base + 2, s);
    }
    set_id(base + 3, id(base + 1));
    return 0;
}

static long get_ids(int base, uint32_t* r, uint32_t* e, uint32_t* s) {
    *r = id(base);
    *e = id(base + 1);
    *s = id(base + 2);
    return 0;
}

static long set_fs_id(int base, uint32_t v) {
    uint32_t old = id(base + 3);
    if (id(EUID) == 0 || one_of(v, base) || v == old) set_id(base + 3, v);
    return old;
}

/* -- Signals ------------------------------------------------------------------------- */

static struct ksigaction guest_sigsys; /* the guest's SIGSYS disposition */

#define SIGSYS_BIT (1ull << (SIGSYS - 1))

static long do_sigaction(long sig, const struct ksigaction* act, struct ksigaction* old, long size) {
    if (sig == SIGSYS) {
        struct ksigaction previous = guest_sigsys;
        if (act != 0) guest_sigsys = *act;
        if (old != 0) *old = previous;
        return 0;
    }
    struct ksigaction mine;
    if (act != 0) {
        mine = *act;
        mine.mask &= ~SIGSYS_BIT;
        act = &mine;
    }
    return sys(NR_rt_sigaction, sig, act, old, size);
}

/* The handler's return restores the mask saved in the signal frame, @mask:
 * the change goes there (to the thread, it would be undone). */
static long do_sigprocmask(uint64_t* mask, long how, const uint64_t* set, uint64_t* old, long size) {
    if (size != 8) return -EINVAL;
    uint64_t now = *mask;
    if (set != 0) {
        if (how == 0 /* SIG_BLOCK */) now |= *set;
        else if (how == 1 /* SIG_UNBLOCK */) now &= ~*set;
        else if (how == 2 /* SIG_SETMASK */) now = *set;
        else return -EINVAL;
        now &= ~(SIGSYS_BIT | 1ull << (9 - 1) /* SIGKILL */ | 1ull << (19 - 1) /* SIGSTOP */);
    }
    if (old != 0) *old = *mask;
    *mask = now;
    return 0;
}

/* A SIGSYS that is not ours: the guest's own filters (Firefox's sandbox),
 * Android's, or a kill(). */

static void foreign(int sig, struct ksiginfo* info, struct kucontext* uc) {
    uintptr_t h = guest_sigsys.handler;
    if (info->code == SYS_SECCOMP && info->errno_ == 0 && info->call_addr == (uintptr_t) burrow_probe + 4) {
        /* Android's own trap on the probed call (a bare SECCOMP_RET_TRAP outranks our errno): not the guest's
         * verdict. Nothing of the guest's filters denied it, so it goes on to the emulation. */
        uc->mcontext.regs[0] = (uint64_t) -PROBE_ERRNO;
        return;
    }
    if (info->code == SYS_SECCOMP && info->call_addr == (uintptr_t) burrow_gadget + 4) {
        /* Burrow's own call, which the guest's filter traps (Chromium's
         * sandboxed processes trap openat2): it fails, as if missing,
         * instead of crashing the guest. */
        uc->mcontext.regs[0] = (uint64_t) -ENOSYS;
        return;
    }
    if (info->code == SYS_SECCOMP && info->errno_ == 0) {
        /* Android's app policy traps with a bare SECCOMP_RET_TRAP. */
        uint64_t* x = uc->mcontext.regs;
        switch (info->syscall) {
        case 202: /* accept: apps must use accept4 (Xwayland does not) */
            x[0] = (uint64_t) sys(242 /* accept4 */, x[0], x[1], x[2], 0);
            break;
        case 39:  /* umount2 */
        case 40:  /* mount */
        case 41:  /* pivot_root */
        case 97:  /* unshare */
        case 268: /* setns: as proot, pretend (sandbox helpers carry on) */
            x[0] = 0;
            break;
        default: /* clone3 (glibc falls back to clone), SysV semaphores and queues... */
            x[0] = (uint64_t) -ENOSYS;
        }
    } else if (h > 1) {
        if (guest_sigsys.flags & SA_SIGINFO) {
            ((void (*)(int, struct ksiginfo*, struct kucontext*)) h)(sig, info, uc);
        } else {
            ((void (*)(int)) h)(sig);
        }
    } else if (info->code == SYS_SECCOMP) {
        uc->mcontext.regs[0] = (uint64_t) -ENOSYS;
    } else if (h == 0) {
        /* The default action: die by it. */
        struct ksigaction dfl = {0, 0, 0, 0};
        sys(NR_rt_sigaction, SIGSYS, &dfl, 0, 8);
        sys(NR_tgkill, sys(NR_getpid, 0, 0, 0, 0), sys(NR_gettid, 0, 0, 0, 0), SIGSYS, 0);
    }
}

/* -- Path syscalls ---------------------------------------------------------------------- */

/* Android's shared storage, where the app may do anything with every file
 * (all-files access): its files show as the guest's own, else KIO marks
 * those of other apps unreadable. Its device, found once per process. */
static int on_shared_storage(uint32_t major, uint32_t minor) {
    static uint64_t device = 0; /* major << 32 | minor, 1 if none */
    if (device == 0) {
        struct kstat st;
        uint64_t d = 1;
        if (sys(NR_newfstatat, AT_FDCWD, "/storage/emulated/0", &st, 0) == 0)
            d = (uint64_t) ((st.dev >> 8) & 0xfff) << 32 | ((st.dev & 0xff) | ((st.dev >> 12) & 0xfff00));
        __atomic_store_n(&device, d, __ATOMIC_RELAXED);
    }
    return __atomic_load_n(&device, __ATOMIC_RELAXED) == ((uint64_t) major << 32 | minor);
}

/* -- Owner store (Kestrel) --------------------------------------------------------------
 * chown() and chmod() in the guest record the owner, group and permission bits in the
 * extended attribute user.kestrel.own on the host file; stat(), fstat() and statx() show them.
 * Files without the attribute keep proot's fake_id0 view. Symbolic links cannot carry user
 * attributes, so their owner is not stored. */
#define OWN_XATTR "user.kestrel.own"
#define OWN_MAGIC 0x4b4f574eu /* "KOWN" */
struct own { uint32_t magic, uid, gid, mode; }; /* mode: permission bits 07777, OWN_MODE_SET if chmod() set them */
#define OWN_MODE_SET 0x80000000u

static int own_get_path(const char* host, int follow, struct own* o) {
    long r = sys6(follow ? NR_getxattr : NR_lgetxattr, (long) host, (long) OWN_XATTR, (long) o, sizeof *o, 0, 0);
    return r == (long) sizeof *o && o->magic == OWN_MAGIC ? 0 : -1;
}

static int own_get_fd(long fd, struct own* o) {
    long r = sys6(NR_fgetxattr, fd, (long) OWN_XATTR, (long) o, sizeof *o, 0, 0);
    if (r == -EBADF) { /* O_PATH descriptors: go through /proc/self/fd */
        char p[32] = "/proc/self/fd/";
        format_unsigned(p + 14, (unsigned long) fd);
        return own_get_path(p, 1, o);
    }
    return r == (long) sizeof *o && o->magic == OWN_MAGIC ? 0 : -1;
}

static long own_set_path(const char* host, int follow, const struct own* o) {
    long r = sys6(follow ? NR_setxattr : NR_lsetxattr, (long) host, (long) OWN_XATTR, (long) o, sizeof *o, 0, 0);
    if (r != -EACCES) return r;
    /* User attributes need write permission: a read-only file of the app's (dpkg unpacks some
     * 0444 before its chown) gets owner-write for the moment. */
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, 0) < 0 || st.uid != cfg.real_uid) return r;
    if (sys(NR_fchmodat, AT_FDCWD, (long) host, (st.mode & 07777) | 0200, 0) < 0) return r;
    r = sys6(NR_setxattr, (long) host, (long) OWN_XATTR, (long) o, sizeof *o, 0, 0);
    sys(NR_fchmodat, AT_FDCWD, (long) host, st.mode & 07777, 0);
    return r;
}

static long own_set_fd(long fd, const struct own* o) {
    long r = sys6(NR_fsetxattr, fd, (long) OWN_XATTR, (long) o, sizeof *o, 0, 0);
    if (r == -EBADF || r == -EACCES) {
        char p[32] = "/proc/self/fd/";
        format_unsigned(p + 14, (unsigned long) fd);
        return own_set_path(p, 1, o);
    }
    return r;
}

/* The rootfs's device: its files without a store record are root's (files created by other
 * guest users get a record when created). Files elsewhere (/proc, /dev, shared storage) keep
 * proot's view: the app's show as the viewer's. */
static uint64_t root_dev(void) {
    static uint64_t dev = 0;
    if (dev == 0) {
        struct kstat st;
        dev = sys(NR_newfstatat, AT_FDCWD, (long) cfg.root, (long) &st, 0) == 0 ? st.dev : 1;
    }
    return dev;
}

static void fake_stat_own(long r, struct kstat* st, const struct own* o) {
    if (r != 0) return;
    if (o) {
        st->uid = o->uid, st->gid = o->gid;
        /* the stored mode only while the host's permission bits still match it: fchmod() is not
         * trapped (trapping it breaks Chromium's sandbox), so it may have changed them since */
        if ((o->mode & OWN_MODE_SET) && (o->mode & 0777u) == (st->mode & 0777u)) st->mode = (st->mode & ~07777u) | (o->mode & 07777u);
        return;
    }
    /* Regular files and directories can carry a store record, so unrecorded ones are root's.
     * Sockets, fifos, devices and symlinks cannot (no user xattrs): proot's view, the viewer's. */
    uint32_t type = st->mode & S_IFMT;
    if (st->dev == root_dev() && st->uid == cfg.real_uid && (type == S_IFREG || type == S_IFDIR)) {
        st->uid = 0;
        if (st->gid == cfg.real_gid) st->gid = 0;
        return;
    }
    if (on_shared_storage((st->dev >> 8) & 0xfff, (st->dev & 0xff) | ((st->dev >> 12) & 0xfff00)))
        st->uid = cfg.real_uid, st->gid = cfg.real_gid;
    fake_owner(&st->uid, &st->gid, st->mode);
}

static void fake_stat(long r, struct kstat* st) { fake_stat_own(r, st, 0); }

static void fake_statx_own(long r, struct kstatx* stx, const struct own* o) {
    if (r != 0) return;
    uint64_t dev = ((uint64_t) (stx->dev_minor & 0xff)) | ((uint64_t) stx->dev_major << 8) | ((uint64_t) (stx->dev_minor & ~0xffu) << 12);
    uint32_t type = stx->mode & S_IFMT;
    if (!o && dev == root_dev() && (stx->mask & STATX_UID) && stx->uid == cfg.real_uid && (type == S_IFREG || type == S_IFDIR)) {
        stx->uid = 0;
        if ((stx->mask & STATX_GID) && stx->gid == cfg.real_gid) stx->gid = 0;
        return;
    }
    if (o) {
        if (stx->mask & STATX_UID) stx->uid = o->uid;
        if (stx->mask & STATX_GID) stx->gid = o->gid;
        if ((stx->mask & STATX_MODE) && (o->mode & OWN_MODE_SET) && (o->mode & 0777u) == (stx->mode & 0777u))
            stx->mode = (uint16_t) ((stx->mode & ~07777u) | (o->mode & 07777u));
        return;
    }
    uint32_t uid = (stx->mask & STATX_UID) ? stx->uid : ~0u;
    uint32_t gid = (stx->mask & STATX_GID) ? stx->gid : ~0u;
    if (on_shared_storage(stx->dev_major, stx->dev_minor)) uid = cfg.real_uid, gid = cfg.real_gid;
    fake_owner(&uid, &gid, (stx->mask & STATX_MODE) ? stx->mode : 0);
    if (stx->mask & STATX_UID) stx->uid = uid;
    if (stx->mask & STATX_GID) stx->gid = gid;
}

static void fake_statx(long r, struct kstatx* stx) { fake_statx_own(r, stx, 0); }

/* An *at() syscall on the path (@dirfd, @path) with its host path instead. */
#define ON_HOST(follow, call)                                    \
    do {                                                         \
        char host[PATH_MAX];                                     \
        long r_ = host_path(dirfd, path, (follow), host);        \
        return r_ < 0 ? r_ : (call);                             \
    } while (0)

/* ON_HOST() that first runs @guard (a negative result, such as ro_guard(host), ends the call with it). */
#define ON_HOST_RO(follow, guard, call)                          \
    do {                                                         \
        char host[PATH_MAX];                                     \
        long r_ = host_path(dirfd, path, (follow), host);        \
        if (r_ >= 0) r_ = (guard);                               \
        return r_ < 0 ? r_ : (call);                             \
    } while (0)

/* An open of @host for @flags: refused in a read-only binding when it writes or makes the file. */
static long ro_open(const char* host, long flags) {
    if (!read_only_host(host) || (flags & O_PATH)) return 0;
    struct kstat st;
    if ((flags & 3) != O_RDONLY || (flags & O_TRUNC)) return -EROFS;
    if ((flags & O_CREAT) && sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, 0) < 0) return -EROFS;
    return 0;
}

static int empty(const char* path) { return path != 0 && path[0] == 0; }

#define SYSFS_MAGIC 0x62656572
#define CGROUP2_MAGIC 0x63677270

/* statfs(), fstatfs(): a binding of a directory onto /sys is sysfs to the guest
 * (systemd's sd-device refuses other file systems), /sys/fs/cgroup cgroup2. */
static long do_statfs(long nr, const uint64_t* x) {
    char host[PATH_MAX], guest[PATH_MAX];
    long r;
    if (nr == NR_statfs) {
        long dirfd = AT_FDCWD;
        const char* path = (const char*) x[0];
        if ((r = host_path(dirfd, path, 1, host)) < 0) return r;
        if ((r = sys(NR_statfs, host, x[1], 0, 0)) < 0) return r;
    } else {
        if ((r = sys(NR_fstatfs, x[0], x[1], 0, 0)) < 0) return r;
        if (fd_path((long) x[0], host, PATH_MAX) <= 0) return 0;
    }
    long* type = (long*) x[1]; /* f_type, the first field */
    if (*type == SYSFS_MAGIC || *type == CGROUP2_MAGIC || host[0] != '/' || !guest_sees(host) ||
        host_to_guest(host, guest, PATH_MAX) < 0 || !starts_with(guest, "/sys/"))
        return 0;
    *type = starts_with(guest, "/sys/fs/cgroup") && (guest[14] == 0 || guest[14] == '/') ? CGROUP2_MAGIC : SYSFS_MAGIC;
    return 0;
}

/* The guest program of the Burrow process named by @guest, a /proc/<pid>/...
 * path, read from its state like peer_ids() does; 0 if none (the launcher). */
static long remote_exe(const char* guest, char* out) {
    if (!starts_with(guest, "/proc/")) return 0;
    const char* p = guest + 6;
    long pid = (long) parse_unsigned(&p);
    if (p == guest + 6) return 0;
    struct {
        void* base;
        size_t length;
    } local = {out, PATH_MAX}, remote = {cfg.exe, PATH_MAX};
    if (sys6(NR_process_vm_readv, pid, (long) &local, 1, (long) &remote, 1, 0) != PATH_MAX) return 0;
    out[PATH_MAX - 1] = 0;
    return length_of(out);
}

static long do_readlink(long dirfd, const char* path, char* buf, long size) {
    if (size <= 0) return -EINVAL;
    if (empty(path)) return sys(NR_readlinkat, dirfd, path, buf, size);
    char guest[PATH_MAX], host[PATH_MAX], target[PATH_MAX];
    if (path == 0) return -EFAULT;
    long r = guest_absolute(dirfd, path, guest);
    if (r < 0) return r;
    if (same(guest, "/proc/self/exe") || same(guest, "/proc/thread-self/exe")) {
        r = copy(target, PATH_MAX, cfg.exe);
    } else {
        long fd;
        r = host_fd(AT_FDCWD, guest, 0, host, &fd);
        if (r < 0) return r;
        if (fd >= 0) {
            r = sys(NR_readlinkat, fd, "", target, PATH_MAX - 1);
            sys(NR_close, fd, 0, 0, 0);
            if (r == -ENOENT) r = -EINVAL; /* older kernels, on no symlink */
        } else {
            r = sys(NR_readlinkat, AT_FDCWD, host, target, PATH_MAX - 1);
        }
        if (r < 0) return r;
        target[r] = 0;
        static const char deleted[] = " (deleted)";
        if (fd < 0 && r > (long) sizeof(deleted) && same(target + r - sizeof(deleted) + 1, deleted)) {
            long n = proc_copy_target(host, target);
            if (n > 0) r = n;
        }
        /* A faked hard link (to its intermediate, not to the file as /proc's fd links) is a file, no symlink. */
        if (l2s_target(target) && r > 5 && target[r - 5] != '.') return -EINVAL;
        /* Another process's exe is Burrow: KWin finds its clients' desktop files by it. */
        long n = same(target, cfg.self) ? remote_exe(guest, target) : 0;
        if (n > 0) r = n;
        else if (target[0] == '/') r = host_to_guest(target, target, PATH_MAX);
    }
    if (r < 0) return r;
    if (r > size) r = size;
    memcpy(buf, target, r);
    return r;
}

static long do_getcwd(char* buf, long size) {
    char host[PATH_MAX], guest[PATH_MAX];
    long r = sys(NR_getcwd, host, PATH_MAX, 0, 0);
    if (r < 0) return r;
    if (!guest_sees(host)) {
        /* Outside the root (a chroot() moved it): as the kernel says it, glibc's getcwd() then fails with ENOENT. */
        static const char unreachable[] = "(unreachable)";
        r = length_of(host);
        if (r + (long) sizeof(unreachable) > PATH_MAX) return -ENAMETOOLONG;
        memcpy(guest, unreachable, sizeof(unreachable) - 1);
        memcpy(guest + sizeof(unreachable) - 1, host, r + 1);
        r += sizeof(unreachable) - 1;
    } else if ((r = host_to_guest(host, guest, PATH_MAX)) < 0) {
        return r;
    }
    if (r + 1 > size) return -ERANGE;
    memcpy(buf, guest, r + 1);
    return r + 1;
}

/* fchownat(): a fake root's chown succeeds on any file it can see. */
/* The owner record a file shows now: its stored one, else proot's fake view of the host's. */
static void own_current(const struct kstat* st, struct own* o) {
    struct kstat v = *st;
    fake_stat_own(0, &v, 0);
    uint32_t uid = v.uid, gid = v.gid;
    o->magic = OWN_MAGIC, o->uid = uid, o->gid = gid, o->mode = 0; /* permissions: the host's */
}

/* chown(): records the new owner in the store; only the guest's root may give a file away. */
static long own_chown(struct own* o, uint32_t uid, uint32_t gid) {
    /* As Linux: only root gives a file away; the owner may change its group. */
    if (id(FSUID) != 0 && ((uid != (uint32_t) -1 && uid != o->uid) || id(FSUID) != o->uid)) return -EPERM;
    if (uid != (uint32_t) -1) o->uid = uid;
    if (gid != (uint32_t) -1) o->gid = gid;
    return 0;
}

static long do_chown(long dirfd, const char* path, long uid, long gid, long flags) {
    struct kstat st;
    struct own o;
    long r;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        if (read_only_fd(dirfd)) return -EROFS;
        if ((r = sys(NR_fstat, dirfd, &st, 0, 0)) < 0) return r;
        if (own_get_fd(dirfd, &o)) own_current(&st, &o);
        if ((r = own_chown(&o, (uint32_t) uid, (uint32_t) gid)) < 0) return r;
        r = own_set_fd(dirfd, &o);
        return r == -EOPNOTSUPP || r == -EPERM || r == -EACCES ? 0 : r;
    }
    char host[PATH_MAX];
    int follow = !(flags & AT_SYMLINK_NOFOLLOW);
    if ((r = host_path(dirfd, path, follow, host)) < 0 || (r = ro_guard(host)) < 0) return r;
    if ((r = sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, follow ? 0 : AT_SYMLINK_NOFOLLOW)) < 0) return r;
    if ((st.mode & S_IFMT) == S_IFLNK) {
        /* a faked hard link (link2symlink): its owner is its file's */
        char file[PATH_MAX];
        if (!l2s_file(host, file)) return 0; /* a real symlink: no user attributes on symlinks */
        if ((r = copy(host, PATH_MAX, file)) < 0) return r;
        if ((r = sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, 0)) < 0) return r;
    }
    if (own_get_path(host, 1, &o)) own_current(&st, &o);
    if ((r = own_chown(&o, (uint32_t) uid, (uint32_t) gid)) < 0) return r;
    r = own_set_path(host, 1, &o);
    return r == -EOPNOTSUPP || r == -EPERM || r == -EACCES ? 0 : r;
}

/* chmod(): the host gets the bits; the store keeps them only when the host did not (set-id bits
 * it refused), so most files never get a store record for their mode. */
static void own_mode_after(const struct kstat* st, long mode, struct own* o, int have) {
    if (!have) own_current(st, o);
    if ((st->mode & 07777u) != ((uint32_t) mode & 07777u)) o->mode = ((uint32_t) mode & 07777u) | OWN_MODE_SET;
    else o->mode = 0;
}

/* Only the file's owner or root may change its mode (as Linux). */
static int may_chmod(const struct own* o) { return id(FSUID) == 0 || id(FSUID) == o->uid; }

static long do_chmod(long dirfd, const char* path, long mode, long flags) {
    struct kstat st;
    struct own o;
    char host[PATH_MAX];
    long r;
    int follow = !(flags & AT_SYMLINK_NOFOLLOW);
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        if (read_only_fd(dirfd)) return -EROFS;
        if ((r = sys(NR_fstat, dirfd, &st, 0, 0)) < 0) return r;
        int have = own_get_fd(dirfd, &o) == 0;
        if (!have) own_current(&st, &o);
        if (!may_chmod(&o)) return -EPERM;
        r = sys(NR_fchmod, dirfd, mode & 07777, 0, 0);
        if (r == -EPERM) r = sys(NR_fchmod, dirfd, mode & 0777, 0, 0);
        if (r == -EBADF) { /* an O_PATH descriptor: through /proc/self/fd */
            char p[32] = "/proc/self/fd/";
            format_unsigned(p + 14, (unsigned long) dirfd);
            r = sys(NR_fchmodat, AT_FDCWD, (long) p, mode & 07777, 0);
            if (r == -EPERM) r = sys(NR_fchmodat, AT_FDCWD, (long) p, mode & 0777, 0);
        }
        if (r < 0) return r;
        if (sys(NR_fstat, dirfd, &st, 0, 0) == 0 && (have || (st.mode & 07777u) != ((uint32_t) mode & 07777u))) {
            own_mode_after(&st, mode, &o, 1);
            own_set_fd(dirfd, &o);
        }
        return 0;
    }
    if ((r = host_path(dirfd, path, follow, host)) < 0 || (r = ro_guard(host)) < 0) return r;
    if ((r = sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, AT_SYMLINK_NOFOLLOW)) < 0) return r;
    if ((st.mode & S_IFMT) == S_IFLNK) {
        /* not followed (AT_SYMLINK_NOFOLLOW): a faked hard link is its file; a symlink's mode
         * cannot change (Linux: EOPNOTSUPP) */
        char file[PATH_MAX];
        if (!l2s_file(host, file)) return -EOPNOTSUPP;
        if ((r = copy(host, PATH_MAX, file)) < 0) return r;
        if ((r = sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, 0)) < 0) return r;
    }
    int have = own_get_path(host, 1, &o) == 0;
    if (!have) own_current(&st, &o);
    if (!may_chmod(&o)) return -EPERM;
    r = sys(NR_fchmodat, AT_FDCWD, (long) host, mode & 07777, 0);
    if (r == -EPERM) r = sys(NR_fchmodat, AT_FDCWD, (long) host, mode & 0777, 0); /* host refused set-id bits */
    if (r < 0) return r;
    if (sys(NR_newfstatat, AT_FDCWD, (long) host, (long) &st, 0) == 0 && (have || (st.mode & 07777u) != ((uint32_t) mode & 07777u))) {
        own_mode_after(&st, mode, &o, 1);
        own_set_path(host, 1, &o); /* handles a file the chmod just made read-only */
    }
    return 0;
}

/* Files created by a guest user other than root get a store record naming the creator
 * (unrecorded files are root's). */
static void own_stamp_path(const char* host) {
    if (id(FSUID) == 0) return;
    struct own o = {OWN_MAGIC, id(FSUID), id(FSGID), 0};
    own_set_path(host, 1, &o);
}

static long own_stamp_fd(long fd) {
    if (fd >= 0 && id(FSUID) != 0) {
        struct own o = {OWN_MAGIC, id(FSUID), id(FSGID), 0};
        own_set_fd(fd, &o);
    }
    return fd;
}

/* newfstatat() of @path into @st, the last component followed if @follow;
 * @host is the host path. */
static long stat_host(long dirfd, const char* path, int follow, char* host, struct kstat* st) {
    long fd, r = host_fd(dirfd, path, follow, host, &fd);
    if (r < 0) return r;
    if (fd < 0) return sys(NR_newfstatat, AT_FDCWD, host, st, follow ? 0 : AT_SYMLINK_NOFOLLOW);
    r = sys(NR_newfstatat, fd, "", st, AT_EMPTY_PATH);
    sys(NR_close, fd, 0, 0, 0);
    return r;
}

/* stat() and lstat(): a faked hard link shows as its file. The last
 * component is looked at unfollowed first: most are no symlink, and that one
 * call answers both. */
static long do_stat(long dirfd, const char* path, struct kstat* st, long flags) {
    long r;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        r = sys(NR_newfstatat, dirfd, path, st, flags);
        struct own o;
        if (r == 0 && (st->mode & S_IFMT) != S_IFLNK && own_get_fd(dirfd, &o) == 0) { fake_stat_own(r, st, &o); return r; }
    } else {
        char host[PATH_MAX];
        r = stat_host(dirfd, path, 0, host, st);
        if (r == -EACCES && proc_file(host) >= 0) r = proc_stat(st);
        int followed = 0;
        if (r == 0 && (st->mode & S_IFMT) == S_IFLNK && !l2s_stat(host, st) && !(flags & AT_SYMLINK_NOFOLLOW))
            r = stat_host(dirfd, path, 1, host, st), followed = 1;
        struct own o;
        if (r == 0 && (st->mode & S_IFMT) != S_IFLNK && own_get_path(host, 1, &o) == 0) {
            (void) followed;
            fake_stat_own(r, st, &o);
            return r;
        }
    }
    fake_stat(r, st);
    return r;
}

/* statx() of @path into @stx, with @flags but for following, the last
 * component followed if @follow; @host is the host path. */
static long statx_host(long dirfd, const char* path, int follow, long flags, long mask, char* host,
                       struct kstatx* stx) {
    long fd, r = host_fd(dirfd, path, follow, host, &fd);
    if (r < 0) return r;
    flags &= ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    if (fd < 0) return sys6(NR_statx, AT_FDCWD, (long) host, flags | (follow ? 0 : AT_SYMLINK_NOFOLLOW), mask, (long) stx, 0);
    r = sys6(NR_statx, fd, (long) "", flags | AT_EMPTY_PATH, mask, (long) stx, 0);
    sys(NR_close, fd, 0, 0, 0);
    return r;
}

static long do_statx(long dirfd, const char* path, long flags, long mask, struct kstatx* stx) {
    long r;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        r = sys6(NR_statx, dirfd, (long) path, flags, mask, (long) stx, 0);
        struct own o;
        if (r == 0 && (stx->mode & S_IFMT) != S_IFLNK && own_get_fd(dirfd, &o) == 0) { fake_statx_own(r, stx, &o); return r; }
    } else {
        char host[PATH_MAX];
        long nofollow = (flags & ~AT_EMPTY_PATH) | AT_SYMLINK_NOFOLLOW;
        r = statx_host(dirfd, path, 0, flags, mask | 1 /* STATX_TYPE */, host, stx);
        if (r == -EACCES && proc_file(host) >= 0) r = proc_statx(stx);
        if (r == 0 && (stx->mode & S_IFMT) == S_IFLNK && !l2s_statx(host, nofollow, mask, stx) &&
            !(flags & AT_SYMLINK_NOFOLLOW))
            r = statx_host(dirfd, path, 1, flags, mask, host, stx);
        struct own o;
        if (r == 0 && (stx->mode & S_IFMT) != S_IFLNK && own_get_path(host, 1, &o) == 0) {
            fake_statx_own(r, stx, &o);
            return r;
        }
    }
    fake_statx(r, stx);
    return r;
}

/* A Unix socket address with its path translated into @un; 0 if none to
 * translate. A host path too long for sockaddr_un goes through its directory,
 * opened as *@dir (closed by the caller after the syscall, -1 if none):
 * /proc/self/fd/<dir>/<name>. */
static long socket_address(const char* addr, long length, int follow, void* un, long* un_length, long* dir) {
    struct sockaddr {
        uint16_t family;
        char path[108];
    }* out = un;
    *dir = -1;
    if (addr == 0 || length <= 2 || *(const uint16_t*) addr != AF_UNIX || addr[2] == 0 /* abstract */) return 0;
    char path[109], host[PATH_MAX];
    long n = length - 2 < 108 ? length - 2 : 108;
    memcpy(path, addr + 2, n);
    path[n] = 0;
    long r = host_path(AT_FDCWD, path, follow, host);
    if (r < 0 || (!follow && (r = ro_guard(host)) < 0)) return r; /* bind() makes the file */
    long h = length_of(host);
    if (h >= 108) {
        long slash = h;
        while (slash > 0 && host[slash] != '/') slash--;
        host[slash] = 0;
        long d = sys(NR_openat, AT_FDCWD, slash ? host : "/", O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (d < 0) return d;
        char* end = format_unsigned((char*) memcpy(out->path, "/proc/self/fd/", 14) + 14, (unsigned long) d);
        if (end - out->path + (h - slash) >= 108) {
            sys(NR_close, d, 0, 0, 0);
            return -ENAMETOOLONG;
        }
        memcpy(end, host + slash, h - slash);
        end[0] = '/';
        end[h - slash] = 0;
        *dir = d;
        h = end + (h - slash) - out->path;
    } else {
        memcpy(out->path, host, h + 1);
    }
    out->family = AF_UNIX;
    *un_length = 2 + h + 1;
    return 1;
}

/* The guest's nameserver, 127.0.0.53:53, becomes the DNS proxy given with
 * -d (on 127.0.0.1) in @out: on Android, the app's, so that Android resolves. */
static int dns_address(const char* addr, long length, char* out) {
    static const char nameserver[6] = {0, 53, 127, 0, 0, 53}; /* port and address, big-endian */
    if (cfg.dns_port == 0 || addr == 0 || length < 8 || *(const uint16_t*) addr != AF_INET ||
        memcmp(addr + 2, nameserver, 6) != 0)
        return 0;
    memset(out, 0, 16);
    memcpy(out, addr, 2);
    out[2] = (char) (cfg.dns_port >> 8);
    out[3] = (char) cfg.dns_port;
    out[4] = 127, out[7] = 1;
    return 1;
}

/* bind() on a Unix socket path, connect() on one or to the nameserver. */
static long do_socket_path(long nr, long fd, const char* addr, long length) {
    char un[110];
    long un_length, dir;
    if (nr == NR_connect && dns_address(addr, length, un)) return sys(nr, fd, un, 16, 0);
    long r = socket_address(addr, length, nr == NR_connect, un, &un_length, &dir);
    if (r < 0) return r;
    if (r == 0) return sys(nr, fd, addr, length, 0);
    r = sys(nr, fd, un, un_length, 0);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

struct kmsghdr {
    void* name;
    uint32_t namelen;
    void* iov;
    size_t iovlen;
    void* control;
    size_t controllen;
    int flags;
};

/* sendmsg(): SCM_CREDENTIALS must carry the real ids (D-Bus and X11 clients
 * send their own, which are fake), and a datagram's destination path the
 * host's. */
static long do_sendmsg(long fd, const struct kmsghdr* m, long flags) {
    struct kmsghdr copy;
    char control[1024], un[110];
    int changed = 0;
    long dir = -1;
    if (m != 0 && m->control != 0 && m->controllen >= 16 && m->controllen <= sizeof(control)) {
        for (size_t at = 0; at + 16 <= m->controllen;) {
            const char* c = (const char*) m->control + at;
            size_t length = *(const size_t*) c;
            if (length < 16 || at + length > m->controllen) break;
            if (*(const int*) (c + 8) == 1 /* SOL_SOCKET */ && *(const int*) (c + 12) == 2 /* SCM_CREDENTIALS */ &&
                length >= 16 + 12) {
                if (!changed) {
                    memcpy(control, m->control, m->controllen);
                    copy = *m;
                    copy.control = control;
                    changed = 1;
                }
                uint32_t* cred = (uint32_t*) (control + at + 16); /* pid, uid, gid */
                cred[1] = cfg.real_uid;
                cred[2] = cfg.real_gid;
            }
            at += (length + 7) & ~(size_t) 7;
        }
    }
    if (m != 0 && m->name != 0 && dns_address(m->name, m->namelen, un)) {
        if (!changed) copy = *m, changed = 1;
        copy.name = un;
        copy.namelen = 16;
    } else if (m != 0 && m->name != 0) {
        long un_length;
        long r = socket_address(m->name, m->namelen, 1, un, &un_length, &dir);
        if (r < 0) return r;
        if (r > 0) {
            if (!changed) copy = *m, changed = 1;
            copy.name = un;
            copy.namelen = (uint32_t) un_length;
        }
    }
    long r = sys(NR_sendmsg, fd, changed ? &copy : m, flags, 0);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

static long do_sendto(const uint64_t* x) {
    char un[110];
    long un_length, dir;
    if (dns_address((const char*) x[4], (long) x[5], un))
        return sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) un, 16);
    long r = socket_address((const char*) x[4], (long) x[5], 1, un, &un_length, &dir);
    if (r < 0) return r;
    if (r == 0) return sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], (long) x[5]);
    r = sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) un, un_length);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

/* recvfrom(): answers of the DNS proxy come from the nameserver, else
 * resolvers (glibc's, c-ares) drop them. */
static long do_recvfrom(const uint64_t* x) {
    long r = sys6(NR_recvfrom, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], (long) x[5]);
    char* from = (char*) x[4];
    if (r >= 0 && from != 0 && x[5] != 0 && *(const uint32_t*) x[5] == 12) netlink_name(from, 12, 0);
    if (r < 0 || cfg.dns_port == 0 || from == 0 || x[5] == 0 || *(const uint32_t*) x[5] < 8 ||
        *(const uint16_t*) from != AF_INET)
        return r;
    static const char proxy_address[4] = {127, 0, 0, 1};
    if ((((unsigned char) from[2] << 8) | (unsigned char) from[3]) == cfg.dns_port &&
        memcmp(from + 4, proxy_address, 4) == 0) {
        from[2] = 0, from[3] = 53;
        from[7] = 53;
    }
    return r;
}

/* getsockname(), getpeername(): a Unix socket's host path becomes the guest's. */
static long do_sockname(long nr, long fd, char* addr, uint32_t* length) {
    char a[129];
    uint32_t n = sizeof(a) - 1;
    long r = sys(nr, fd, a, &n, 0);
    if (r < 0) return r;
    if (n > 2 && n < sizeof(a) && *(const uint16_t*) a == AF_UNIX && a[2] == '/') {
        char guest[PATH_MAX];
        a[n] = 0;
        long g = host_to_guest(a + 2, guest, sizeof(guest));
        if (g >= 0 && g < 108) {
            memcpy(a + 2, guest, g + 1);
            n = (uint32_t) (2 + g + 1);
        }
    }
    netlink_name(a, n, nr == NR_getsockname);
    if (length == 0) return -EFAULT;
    memcpy(addr, a, *length < n ? *length : n);
    *length = n;
    return 0;
}

long peer_read(long pid, void* local, const void* remote, long size) {
    char link[48] = "/proc/", exe[512];
    char* end = format_unsigned(link + 6, (unsigned long) pid);
    memcpy(end, "/exe", 5);
    long n = sys(NR_readlinkat, AT_FDCWD, link, exe, sizeof(exe) - 1);
    if (n <= 0) return n < 0 ? n : -ESRCH;
    exe[n] = 0;
    if (!same(exe, cfg.self)) return -ESRCH;
    struct {
        const void* base;
        size_t length;
    } to = {local, (size_t) size}, from = {remote, (size_t) size};
    return sys6(NR_process_vm_readv, pid, (long) &to, 1, (long) &from, 1, 0);
}

/* The emulated ids of Burrow process @pid, read where Burrow keeps them. */
static int peer_ids(long pid, uint32_t* ids) {
    return peer_read(pid, ids, cfg.ids, sizeof(cfg.ids)) == (long) sizeof(cfg.ids);
}

/* getsockopt(SO_PEERCRED): the peer's real ids become its fake ones, root's
 * when they cannot be read. */
static long do_peercred(const uint64_t* x) {
    long r = sys6(NR_getsockopt, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], 0);
    if (r < 0 || x[1] != 1 /* SOL_SOCKET */ || x[4] == 0 || *(const uint32_t*) x[4] < 12) return r;
    uint32_t* cred = (uint32_t*) x[3]; /* pid, uid, gid */
    uint32_t ids[ID_COUNT];
    int known = peer_ids(cred[0], ids);
    if (cred[1] == cfg.real_uid) cred[1] = known ? ids[EUID] : 0;
    if (cred[2] == cfg.real_gid) cred[2] = known ? ids[EGID] : 0;
    return r;
}

/* socket(AF_NETLINK, *, NETLINK_KOBJECT_UEVENT): SELinux refuses it to apps
 * (EACCES), so libudev has no monitor, and KWin 6.8's GpuManager dereferences
 * the missing monitor at start. A route socket stands in, Burrow's own once
 * bound (netlink.c): bind() succeeds and no uevent ever comes, as on a system
 * where nothing is plugged in. */
static long do_uevent_socket(const uint64_t* x) {
    long r = sys(NR_socket, x[0], x[1], x[2], 0);
    if (r != -EACCES || x[0] != 16 /* AF_NETLINK */ || x[2] != 15) return r;
    return sys(NR_socket, x[0], x[1], 0 /* NETLINK_ROUTE */, 0);
}

/* DRM_IOCTL_VERSION: the guest's render node is KGSL, which knows no DRM
 * ioctl, and Chromium's GPU process dies without a version. KGSL answers as
 * "kgsl": Mesa's loader is told its driver (zink), Turnip's msm probe skips
 * any name but "msm". */
static long do_termios2(const uint64_t* x);

static long do_drm_version(const uint64_t* x) {
    if ((uint32_t) x[1] != DRM_IOCTL_VERSION) return do_termios2(x);
    long r = sys(NR_ioctl, x[0], x[1], x[2], 0);
    if (r != -25 /* ENOTTY */ && r != -EINVAL) return r;
    char target[32];
    if (fd_path((int) x[0], target, sizeof(target)) < 0) return r;
    if (!same(target, "/dev/kgsl-3d0")) return r;
    struct drm_version {
        int major, minor, patchlevel;
        size_t name_length;
        char* name;
        size_t date_length;
        char* date;
        size_t desc_length;
        char* desc;
    }* v = (struct drm_version*) x[2];
    if (v == 0) return -EFAULT;
    static const char* const strings[] = {"kgsl", "20260101", "Qualcomm KGSL (Burrow)"};
    size_t* lengths[] = {&v->name_length, &v->date_length, &v->desc_length};
    char* buffers[] = {v->name, v->date, v->desc};
    v->major = 1, v->minor = 0, v->patchlevel = 0;
    for (int i = 0; i < 3; i++) {
        size_t length = (size_t) length_of(strings[i]);
        if (buffers[i] != 0) memcpy(buffers[i], strings[i], *lengths[i] < length ? *lengths[i] : length);
        *lengths[i] = length;
    }
    return 0;
}

/* TCGETS2 and the TCSETS2 family: Android's SELinux policy allows the termios ioctls of a terminal
 * but not these (EACCES), and glibc 2.42's tcgetattr() and isatty() use them with no fallback: bash
 * took the terminal for a file and showed no prompt (Ubuntu 26.04, Fedora 45, Arch). Tried as they
 * are first; on EACCES they are made with TCGETS/TCSETS, whose struct is termios2 without the speeds. */
struct ktermios {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t line, cc[19];
};
struct ktermios2 {
    struct ktermios t;
    uint32_t ispeed, ospeed;
};

static uint32_t baud_of(uint32_t cflag) {
    static const uint32_t rate[] = {0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400};
    static const uint32_t high[] = {57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000,
                                    1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000};
    uint32_t b = cflag & 0x100f; /* CBAUD */
    if (b < 16) return rate[b];
    if (b >= 0x1001 && b <= 0x100f) return high[b - 0x1001];
    return 38400;
}

static long do_termios2(const uint64_t* x) {
    uint32_t cmd = (uint32_t) x[1];
    long r = sys(NR_ioctl, x[0], x[1], x[2], 0);
    if (r != -EACCES || x[2] == 0) return r;
    struct ktermios2* t2 = (struct ktermios2*) x[2];
    if (cmd == TCGETS2) {
        struct ktermios t;
        r = sys(NR_ioctl, x[0], 0x5401 /* TCGETS */, &t, 0);
        if (r < 0) return r;
        t2->t = t;
        t2->ispeed = t2->ospeed = baud_of(t.cflag);
        return 0;
    }
    struct ktermios t = t2->t;
    if ((t.cflag & 0x100f) == 0x1000 /* BOTHER */) t.cflag = (t.cflag & ~0x100fu) | 15; /* B38400 */
    return sys(NR_ioctl, x[0], cmd == TCSETS2 ? 0x5402 : cmd == TCSETSW2 ? 0x5403 : 0x5404, &t, 0);
}

/* -- execve ------------------------------------------------------------------------------ */

static void* map(long size) {
    long p = sys6(NR_mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p < 0 && p > -4096 ? 0 : (void*) p;
}

/* ptrace(PTRACE_TRACEME) in a vfork() child waits for its execve(), made
 * then by the loader once the program is in place (load_and_run()). Made
 * here, the child's next trap would stop it for its tracer, which waits for
 * that execve() (gdb's run hung). Such a child may only exec or exit; one of
 * fork() (gdb's check of ptrace, which stops itself) is traced at once. The
 * thread is recorded, not a flag: the child writes its parent's memory. */
static long traceme_tid, vm_probe;

static long do_traceme(void) {
    long tid = sys(NR_gettid, 0, 0, 0, 0), parent = 0;
    vm_probe = tid;
    if (peer_read(sys(NR_getppid, 0, 0, 0, 0), &parent, &vm_probe, sizeof(parent)) != sizeof(parent) || parent != tid)
        return sys(NR_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
    traceme_tid = tid;
    return 0;
}

/* Reads "#!interpreter [argument]" from @head (@n bytes). Returns 1 with the
 * strings cut in place, 0 if it is no script. */
static int shebang(char* head, long n, char** interpreter, char** argument) {
    if (n < 2 || head[0] != '#' || head[1] != '!') return 0;
    long i = 2, end = 2;
    while (end < n && head[end] != '\n') end++;
    head[end < n ? end : n - 1] = 0;
    while (head[i] == ' ' || head[i] == '\t') i++;
    *interpreter = head + i;
    while (head[i] && head[i] != ' ' && head[i] != '\t') i++;
    *argument = 0;
    if (head[i]) {
        head[i++] = 0;
        while (head[i] == ' ' || head[i] == '\t') i++;
        if (head[i]) {
            *argument = head + i;
            long last = length_of(head + i) - 1;
            while (last >= 0 && (head[i + last] == ' ' || head[i + last] == '\t')) head[i + last--] = 0;
        }
    }
    return **interpreter != 0;
}

/* Whether a program is Wine's: its loaders and server by base name, or anything below a wine/
 * directory (/usr/lib/wine/wine64, a Hangover or a /opt/wine tree). Wine's own entry points
 * (__wine_syscall_dispatcher) have no BTI landing pad, so such a process gets no PROT_BTI, see do_mprotect(). */
static int wine_program(const char* path) {
    const char* b = path;
    for (const char* p = path; *p; p++) {
        if (*p == '/' && p[1]) b = p + 1;
        if (starts_with(p, "/wine/")) return 1;
    }
    return same(b, "wine") || same(b, "wine64") || same(b, "wine-preloader") || same(b, "wine64-preloader") ||
           same(b, "wineserver") || same(b, "wineserver32") || same(b, "wineserver64");
}

long emulate_execve(long dirfd, const char* path, char* const* argv, char* const* envp, long flags) {
    char guest[PATH_MAX], host[PATH_MAX], resolved[PATH_MAX];
    char heads[4][256];
    /* argv's head after the scripts' interpreters: at each level the kernel
     * runs "interpreter [argument] file args[1..]". */
    const char* head[12];
    int head_count = 1;
    const char* file = path;
    long r;
    if (path == 0) return -EFAULT;
    head[0] = argv != 0 ? argv[0] : 0;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        if (fd_path((int) dirfd, host, PATH_MAX) < 0) return -EBADF;
        r = host_to_guest(host, guest, PATH_MAX);
    } else {
        if (path[0] == 0) return -ENOENT;
        r = guest_absolute(dirfd, path, guest);
    }
    if (r < 0) return r;
    /* The process name: the base name of the file execve() was given. */
    char name[16];
    const char* b = guest;
    for (const char* p = guest; *p; p++)
        if (*p == '/' && p[1]) b = p + 1;
    long l = 0;
    while (b[l] && b[l] != '/' && l < 15) name[l] = b[l], l++;
    name[l] = 0;
    uint32_t set_ids_mode = 0; /* S_ISUID and S_ISGID of the file itself (scripts' are ignored, as by Linux) */
    uint32_t set_uid_to = 0, set_gid_to = 0; /* the owner they switch to: root unless the owner store says otherwise */
    for (int depth = 0;; depth++) {
        r = to_host(guest, !(flags & AT_SYMLINK_NOFOLLOW), host, resolved);
        if (r < 0) return r;
        struct kstat st;
        r = sys(NR_newfstatat, AT_FDCWD, host, &st, 0);
        if (r < 0) return r;
        if ((st.mode & S_IFMT) != S_IFREG) return -EACCES;
        if (depth == 0) {
            struct own o;
            set_ids_mode = st.mode & (S_ISUID | S_ISGID);
            if (own_get_path(host, 1, &o) == 0) {
                if ((o.mode & OWN_MODE_SET) && (o.mode & 0777u) == (st.mode & 0777u)) set_ids_mode = o.mode & (S_ISUID | S_ISGID);
                set_uid_to = o.uid, set_gid_to = o.gid;
            }
        }
        r = sys(NR_faccessat, AT_FDCWD, host, X_OK, 0);
        if (r < 0) return r;
        /* An execute-only program (Fedora ships sudo as 4111): every file is the app's, and the
         * app must read a program to start it (its head here, its segments in the loader), so
         * the owner gets read permission, for good (the guest then sees 4511). */
        if (st.uid == cfg.real_uid && !(st.mode & 0400) &&
            sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 07777) | 0400, 0) == -EPERM)
            sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 0777) | 0400, 0);
        long fd = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) return fd;
        char* h = heads[depth];
        long n = sys(NR_pread64, fd, h, sizeof(heads[0]) - 1, 0);
        sys(NR_close, fd, 0, 0, 0);
        if (n < 0) return n;
        h[n] = 0;
        if (n >= 20 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
            if (h[4] != 2 /* ELFCLASS64 */ || *(uint16_t*) (h + 18) != 183 /* EM_AARCH64 */) return -ENOEXEC;
            break;
        }
        char *interpreter, *argument;
        if (!shebang(h, n, &interpreter, &argument)) return -ENOEXEC;
        if (depth == 3) return -ELOOP;
        const char* rest[12];
        int rest_count = head_count - 1;
        memcpy(rest, head + 1, rest_count * sizeof(*rest));
        head_count = 0;
        head[head_count++] = interpreter;
        if (argument) head[head_count++] = argument;
        head[head_count++] = file;
        memcpy(head + head_count, rest, rest_count * sizeof(*rest));
        head_count += rest_count;
        file = interpreter;
        flags &= ~AT_SYMLINK_NOFOLLOW;
        r = guest_absolute(AT_FDCWD, interpreter, guest);
        if (r < 0) return r;
        set_ids_mode = 0;
    }

    long argc = 0, envc = 0;
    while (argv != 0 && argv[argc] != 0) argc++;
    while (envp != 0 && envp[envc] != 0) envc++;

    long words = head_count + argc + envc + 3;
    long state_size = 3 * PATH_MAX + MAX_BINDS * 800;
    long size = words * 8 + state_size;
    char** block = map(size);
    if (block == 0) return -ENOMEM;
    char* state = (char*) (block + words);
    memcpy(state, "BURROW=", 7);
    /* Set-user-ID and set-group-ID programs (sudo, su): every file is the
     * app's, shown as root's to root, so they take root's ids. The old ids
     * come back if the execve() fails. */
    uint32_t old_ids[ID_COUNT];
    for (int i = 0; i < ID_COUNT; i++) old_ids[i] = id(i);
    if (set_ids_mode & S_ISUID) set_id(EUID, set_uid_to), set_id(SUID, set_uid_to), set_id(FSUID, set_uid_to);
    if (set_ids_mode & S_ISGID) set_id(EGID, set_gid_to), set_id(SGID, set_gid_to), set_id(FSGID, set_gid_to);
    cfg.traced = traceme_tid != 0 && traceme_tid == sys(NR_gettid, 0, 0, 0, 0);
    /* Without PROT_BTI: Wine's programs, and any program started with BURROW_NO_BTI=1 in its environment.
     * Not inherited by what Wine starts, only by a fork() without execve(). */
    int old_no_bti = __atomic_load_n(&cfg.no_bti, __ATOMIC_RELAXED);
    int no_bti = wine_program(resolved) || wine_program(guest);
    for (long i = 0; i < envc && !no_bti; i++) no_bti = same(envp[i], "BURROW_NO_BTI=1");
    __atomic_store_n(&cfg.no_bti, no_bti, __ATOMIC_RELAXED);
    r = encode_config(state + 7, state_size - 7, resolved, host, name);
    __atomic_store_n(&cfg.no_bti, old_no_bti, __ATOMIC_RELAXED);
    cfg.traced = 0;
    for (int i = 0; i < ID_COUNT; i++) set_id(i, old_ids[i]);
    if (r < 0) {
        sys(NR_munmap, block, size, 0, 0);
        return r;
    }
    char** new_argv = block;
    long a = 0;
    for (int i = 0; i < head_count; i++)
        if (head[i] != 0) new_argv[a++] = (char*) head[i];
    for (long i = 1; i < argc; i++) new_argv[a++] = argv[i];
    new_argv[a++] = 0;
    char** new_envp = new_argv + a;
    long e = 0;
    for (long i = 0; i < envc; i++)
        if (!starts_with(envp[i], "BURROW=")) new_envp[e++] = envp[i];
    new_envp[e++] = state;
    new_envp[e] = 0;
    r = sys(NR_execve, cfg.self, new_argv, new_envp, 0);
    sys(NR_munmap, block, size, 0, 0);
    return r;
}

/* Root writes into read-only directories too (Fedora's /root is 0550; real root ignores
 * directory permissions): when the fake root is refused there, the app-owned directory holding
 * @host gets u+wx for the time of the call. lend_dir() says whether it lent, unlend_dir() gives
 * the mode back. */
static int lend_dir(const char* host, char* dir, uint32_t* mode) {
    if (id(FSUID) != 0) return 0;
    long s = length_of(host);
    while (s > 0 && host[s] != '/') s--;
    if (s == 0 || s >= PATH_MAX) return 0;
    for (long i = 0; i < s; i++) dir[i] = host[i];
    dir[s] = 0;
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, dir, &st, 0) < 0 || st.uid != cfg.real_uid || (st.mode & 0300) == 0300) return 0;
    if (sys(NR_fchmodat, AT_FDCWD, dir, (st.mode & 07777) | 0300, 0) < 0) return 0;
    *mode = st.mode & 07777;
    return 1;
}
static void unlend_dir(const char* dir, uint32_t mode) { sys(NR_fchmodat, AT_FDCWD, dir, mode, 0); }

/* openat()/openat2() of @host; @a and @b are the call's third and fourth
 * arguments. Root opens files whatever their mode: when the fake root is
 * refused a file of the app's, it gets the permission it lacks for the time
 * of the open, as proot lends u+rw. */
static long open_as_root(long nr, const char* host, long flags, long a, long b) {
    if (!(flags & O_PATH) && proc_maps(host)) return proc_maps_open(host, flags);
    if (!(flags & O_PATH) && proc_status(host)) return proc_status_open(host, flags);
    if (!(flags & O_PATH) && proc_mounts(host)) return proc_mounts_open(host, flags);
    if (!(flags & O_PATH) && proc_auxv(host)) return proc_auxv_open(host, flags);
    long r = sys(nr, AT_FDCWD, host, a, b);
    if (r == -ELOOP && (flags & O_NOFOLLOW) && !(flags & O_PATH)) {
        /* A faked hard link is its file, also unfollowed (ostree's checkouts). */
        char final[PATH_MAX];
        if (l2s_file(host, final)) return open_as_root(nr, final, flags, a, b);
    }
    int proc = r == -EACCES && !(flags & O_PATH) ? proc_file(host) : -1;
    if (proc >= 0) return proc_open(proc, flags);
    if (r != -EACCES || id(FSUID) != 0 || (flags & O_PATH)) return r;
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0) {
        /* a new file in a read-only directory */
        char dir[PATH_MAX];
        uint32_t mode;
        if (!(flags & O_CREAT) || !lend_dir(host, dir, &mode)) return r;
        r = sys(nr, AT_FDCWD, host, a, b);
        unlend_dir(dir, mode);
        return r;
    }
    if (st.uid != cfg.real_uid) return r;
    uint32_t need = (flags & 3) == 0 ? 0400 : (flags & 3) == 1 ? 0200 : 0600;
    if ((st.mode & need) == need) return r;
    if (sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 07777) | need, 0) < 0) return r;
    r = sys(nr, AT_FDCWD, host, a, b);
    sys(NR_fchmodat, AT_FDCWD, host, st.mode & 07777, 0);
    return r;
}

/* A descriptor opened O_PATH | O_NOFOLLOW on a faked hard link becomes its
 * file's: the link is that file (ostree checks what it opened is no symlink). */
static long l2s_path_fd(long fd, long flags) {
    struct kstat st;
    if (fd < 0 || (flags & (O_PATH | O_NOFOLLOW)) != (O_PATH | O_NOFOLLOW)) return fd;
    if (sys(NR_fstat, fd, &st, 0, 0) < 0 || (st.mode & S_IFMT) != S_IFLNK) return fd;
    char host[PATH_MAX], final[PATH_MAX];
    if (fd_path(fd, host, PATH_MAX) <= 0) return fd;
    if (!l2s_file(host, final)) return fd;
    long r = sys(NR_openat, AT_FDCWD, final, flags, 0);
    if (r < 0) return fd;
    sys(NR_close, fd, 0, 0, 0);
    return r;
}

/* Whether the host path @host is a directory of the host's /sys that its mode
 * lets everyone read: SELinux denies apps most of them (/sys/dev, /sys/class),
 * where Linux lets anyone list them. Flatpak shares only those access() lets
 * read, and Mesa finds the GPU by the bindings below them (/sys/dev/char). */
static int readable_sysfs_dir(const char* host) {
    struct kstat st;
    if (!starts_with(host, "/sys/")) return 0;
    if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0) return 0;
    return (st.mode & S_IFMT) == S_IFDIR && (st.mode & 05) == 05;
}

/* An empty directory for a /sys directory SELinux will not open although its
 * mode lets everyone read it (readable_sysfs_dir()): access() says it is
 * readable, and a program that then cannot open it may give up for good
 * (libpci exits: Chromium's GPU process, so no WebGL). On a phone such a
 * directory (/sys/bus/pci/devices) has nothing a program could use. */
static long open_empty_dir(long flags) {
    char p[sizeof(cfg.root) + 24];
    memcpy(p, cfg.root, cfg.root_length);
    memcpy(p + cfg.root_length, "/tmp/.burrow-empty", 19);
    long how = O_RDONLY | O_DIRECTORY | (flags & O_CLOEXEC);
    long r = sys(NR_openat, AT_FDCWD, p, how, 0);
    if (r == -ENOENT) { /* the first time (or /tmp was emptied) */
        sys(NR_mkdirat, AT_FDCWD, p, 0555, 0);
        r = sys(NR_openat, AT_FDCWD, p, how, 0);
    }
    return r;
}

/* faccessat() and faccessat2(): the made-up files of /proc are readable, and
 * so are the directories of /sys as on Linux. */
static long do_access(long dirfd, const char* path, long mode, long flags) {
    char host[PATH_MAX];
    long fd, r = host_fd(dirfd, path, !(flags & AT_SYMLINK_NOFOLLOW), host, &fd);
    if (r < 0) return r;
    if (fd >= 0) {
        r = sys(NR_faccessat2, fd, "", mode, (flags & ~AT_SYMLINK_NOFOLLOW) | AT_EMPTY_PATH);
        sys(NR_close, fd, 0, 0, 0);
    } else {
        r = flags ? sys(NR_faccessat2, AT_FDCWD, host, mode, flags) : sys(NR_faccessat, AT_FDCWD, host, mode, 0);
        if (r == -EACCES && !(mode & 3 /* W_OK | X_OK */) && proc_file(host) >= 0) return 0;
    }
    if (r == -EACCES && !(mode & 2 /* W_OK */) && readable_sysfs_dir(host)) return 0;
    return r;
}

/* unshare(): namespaces pretend, as Android answers apps. A new user or
 * mount namespace lets the process mount and chroot, as its root there could
 * (bwrap's sandboxes); exec() forgets it, the mounts made stay. */
static int own_namespace;

static int may_mount(void) { return id(EUID) == 0 || own_namespace; }

static long do_unshare(long flags) {
    if (flags & (0x00020000 /* CLONE_NEWNS */ | 0x10000000 /* CLONE_NEWUSER */)) own_namespace = 1;
    return 0;
}

/* clone(CLONE_FS) without CLONE_VM: the kernel shares the working directory,
 * but the root is Burrow's, in each process's memory. The child's chroot()
 * goes to its parent through a record (record_shared_root()), which the
 * parent takes at its next trap, also after an execve() (Chromium's sandbox:
 * its helper chroot()s for the zygote, ChrootToSafeEmptyDir() for itself).
 * The call is made here without its stack, so that the child returns
 * through this handler, then on its own stack. */
static int fs_parent; /* this process is such a child */

static long do_clone(struct kucontext* uc) {
    uint64_t* x = uc->mcontext.regs;
    long r = sys6(NR_clone, (long) x[0], 0, (long) x[2], (long) x[3], (long) x[4], 0);
    if (r == 0) {
        fs_parent = 1;
        cfg.fs_child = 0;
        if (x[1] != 0) uc->mcontext.sp = x[1];
    } else if (r > 0) {
        cfg.fs_child = (int) r;
    }
    return r;
}

/* The root a child sharing it chroot()ed into, once it has. shortcut: the
 * bindings below that root are not taken; chroot()s into an empty directory
 * (Chromium's) have none. */
static void take_child_root(void) {
    char root[sizeof(cfg.root)];
    long n = take_shared_root(cfg.fs_child, root, sizeof(root));
    if (n > 0) {
        memcpy(cfg.root, root, n + 1);
        cfg.root_length = n;
        cfg.bind_count = 0;
        set_root_alias();
        pathcache_reset_local();
        cfg.fs_child = 0;
    } else if (sys(NR_kill, cfg.fs_child, 0, 0, 0) == -ESRCH) {
        cfg.fs_child = 0;
    }
}

/* The guest path @target resolved into @guest, without a trailing slash. */
static long mount_point(const char* target, char* guest) {
    char absolute[PATH_MAX], host[PATH_MAX];
    if (target == 0) return -EFAULT;
    if (target[0] == 0) return -ENOENT;
    long r = guest_absolute(AT_FDCWD, target, absolute);
    if (r >= 0) r = to_host(absolute, 1, host, guest);
    if (r < 0) return r;
    long n = length_of(guest);
    if (n > 1 && guest[n - 1] == '/') guest[--n] = 0;
    return n;
}

/* Whether the host path @host comes from the rootfs or a walked binding (also
 * one of the first root, after chroot), not from a binding left to the kernel. */
static int walked_host(const char* host) {
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        long n = b->host_length;
        if (!b->walked && starts_with(host, b->host) && (host[n] == 0 || host[n] == '/' || b->host[n - 1] == '/'))
            return 0;
    }
    return 1;
}

/* Binds the guest path @guest (@g bytes) to the host path @host (@h bytes),
 * replacing a binding of the same guest path. */
static long add_binding(const char* guest, long g, const char* host, long h, int walked) {
    if (g >= (long) sizeof(cfg.binds[0].guest) || h >= (long) sizeof(cfg.binds[0].host)) return -ENAMETOOLONG;
    int i = 0;
    while (i < cfg.bind_count && !same(cfg.binds[i].guest, guest)) i++;
    if (i == MAX_BINDS) return -ENOMEM;
    struct bind* b = &cfg.binds[i];
    memmove(b->guest, guest, g + 1);
    memmove(b->host, host, h + 1);
    b->guest_length = g;
    b->host_length = h;
    b->walked = walked;
    b->readonly = read_only_host(host); /* a bind mount of a read-only binding's files is read-only too */
    if (i == cfg.bind_count) cfg.bind_count++;
    return 0;
}

/* mount(): a bind mount becomes a binding of this process, inherited by its
 * children; the others (tmpfs, proc, remounts, propagation) pretend. A
 * recursive one takes the bindings below its source along, as the kernel
 * takes the mounts: Flatpak binds /dev and /sys whole, and the GPU's render
 * node and sysfs entries are bindings below them. */
static long do_mount(const char* source, const char* target, long flags) {
    pathcache_invalidate();
    char host[PATH_MAX], guest[PATH_MAX], from[PATH_MAX], below[PATH_MAX];
    if (!may_mount()) return -EPERM;
    if (!(flags & 4096 /* MS_BIND */) || (flags & 32 /* MS_REMOUNT */)) return 0;
    if (source == 0) return -EFAULT;
    long r = host_path(AT_FDCWD, source, 1, host);
    if (r < 0) return r;
    long g = mount_point(target, guest);
    if (g < 0) return g;
    long f = (flags & 16384 /* MS_REC */) ? mount_point(source, from) : -1;
    int n = cfg.bind_count; /* the bindings so far: binding / below itself must not copy the new one */
    r = add_binding(guest, g, host, length_of(host), walked_host(host));
    if (r < 0 || f < 0) return r;
    if (f == 1) f = 0; /* "/": every binding is below it */
    for (int i = 0; i < n; i++) {
        const struct bind* b = &cfg.binds[i];
        if (b->guest_length <= f || memcmp(b->guest, from, f) != 0 || b->guest[f] != '/') continue;
        /* Not the new root's own bindings, when it is built inside the source
         * (bwrap's below /tmp, and Flatpak binds /tmp). */
        long d = 0;
        for (long k = 0; k < g && guest[k] == b->guest[k]; k++)
            if (k > 0 && guest[k] == '/') d = k;
        if (d > f) continue;
        if (g + b->guest_length - f >= (long) sizeof(below)) return -ENAMETOOLONG;
        memcpy(below, guest, g);
        memcpy(below + g, b->guest + f, b->guest_length - f + 1);
        r = add_binding(below, g + b->guest_length - f, b->host, b->host_length, b->walked);
        if (r < 0) return r;
    }
    return 0;
}

/* umount2(): a binding made by mount() goes; anything else pretends. */
static long do_umount(const char* target) {
    pathcache_invalidate();
    char guest[PATH_MAX];
    if (!may_mount()) return -EPERM;
    long g = mount_point(target, guest);
    if (g < 0) return g;
    for (int i = 0; i < cfg.bind_count; i++) {
        if (!same(cfg.binds[i].guest, guest)) continue;
        memmove(&cfg.binds[i], &cfg.binds[i + 1], (cfg.bind_count - i - 1) * sizeof(*cfg.binds));
        cfg.bind_count--;
        break;
    }
    return 0;
}

/* mprotect() asking for PROT_EXEC or PROT_BTI.
 * - PROT_BTI (ld.so sets it on every library with the BTI note, which Debian and Ubuntu build with;
 *   glibc 2.40 and later in mmap(), earlier in mprotect())
 *   is dropped in Wine's processes only (cfg.no_bti, set at execve): the CPU raises SIGILL for a jump to code with no landing pad, and Wine's own
 *   entry points (__wine_syscall_dispatcher, __wine_unix_call_dispatcher in ntdll.so) have none, so
 *   wineboot dies in an exception loop on the first system call. The libraries lose BTI's
 *   hardening, as on a CPU without it.
 * Android refuses two kinds of PROT_EXEC to apps (EACCES, SELinux):
 * - the executable stack ld.so asks for (PT_GNU_STACK) of a library: the program would stop before
 *   main, the stack stays as it is;
 * - execute on pages of a private file mapping that were written ("execmod"): Wine maps its PE
 *   modules from the file, relocates them and then makes the code executable ("map_image_into_view
 *   failed to set 60000020 protection"). The range gets an anonymous copy of its current content
 *   that replaces it in one step (mremap), and the copy is given the protection. A shared file
 *   mapping in the range turns into private memory then. */
static long do_mprotect(const uint64_t* x) {
    uint64_t prot = __atomic_load_n(&cfg.no_bti, __ATOMIC_RELAXED) ? x[2] & ~(uint64_t) PROT_BTI : x[2];
    long r = sys(NR_mprotect, x[0], x[1], prot, 0);
    if (r != -EACCES) return r;
    uint64_t addr = x[0], len = (x[1] + 4095) & ~4095ull;
    if (!(prot & PROT_EXEC)) return r;
    if ((prot & 0x01000000) || len == 0 || (addr & 4095)) return 0;
    if ((r = sys(NR_mprotect, addr, len, PROT_READ, 0)) < 0) return r;
    long tmp = sys6(NR_mmap, 0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tmp < 0 && tmp > -4096) return tmp;
    memcpy((void*) tmp, (const void*) addr, len);
    r = sys6(NR_mremap, tmp, len, len, MREMAP_MAYMOVE | MREMAP_FIXED, addr, 0);
    if (r < 0 && r > -4096) {
        sys(NR_munmap, tmp, len, 0, 0);
        return r;
    }
    return sys(NR_mprotect, addr, len, prot, 0);
}

/* chroot(): the directory becomes the rootfs, the bindings below it stay.
 * SysV IPC stays in the first root (cfg.ipc), link2symlink's links of the
 * old one are followed by their host paths (path.c). */
static long do_chroot(const char* path) {
    pathcache_invalidate();
    char host[PATH_MAX], absolute[PATH_MAX], guest[PATH_MAX], root[sizeof(cfg.root)];
    if (!may_mount()) return -EPERM;
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    long r = guest_absolute(AT_FDCWD, path, absolute);
    if (r >= 0) r = to_host(absolute, 1, host, guest);
    if (r < 0) return r;
    long fd = sys(NR_openat, AT_FDCWD, host, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    long n;
    if (fd == -EMFILE) {
        /* No descriptor left (Chromium's sandbox helper sets RLIMIT_NOFILE to 0
         * first): the host path as it is, checked to be a directory. */
        struct kstat st;
        if ((n = sys(NR_newfstatat, AT_FDCWD, host, &st, 0)) < 0) return n;
        if ((st.mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
        n = length_of(host);
        if (n >= (long) sizeof(root) - 1) return -ENAMETOOLONG;
        memcpy(root, host, n);
    } else {
        if (fd < 0) return fd;
        n = fd_path(fd, root, sizeof(root));
        sys(NR_close, fd, 0, 0, 0);
    }
    if (n <= 0) return n < 0 ? n : -ENOENT;
    if (n == (long) sizeof(root) - 1) return -ENAMETOOLONG;
    root[n] = 0;
    long g = length_of(guest);
    if (g == 1) return 0; /* "/" */
    /* shortcut: other threads may resolve a path meanwhile; chroot() comes before them in practice. */
    int kept = 0;
    for (int i = 0; i < cfg.bind_count; i++) {
        struct bind* b = &cfg.binds[i];
        if (b->guest_length <= g || memcmp(b->guest, guest, g) != 0 || b->guest[g] != '/') continue;
        struct bind* k = &cfg.binds[kept++];
        memmove(k->host, b->host, b->host_length + 1);
        k->host_length = b->host_length;
        k->walked = b->walked;
        k->readonly = b->readonly;
        k->guest_length = b->guest_length - g;
        memmove(k->guest, b->guest + g, k->guest_length + 1);
    }
    cfg.bind_count = kept;
    memcpy(cfg.root, root, n + 1);
    cfg.root_length = n;
    set_root_alias();
    pathcache_reset_local(); /* entries are guest paths of the old root */
    pathcache_invalidate();
    record_root();
    if (fs_parent) record_shared_root();
    return 0;
}

/* listxattr() results without the owner store's own attribute. @r: the list's size or -errno. */
static long strip_own_name(char* list, long r, long size) {
    if (r <= 0 || size == 0 || list == 0) return r;
    long n = sizeof(OWN_XATTR);
    for (long at = 0; at < r;) {
        long len = length_of(list + at) + 1;
        if (len == n && same(list + at, OWN_XATTR)) {
            memmove(list + at, list + at + len, r - at - len);
            return r - len;
        }
        at += len;
    }
    return r;
}

/* listxattr()/flistxattr() with a size probe (size 0): the real list, less the store's name. */
static long list_xattr(long nr, long target, char* list, long size) {
    char tmp[8192];
    long r = sys6(nr, target, (long) (size ? list : tmp), size ? size : (long) sizeof(tmp), 0, 0, 0);
    if (size == 0 && r == -ERANGE) return sys6(nr, target, 0, 0, 0, 0, 0); /* too long to filter: as is */
    return strip_own_name(size ? list : tmp, r, 1);
}

/* -- Dispatch ------------------------------------------------------------------------------- */

static long emulate(long nr, const uint64_t* x) {
    long dirfd = (long) (int) x[0];
    const char* path = (const char*) x[1];
    switch (nr) {
    case NR_openat: {
        long flags = (long) x[2];
        /* An O_TMPFILE file gets its name from linkat(), which Android
         * refuses: say it is unsupported, so programs (Qt's QTemporaryFile,
         * glibc's tmpfile()) fall back to a named file. */
        if (flags & 020000000 /* __O_TMPFILE */) return -95 /* EOPNOTSUPP */;
        int stamp = (flags & O_CREAT) && id(FSUID) != 0, existed = 0;
        if (stamp) { /* a non-root creator: is the file new? */
            char h[PATH_MAX];
            struct kstat st;
            existed = host_path(dirfd, path, 1, h) < 0 || sys(NR_newfstatat, AT_FDCWD, (long) h, (long) &st, 0) == 0;
        }
        long r = open_direct(dirfd, path, flags, (long) x[3]);
        if (r != -ELOOP && r != -EINVAL && r != -EACCES) return stamp && !existed ? own_stamp_fd(l2s_path_fd(r, flags)) : l2s_path_fd(r, flags);
        int follow = !(flags & O_NOFOLLOW) && (flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL);
        char host[PATH_MAX];
        r = host_path(dirfd, path, follow, host);
        if (r < 0) return r;
        if ((r = ro_open(host, flags)) < 0) return r;
        r = l2s_path_fd(open_as_root(NR_openat, host, flags, flags, (long) x[3]), flags);
        if (r == -EACCES && (flags & 3) == O_RDONLY && !(flags & O_CREAT) && readable_sysfs_dir(host)) return open_empty_dir(flags);
        return stamp && !existed ? own_stamp_fd(r) : r;
    }
    case NR_openat2: {
        const struct open_how* how = (const struct open_how*) x[2];
        /* RESOLVE_BENEATH and the like would apply to the host path (EXDEV for
         * an absolute one): say openat2 is missing, and callers (libglnx's,
         * Flatpak's) confine the path themselves. */
        if (how == 0) return -EFAULT;
        if (how->resolve != 0) return -ENOSYS;
        int follow = !(how->flags & O_NOFOLLOW) && (how->flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL);
        ON_HOST_RO(follow, ro_open(host, (long) how->flags), l2s_path_fd(open_as_root(NR_openat2, host, (long) how->flags, (long) how, (long) x[3]),
                                    (long) how->flags));
    }
    case NR_getdents64: {
        long r;
        do r = sys(NR_getdents64, x[0], x[1], x[2], 0);
        while (r > 0 && (r = l2s_dirents(dirfd, (char*) x[1], r)) == 0); /* 0 would end the listing */
        return r;
    }
    case NR_newfstatat: return do_stat(dirfd, path, (struct kstat*) x[2], (long) x[3]);
    case NR_fstat: {
        long r = sys(NR_fstat, x[0], x[1], 0, 0);
        struct own o;
        if (r == 0 && own_get_fd(x[0], &o) == 0) fake_stat_own(r, (struct kstat*) x[1], &o);
        else fake_stat(r, (struct kstat*) x[1]);
        return r;
    }
    case NR_statx: return do_statx(dirfd, path, (long) x[2], (long) x[3], (struct kstatx*) x[4]);
    case NR_faccessat: return do_access(dirfd, path, (long) x[2], 0);
    case NR_faccessat2:
        if (empty(path) && (x[3] & AT_EMPTY_PATH)) return sys(NR_faccessat2, x[0], path, x[2], x[3]);
        return do_access(dirfd, path, (long) x[2], (long) x[3]);
    case NR_readlinkat: return do_readlink(dirfd, path, (char*) x[2], (long) x[3]);
    case NR_getcwd: return do_getcwd((char*) x[0], (long) x[1]);
    case NR_chdir: {
        dirfd = AT_FDCWD;
        path = (const char*) x[0];
        ON_HOST(1, sys(NR_chdir, host, 0, 0, 0));
    }
    case NR_chroot: return do_chroot((const char*) x[0]);
    case NR_mount: return do_mount((const char*) x[0], (const char*) x[1], (long) x[3]);
    case NR_umount2: return do_umount((const char*) x[0]);
    case NR_unshare: return do_unshare((long) x[0]);
    case NR_ptrace: return do_traceme();
    case NR_seccomp:
    case NR_prctl: return do_guest_filter(nr, x);
    case NR_mprotect: return do_mprotect(x);
    case NR_mmap: return sys6(NR_mmap, x[0], x[1], __atomic_load_n(&cfg.no_bti, __ATOMIC_RELAXED) ? x[2] & ~(uint64_t) PROT_BTI : x[2], x[3], x[4], x[5]);
    case NR_mkdirat: {
        char host[PATH_MAX];
        long r = host_path(dirfd, path, 0, host);
        if (r < 0 || (r = ro_guard(host)) < 0) return r;
        r = sys(NR_mkdirat, AT_FDCWD, host, x[2], 0);
        char dir[PATH_MAX];
        uint32_t mode;
        if (r == -EACCES && lend_dir(host, dir, &mode)) {
            r = sys(NR_mkdirat, AT_FDCWD, host, x[2], 0);
            unlend_dir(dir, mode);
        }
        if (r == 0) own_stamp_path(host);
        return r;
    }
    case NR_mknodat: ON_HOST_RO(0, ro_guard(host), sys(NR_mknodat, AT_FDCWD, host, x[2], x[3]));
    case NR_unlinkat: {
        char host[PATH_MAX];
        long r = host_path(dirfd, path, 0, host);
        if (r < 0 || (r = ro_guard(host)) < 0) return r;
        if (!(x[2] & 0x200 /* AT_REMOVEDIR */) && (r = l2s_unlinked(host)) < 0) return r;
        if (x[2] & 0x200) pathcache_invalidate(); /* a directory goes away: before and after */
        r = sys(NR_unlinkat, AT_FDCWD, host, x[2], 0);
        if (x[2] & 0x200) pathcache_invalidate();
        if (r != -EACCES || id(FSUID) != 0) return r;
        /* Root removes from read-only directories too (rm -rf of Go's module cache). */
        long slash = length_of(host);
        while (slash > 0 && host[slash] != '/') slash--;
        if (slash == 0) return r;
        host[slash] = 0;
        struct kstat st;
        if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0 || st.uid != cfg.real_uid || (st.mode & 0300) == 0300 ||
            sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 07777) | 0300, 0) < 0)
            return r;
        host[slash] = '/';
        r = sys(NR_unlinkat, AT_FDCWD, host, x[2], 0);
        host[slash] = 0;
        sys(NR_fchmodat, AT_FDCWD, host, st.mode & 07777, 0);
        return r;
    }
    case NR_symlinkat: {
        dirfd = (long) (int) x[1];
        path = (const char*) x[2];
        char host[PATH_MAX], dir[PATH_MAX];
        uint32_t mode;
        long r = host_path(dirfd, path, 0, host);
        if (r < 0 || (r = ro_guard(host)) < 0) return r;
        r = sys(NR_symlinkat, x[0], AT_FDCWD, host, 0);
        if (r == -EACCES && lend_dir(host, dir, &mode)) {
            r = sys(NR_symlinkat, x[0], AT_FDCWD, host, 0);
            unlend_dir(dir, mode);
        }
        return r;
    }
    case NR_linkat: {
        char from[PATH_MAX], to[PATH_MAX];
        long flags = (long) x[4];
        long r;
        if (empty(path) && (flags & AT_EMPTY_PATH)) {
            /* The file of descriptor @dirfd, by its host path: an unnamed one (O_TMPFILE) cannot get a name. */
            r = fd_path(dirfd, from, PATH_MAX);
            if (r < 0) return r == -ENOENT ? -EBADF : r;
            if (from[0] != '/' || (r > 10 && same(from + r - 10, " (deleted)"))) return -ENOENT;
            flags = 0;
        } else {
            r = host_path(dirfd, path, (flags & AT_SYMLINK_FOLLOW) != 0, from);
        }
        if (r < 0) return r;
        r = host_path((long) (int) x[2], (const char*) x[3], 0, to);
        if (r < 0 || (r = ro_guard(to)) < 0) return r;
        /* A second name for a file of a read-only binding would be a writable one (and the
         * link2symlink fallback would move the file): the caller copies instead. */
        if (read_only_host(from)) return -EXDEV;
        r = sys6(NR_linkat, AT_FDCWD, (long) from, AT_FDCWD, (long) to, flags & AT_SYMLINK_FOLLOW, 0);
        return r == -EACCES || r == -EPERM ? l2s_link(from, to) : r;
    }
    case NR_renameat:
    case NR_renameat2: {
        char from[PATH_MAX];
        long r = host_path(dirfd, path, 0, from);
        if (r < 0 || (r = ro_guard(from)) < 0) return r;
        char to[PATH_MAX];
        r = host_path((long) (int) x[2], (const char*) x[3], 0, to);
        if (r < 0 || (r = ro_guard(to)) < 0) return r;
        /* A faked hard link replaced: one link less. */
        if ((r = l2s_unlinked(to)) < 0) return r;
        /* renaming a directory or a symlink, or exchanging anything, changes what paths resolve to */
        int bump = nr == NR_renameat2 && ((long) x[4] & 2 /* RENAME_EXCHANGE */);
        if (!bump) {
            struct kstat st;
            bump = sys(NR_newfstatat, AT_FDCWD, (long) from, (long) &st, AT_SYMLINK_NOFOLLOW) < 0 || (st.mode & S_IFMT) != S_IFREG;
        }
        if (bump) pathcache_invalidate();
        long rflags = nr == NR_renameat ? 0 : (long) x[4];
        r = sys6(NR_renameat2, AT_FDCWD, (long) from, AT_FDCWD, (long) to, rflags, 0);
        if (r == -EACCES) {
            char d1[PATH_MAX], d2[PATH_MAX];
            uint32_t m1 = 0, m2 = 0;
            int l1 = lend_dir(from, d1, &m1), l2 = lend_dir(to, d2, &m2);
            if (l1 || l2) r = sys6(NR_renameat2, AT_FDCWD, (long) from, AT_FDCWD, (long) to, rflags, 0);
            if (l2) unlend_dir(d2, m2);
            if (l1) unlend_dir(d1, m1);
        }
        if (bump) pathcache_invalidate();
        return r;
    }
    case NR_fchmod: return do_chmod(x[0], "", (long) x[1], AT_EMPTY_PATH);
    case NR_fchmodat: return do_chmod(dirfd, path, (long) x[2], 0);
    case NR_fchmodat2: return do_chmod(dirfd, path, (long) x[2], (long) x[3]);
    case NR_fchownat: return do_chown(dirfd, path, (long) x[2], (long) x[3], (long) x[4]);
    case NR_fchown: return do_chown(x[0], "", (long) x[1], (long) x[2], AT_EMPTY_PATH);
    case NR_utimensat:
        if (path == 0 || (empty(path) && (x[3] & AT_EMPTY_PATH))) {
            if (read_only_fd((long) x[0])) return -EROFS;
            return sys(NR_utimensat, x[0], path, x[2], x[3]);
        }
        ON_HOST_RO(!(x[3] & AT_SYMLINK_NOFOLLOW), ro_guard(host), sys(NR_utimensat, AT_FDCWD, host, x[2], x[3]));
    case NR_statfs:
    case NR_fstatfs: return do_statfs(nr, x);
    case NR_truncate:
    case NR_setxattr:
    case NR_lsetxattr:
    case NR_getxattr:
    case NR_lgetxattr:
    case NR_listxattr:
    case NR_llistxattr:
    case NR_removexattr:
    case NR_lremovexattr: {
        int follow = nr != NR_lsetxattr && nr != NR_lgetxattr && nr != NR_llistxattr && nr != NR_lremovexattr;
        if (nr != NR_truncate && nr != NR_listxattr && nr != NR_llistxattr && x[1] && same((const char*) x[1], OWN_XATTR))
            return nr == NR_getxattr || nr == NR_lgetxattr ? -ENODATA : -EPERM;
        dirfd = AT_FDCWD;
        path = (const char*) x[0];
        if (nr == NR_listxattr || nr == NR_llistxattr) ON_HOST(follow, list_xattr(nr, (long) host, (char*) x[1], (long) x[2]));
        int changes = nr == NR_truncate || nr == NR_setxattr || nr == NR_lsetxattr || nr == NR_removexattr || nr == NR_lremovexattr;
        ON_HOST_RO(follow, changes ? ro_guard(host) : 0, sys6(nr, (long) host, (long) x[1], (long) x[2], (long) x[3], (long) x[4], 0));
    }
    case NR_fgetxattr:
    case NR_fsetxattr:
    case NR_fremovexattr:
        if (x[1] && same((const char*) x[1], OWN_XATTR)) return nr == NR_fgetxattr ? -ENODATA : -EPERM;
        if (nr != NR_fgetxattr && read_only_fd((long) x[0])) return -EROFS;
        return sys6(nr, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], 0);
    case NR_flistxattr: {
        return list_xattr(nr, (long) x[0], (char*) x[1], (long) x[2]);
    }
    case NR_inotify_add_watch:
        dirfd = AT_FDCWD;
        ON_HOST(!(x[2] & IN_DONT_FOLLOW), sys(NR_inotify_add_watch, x[0], host, x[2], 0));
    case NR_bind:
    case NR_connect: return netlink_bind((long) x[0], do_socket_path(nr, (long) x[0], (const char*) x[1], (long) x[2]));
    case NR_sendmsg: {
        const struct kmsghdr* m = (const struct kmsghdr*) x[1];
        long r = do_sendmsg((long) x[0], m, (long) x[2]);
        return r >= 0 || m == 0 ? r : netlink_sendmsg((long) x[0], m->iov, m->iovlen, r);
    }
    case NR_sendto: return netlink_send((long) x[0], (const void*) x[1], (long) x[2], do_sendto(x));
    case NR_recvfrom: return do_recvfrom(x);
    case NR_getsockname:
    case NR_getpeername: return do_sockname(nr, (long) x[0], (char*) x[1], (uint32_t*) x[2]);
    case NR_getsockopt: return do_peercred(x);
    case NR_ioctl: return do_drm_version(x);
    case NR_socket: return do_uevent_socket(x);
    case NR_shmget:
    case NR_shmctl:
    case NR_shmat:
    case NR_shmdt:
    case NR_semget:
    case NR_semctl:
    case NR_semtimedop:
    case NR_semop:
    case NR_msgget:
    case NR_msgctl:
    case NR_msgrcv:
    case NR_msgsnd: return emulate_sysv(nr, x);
    case NR_execve:
        return emulate_execve(AT_FDCWD, (const char*) x[0], (char* const*) x[1], (char* const*) x[2], 0);
    case NR_execveat:
        return emulate_execve(dirfd, path, (char* const*) x[2], (char* const*) x[3], (long) x[4]);

    case NR_capget: {
        /* Capabilities (Kestrel): the guest's root shows them all, other users none; daemons that
         * drop them (dbus-daemon, sshd) see the drop succeed. Nothing reaches the kernel. */
        uint32_t* header = (uint32_t*) x[0]; /* version, pid */
        uint32_t* data = (uint32_t*) x[1];   /* 2 x {effective, permitted, inheritable} for v3 */
        if (header == 0) return -EFAULT;
        int words = header[0] == 0x19980330 /* v1 */ ? 1 : 2;
        if (header[0] != 0x20080522 /* _LINUX_CAPABILITY_VERSION_3 */ && header[0] != 0x20071026 /* v2 */ && words == 2) {
            header[0] = 0x20080522;
            return data ? -EINVAL : 0;
        }
        int32_t pid = (int32_t) header[1];
        if (pid < 0) return -EINVAL;
        if (pid != 0 && pid != sys(NR_getpid, 0, 0, 0, 0) && sys(NR_kill, pid, 0, 0, 0) == -ESRCH) return -ESRCH;
        if (data) {
            /* another process's: its ids are not known here, so the caller's rule is shown */
            uint32_t all = id(EUID) == 0 ? 0xffffffffu : 0;
            for (int i = 0; i < words; i++) data[i * 3] = all, data[i * 3 + 1] = all, data[i * 3 + 2] = 0;
            if (words == 2) data[3] &= 0x1ff, data[4] &= 0x1ff; /* capabilities 32..40 */
        }
        return 0;
    }
    case NR_capset: {
        uint32_t* header = (uint32_t*) x[0];
        if (header == 0) return -EFAULT;
        if (header[0] != 0x20080522 && header[0] != 0x20071026 && header[0] != 0x19980330) return -EINVAL;
        if (header[1] != 0 && (int32_t) header[1] != (int32_t) sys(NR_getpid, 0, 0, 0, 0)) return -EPERM;
        /* No state is kept: a later capget() shows the full set again, and any set is accepted
         * (a daemon that switches users keeping some capabilities, as dbus-daemon does, calls
         * this as non-root). Guest users are not a security boundary (plan, Constraints). */
        return 0;
    }
    case NR_getuid: return id(RUID);
    case NR_geteuid: return id(EUID);
    case NR_getgid: return id(RGID);
    case NR_getegid: return id(EGID);
    case NR_getresuid: return get_ids(RUID, (uint32_t*) x[0], (uint32_t*) x[1], (uint32_t*) x[2]);
    case NR_getresgid: return get_ids(RGID, (uint32_t*) x[0], (uint32_t*) x[1], (uint32_t*) x[2]);
    case NR_setuid: return set_ids(RUID, (uint32_t) x[0], 0, 0, 1);
    case NR_setgid: return set_ids(RGID, (uint32_t) x[0], 0, 0, 1);
    case NR_setreuid: return set_ids(RUID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) -1, 2);
    case NR_setregid: return set_ids(RGID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) -1, 2);
    case NR_setresuid: return set_ids(RUID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) x[2], 3);
    case NR_setresgid: return set_ids(RGID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) x[2], 3);
    case NR_setfsuid: return set_fs_id(RUID, (uint32_t) x[0]);
    case NR_setfsgid: return set_fs_id(RGID, (uint32_t) x[0]);
    case NR_getgroups: {
        long size = (long) (int) x[0];
        if (size == 0) return cfg.group_count;
        if (size < cfg.group_count) return -EINVAL;
        if (x[1] == 0) return -EFAULT;
        memcpy((uint32_t*) x[1], cfg.groups, cfg.group_count * sizeof(uint32_t));
        return cfg.group_count;
    }
    case NR_setgroups: {
        long size = (long) x[0];
        if (id(EUID) != 0) return -EPERM;
        /* shortcut: more groups than MAX_GROUPS fail; raise it if a program needs them. */
        if (size < 0 || size > MAX_GROUPS) return -EINVAL;
        if (size > 0 && x[1] == 0) return -EFAULT;
        memcpy(cfg.groups, (const uint32_t*) x[1], size * sizeof(uint32_t));
        cfg.group_count = (int) size;
        return 0;
    }

    case NR_uname: {
        /* Android's is "localhost": the guest's own name, as a system set up from /etc/hostname at boot. */
        long r = sys(NR_uname, x[0], 0, 0, 0);
        if (r == 0 && cfg.hostname[0]) memcpy((char*) x[0] + 65, cfg.hostname, sizeof(cfg.hostname));
        return r;
    }

    case NR_lseek:
        proc_rewind((long) x[0]);
        return sys(NR_lseek, x[0], x[1], x[2], 0);

    case NR_rt_sigaction:
        return do_sigaction((long) x[0], (const struct ksigaction*) x[1], (struct ksigaction*) x[2], (long) x[3]);
    }
    return -ENOSYS;
}

/* -- Statistics (-s) -------------------------------------------------------------------------- */

/* Per syscall, shared by all the guest's processes through a MAP_SHARED file:
 * traps, and ticks of the virtual counter in the whole handler (stack
 * switching included) and in the emulation alone. */
#define STATS_MAGIC 0x31737473776f7262ull /* "burwsts1" */
#define STATS_SYSCALLS 512
struct stats {
    uint64_t magic, frequency;
    uint64_t count[STATS_SYSCALLS], total[STATS_SYSCALLS], emulated[STATS_SYSCALLS];
};
static struct stats* stats;

static inline uint64_t ticks(void) {
    uint64_t t;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t));
    return t;
}

static void open_stats(void) {
    long fd = sys(NR_openat, AT_FDCWD, cfg.stats, 2 /* O_RDWR */ | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return;
    struct kstat st;
    if (sys(NR_fstat, fd, &st, 0, 0) == 0 && st.size < (int64_t) sizeof(struct stats))
        sys(46 /* NR_ftruncate */, fd, sizeof(struct stats), 0, 0);
    long p = sys6(NR_mmap, 0, sizeof(struct stats), PROT_READ | PROT_WRITE, 1 /* MAP_SHARED */, fd, 0);
    sys(NR_close, fd, 0, 0, 0);
    if (p < 0 && p > -4096) return;
    stats = (struct stats*) p;
    if (stats->magic != STATS_MAGIC) {
        uint64_t frequency;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
        stats->frequency = frequency;
        stats->magic = STATS_MAGIC;
    }
}

uint64_t stats_start(void) {
    return stats ? ticks() : 0;
}

void stats_step(int step, uint64_t start) {
    if (stats == 0) return;
    __atomic_fetch_add(&stats->count[step], 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&stats->total[step], ticks() - start, __ATOMIC_RELAXED);
}

static void count(const struct ksiginfo* info, uint64_t* sums, uint64_t start) {
    if (info->code != SYS_SECCOMP || info->errno_ != TRAP_DATA || (unsigned) info->syscall >= STATS_SYSCALLS) return;
    if (sums == stats->total) __atomic_fetch_add(&stats->count[info->syscall], 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&sums[info->syscall], ticks() - start, __ATOMIC_RELAXED);
}

/* -- Handler ------------------------------------------------------------------------------- */

static void on_trap(struct ksiginfo* info, struct kucontext* uc) {
    uint64_t* x = uc->mcontext.regs;
    if (cfg.fs_child != 0) take_child_root();
    /* A guest filter that denies this call (ERRNO) is obeyed before anything is emulated: Chromium's sandbox
     * checks that fchmod(-1, 07777) fails as its policy says, and a renderer that sees another errno aborts.
     * The call is repeated from the probe, which our filter answers with an errno of its own: what comes back is
     * then the guest's filters' verdict, or ours (PROBE_ERRNO) if they allow the call. Their traps never get
     * here (they are the guest's own, see foreign()), and a kill does not return. */
    if (__atomic_load_n(&cfg.guest_filtered, __ATOMIC_RELAXED)) {
        long v = probe6(info->syscall, x);
        if (v != -PROBE_ERRNO) {
            x[0] = (uint64_t) v;
            return;
        }
    }
    if (info->syscall == NR_clone) {
        x[0] = (uint64_t) do_clone(uc);
        return;
    }
    if (info->syscall == NR_rt_sigprocmask) {
        x[0] = (uint64_t) do_sigprocmask(&uc->sigmask, (long) x[0], (const uint64_t*) x[1], (uint64_t*) x[2],
                                         (long) x[3]);
        return;
    }
    if (info->syscall == NR_rt_sigreturn) {
        /* The mask in the frame comes back with no rt_sigprocmask(): a handler
         * may have put SIGSYS there (FEX's, with the x86 guest's mask). The
         * frame (siginfo, then the ucontext) is at sp; the real call goes
         * from the gadget once this handler returns. */
        ((struct kucontext*) (uc->mcontext.sp + 128))->sigmask &= ~SIGSYS_BIT;
        uc->mcontext.pc = (uintptr_t) burrow_gadget;
        return;
    }
    x[0] = (uint64_t) emulate(info->syscall, x);
}

static __attribute__((noinline)) void on_sigsys(int sig, struct ksiginfo* info, struct kucontext* uc) {
    if (info->code != SYS_SECCOMP || info->errno_ != TRAP_DATA) {
        foreign(sig, info, uc);
        return;
    }
    uint64_t start = stats ? ticks() : 0;
    on_trap(info, uc);
    if (stats) count(info, stats->emulated, start);
}

/* The handler needs tens of KB, more than the signal stacks guests set up
 * (Firefox's threads: 20 KB, Go's: 32 KB), so it runs on one of these, owned
 * by a thread id. When the thread has a sigaltstack, the stack is also its
 * sigaltstack meanwhile: a nested signal (a trapped syscall in a guest SIGSYS
 * handler) must go below it, not at the top of the guest's sigaltstack, where
 * the outer frame lives. Without one, a nested signal goes below it anyway. */
#define STACKS 32
#define STACK_SIZE (128 * 1024)
static char* stacks;
static int stack_owner[STACKS];

struct kstack {
    void* sp;
    int flags;
    size_t size;
};
static struct kstack saved_stack[STACKS]; /* the guest's sigaltstack, per stack of ours in use */
static char stack_switched[STACKS];

extern void burrow_call_on_stack(long a, void* b, void* c, void* fn, char* top);

static int claim_stack(void) {
    int tid = (int) sys(NR_gettid, 0, 0, 0, 0);
    for (int pass = 0; stacks != 0 && pass < 2; pass++) {
        for (int i = 0; i < STACKS; i++) {
            int free_slot = 0;
            if (__atomic_compare_exchange_n(&stack_owner[i], &free_slot, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return i;
        }
        /* Owners gone: the parent's threads after a fork, a vfork child that
         * exec'd. shortcut: a live CLONE_VM child of another process can lose
         * its stack here, only when all are taken. */
        long pid = sys(NR_getpid, 0, 0, 0, 0);
        for (int i = 0; i < STACKS; i++) {
            int owner = __atomic_load_n(&stack_owner[i], __ATOMIC_RELAXED);
            if (owner != 0 && sys(NR_tgkill, pid, owner, 0, 0) == -ESRCH)
                __atomic_compare_exchange_n(&stack_owner[i], &owner, 0, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        }
    }
    return -1;
}

/* On a stack of ours, which becomes the sigaltstack. Changed from here: the
 * kernel refuses to change it from the sigaltstack in use, where SA_ONSTACK
 * may have put the handler. Signals are blocked until then (sa_mask): one
 * would go at the top of the guest's sigaltstack, over our frame. Then the
 * guest's mask is back, so that they interrupt a blocking emulated call. */
static void on_our_stack(int sig, struct ksiginfo* info, struct kucontext* uc) {
    int slot = (int) (((char*) __builtin_frame_address(0) - stacks) / STACK_SIZE);
    struct kstack ours = {stacks + (long) slot * STACK_SIZE, 0, STACK_SIZE};
    stack_switched[slot] = !(uc->stack.flags & 2 /* SS_DISABLE */) &&
                           sys(NR_sigaltstack, &ours, &saved_stack[slot], 0, 0) == 0;
    sys(NR_rt_sigprocmask, SIG_SETMASK, &uc->sigmask, 0, 8);
    on_sigsys(sig, info, uc);
}

static void on_sigsys_entry(int sig, struct ksiginfo* info, struct kucontext* uc) {
    uint64_t start = stats ? ticks() : 0;
    int slot = claim_stack();
    if (slot < 0) {
        sys(NR_rt_sigprocmask, SIG_SETMASK, &uc->sigmask, 0, 8);
        on_sigsys(sig, info, uc);
    } else {
        burrow_call_on_stack(sig, info, uc, (void*) on_our_stack, stacks + (long) (slot + 1) * STACK_SIZE);
        /* Back off our stack, where the kernel lets the guest's come back. */
        if (stack_switched[slot]) {
            saved_stack[slot].flags &= ~1; /* SS_ONSTACK, reported only */
            sys(NR_sigaltstack, &saved_stack[slot], 0, 0, 0);
        }
        __atomic_store_n(&stack_owner[slot], 0, __ATOMIC_RELEASE);
    }
    if (stats) count(info, stats->total, start);
}

void install_handler(void) {
    long p = sys6(NR_mmap, 0, (long) STACKS * STACK_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    stacks = p < 0 && p > -4096 ? 0 : (char*) p;
    if (cfg.stats[0]) open_stats();
    /* SA_ONSTACK: the kernel's frame goes on the guest's sigaltstack if it has
     * one, not on the thread's stack, which may be a goroutine's few KB. The
     * handler itself moves to a stack of ours, all signals blocked meanwhile
     * but SIGSYS (a blocked trap would kill). */
    struct ksigaction act = {(uintptr_t) on_sigsys_entry, SA_SIGINFO | SA_NODEFER | SA_ONSTACK | SA_RESTORER,
                             (uintptr_t) burrow_sigreturn, ~(1ull << (SIGSYS - 1))};
    if (sys(NR_rt_sigaction, SIGSYS, &act, 0, 8) < 0) die("cannot install the SIGSYS handler", 0);
}
