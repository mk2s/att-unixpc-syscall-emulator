//! AT&T UNIX PC (3B1) ABI data — the single isolated place where the guest
//! ABI is described. Syscall numbers were extracted from the machine's own
//! `/tmp/upc/lib/libc.a` (see docs/abi.md and tools/extract_syscalls.py).
//! errno / signal values and struct sizes come from the machine headers in
//! `/tmp/upc/usr/include`.

const std = @import("std");

/// Guest is big-endian MC68010.
pub const endian: std.builtin.Endian = .big;

// ---------------------------------------------------------------------------
// Address space (sys/param.h)
// ---------------------------------------------------------------------------
pub const VUSER_START: u32 = 0x80000; // base of user text/data
pub const VUSER_END: u32 = 0x300000; // end of user region
pub const USRSTACK: u32 = 0x300000; // stack top (grows down)
pub const SHLIB_START: u32 = 0x300000; // shared library region base
pub const SHLIB_END: u32 = 0x380000; // shared library region end
pub const NBPC: u32 = 4096; // bytes per page (click)
pub const BPCSHIFT: u5 = 12;
pub const NCARGS: u32 = 5120; // max bytes in exec arg list
pub const NOFILE: u32 = 80; // max open files per process
pub const SSIZE: u32 = 2048; // initial stack size

// ---------------------------------------------------------------------------
// Syscall trap convention
// ---------------------------------------------------------------------------
/// Kernel SYSCALL trap vector (sys/trap.h SYSCALL=32). This is m68k `trap #0`.
pub const SYSCALL_TRAP_VECTOR: u32 = 32;
/// The trap number used by the `trap` instruction for syscalls.
pub const SYSCALL_TRAP_NUMBER: u4 = 0;

// ---------------------------------------------------------------------------
// Syscall numbers (verified from libc.a — see docs/abi.md)
// ---------------------------------------------------------------------------
pub const Syscall = enum(u16) {
    exit = 1,
    fork = 2,
    read = 3,
    write = 4,
    open = 5,
    close = 6,
    wait = 7,
    creat = 8,
    link = 9,
    unlink = 10,
    chdir = 12,
    time = 13,
    mknod = 14,
    chmod = 15,
    chown = 16,
    sbrk = 17,
    stat = 18,
    lseek = 19,
    getpid = 20, // ppid returned in D1
    mount = 21,
    umount = 22,
    setuid = 23,
    getuid = 24, // euid returned in D1
    stime = 25,
    ptrace = 26,
    alarm = 27,
    fstat = 28,
    pause = 29,
    utime = 30,
    stty = 31,
    gtty = 32,
    access = 33,
    nice = 34,
    sync = 36,
    kill = 37,
    setpgrp = 39,
    dup = 41,
    pipe = 42, // read fd in D0, write fd in D1
    times = 43,
    profil = 44,
    plock = 45,
    setgid = 46,
    getgid = 47, // egid returned in D1
    signal = 48,
    msgsys = 49,
    acct = 51,
    shmsys = 52,
    semsys = 53,
    ioctl = 54,
    utssys = 57,
    execve = 59,
    umask = 60,
    chroot = 61,
    fcntl = 62,
    ulimit = 63,
    locking = 67,
    syslocal = 68,
    openi = 69,
    swrite = 70,
    _,

    pub fn name(self: Syscall) []const u8 {
        return switch (self) {
            .exit => "exit",
            .fork => "fork",
            .read => "read",
            .write => "write",
            .open => "open",
            .close => "close",
            .wait => "wait",
            .creat => "creat",
            .link => "link",
            .unlink => "unlink",
            .chdir => "chdir",
            .time => "time",
            .mknod => "mknod",
            .chmod => "chmod",
            .chown => "chown",
            .sbrk => "sbrk",
            .stat => "stat",
            .lseek => "lseek",
            .getpid => "getpid",
            .mount => "mount",
            .umount => "umount",
            .setuid => "setuid",
            .getuid => "getuid",
            .stime => "stime",
            .ptrace => "ptrace",
            .alarm => "alarm",
            .fstat => "fstat",
            .pause => "pause",
            .utime => "utime",
            .stty => "stty",
            .gtty => "gtty",
            .access => "access",
            .nice => "nice",
            .sync => "sync",
            .kill => "kill",
            .setpgrp => "setpgrp",
            .dup => "dup",
            .pipe => "pipe",
            .times => "times",
            .profil => "profil",
            .plock => "plock",
            .setgid => "setgid",
            .getgid => "getgid",
            .signal => "signal",
            .msgsys => "msgsys",
            .acct => "acct",
            .shmsys => "shmsys",
            .semsys => "semsys",
            .ioctl => "ioctl",
            .utssys => "utssys",
            .execve => "execve",
            .umask => "umask",
            .chroot => "chroot",
            .fcntl => "fcntl",
            .ulimit => "ulimit",
            .locking => "locking",
            .syslocal => "syslocal",
            .openi => "openi",
            .swrite => "swrite",
            _ => "UNKNOWN",
        };
    }
};

// ---------------------------------------------------------------------------
// COFF magics (filehdr.h) — the file-header f_magic holds the 68k magic.
// ---------------------------------------------------------------------------
pub const MC68KWRMAGIC: u16 = 0o520; // 0x0150 writable text
pub const MC68KROMAGIC: u16 = 0o521; // 0x0151 read-only text
pub const MC68KPGMAGIC: u16 = 0o522; // 0x0152 demand paged

pub fn isMc68kMagic(m: u16) bool {
    return m == MC68KWRMAGIC or m == MC68KROMAGIC or m == MC68KPGMAGIC;
}

// COFF section flags (scnhdr.h)
pub const STYP_TEXT: u32 = 0x20;
pub const STYP_DATA: u32 = 0x40;
pub const STYP_BSS: u32 = 0x80;

// ---------------------------------------------------------------------------
// errno values (sys/errno.h) — guest side
// ---------------------------------------------------------------------------
pub const Errno = enum(u16) {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    ENOMSG = 35,
    EIDRM = 36,
};

/// Translate a host std.posix errno-ish tag to a guest errno value.
/// Extend as syscalls are implemented; unknowns map to EINVAL.
pub fn guestErrnoFromPosix(e: anyerror) u16 {
    return switch (e) {
        error.AccessDenied, error.PermissionDenied => @intFromEnum(Errno.EACCES),
        error.FileNotFound => @intFromEnum(Errno.ENOENT),
        error.IsDir => @intFromEnum(Errno.EISDIR),
        error.NotDir => @intFromEnum(Errno.ENOTDIR),
        error.PathAlreadyExists => @intFromEnum(Errno.EEXIST),
        error.FileTooBig => @intFromEnum(Errno.EFBIG),
        error.NoSpaceLeft => @intFromEnum(Errno.ENOSPC),
        error.BadPathName, error.NameTooLong => @intFromEnum(Errno.ENOENT),
        error.SystemResources, error.OutOfMemory => @intFromEnum(Errno.ENOMEM),
        error.InputOutput => @intFromEnum(Errno.EIO),
        else => @intFromEnum(Errno.EINVAL),
    };
}

// ---------------------------------------------------------------------------
// Signals (sys/signal.h)
// ---------------------------------------------------------------------------
pub const Signal = enum(u8) {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGIOT = 6,
    SIGEMT = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGBUS = 10,
    SIGSEGV = 11,
    SIGSYS = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGUSR1 = 16,
    SIGUSR2 = 17,
    SIGCLD = 18,
    SIGPWR = 19,
    SIGWIND = 20,
    SIGPHONE = 21,
};
pub const NSIG: u8 = 32;
pub const SIG_DFL: u32 = 0;
pub const SIG_IGN: u32 = 1;

// ---------------------------------------------------------------------------
// fcntl / open flags (fcntl.h)
// ---------------------------------------------------------------------------
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_NDELAY: u32 = 0o4;
pub const O_APPEND: u32 = 0o10;
pub const O_CREAT: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_EXCL: u32 = 0o2000;

// ---------------------------------------------------------------------------
// struct sizes (guest layout, big-endian)
// ---------------------------------------------------------------------------
/// struct stat: st_dev(2) st_ino(2) st_mode(2) st_nlink(2) st_uid(2)
///              st_gid(2) st_rdev(2)  = 7 shorts = 14 bytes, then
///              st_size(4) st_atime(4) st_mtime(4) st_ctime(4) = 16 bytes.
/// Total = 30 bytes.
pub const STAT_SIZE: u32 = (7 * 2) + (4 * 4);
/// struct direct: d_ino(2) + d_name[14] = 16 bytes.
pub const DIRECT_SIZE: u32 = 16;
pub const DIRSIZ: u32 = 14;

// ---------------------------------------------------------------------------
// 3B1 disk / Volume Home Block (from <sys/gdioctl.h>, <sys/gdisk.h>)
// ---------------------------------------------------------------------------
/// GDGETA: get the gdisk structure. GDIOC = ('G'<<8) = 0x4700; GDGETA = |1.
pub const GDGETA: u32 = 0x4701;
/// VHB magic ("UQVQ", big-endian 0x55515651).
pub const VHBMAGIC: u32 = 0x55515651;
/// gdctl.status bits: F_CT_FMT (valid VHB read) and F_READY (drive ready).
pub const VHB_STATUS_VALID: u32 = 0x0002; // VALID_VHB / F_CT_FMT
pub const VHB_STATUS_READY: u32 = 0x0004; // DRV_READY / F_READY
/// gdctl.dsktyp disk-type codes: HD=Winchester, FD=floppy.
pub const GD_HD: u16 = 0;
pub const GD_FD: u16 = 2;

test "syscall numbers match verified fixture" {
    // Fixture: the plan's required set (read/write/open/close/exit/fork/
    // exec/wait/brk/lseek) plus a few UNIX-PC-specific ones. These values
    // are the ground truth extracted from libc.a.
    try std.testing.expectEqual(@as(u16, 1), @intFromEnum(Syscall.exit));
    try std.testing.expectEqual(@as(u16, 2), @intFromEnum(Syscall.fork));
    try std.testing.expectEqual(@as(u16, 3), @intFromEnum(Syscall.read));
    try std.testing.expectEqual(@as(u16, 4), @intFromEnum(Syscall.write));
    try std.testing.expectEqual(@as(u16, 5), @intFromEnum(Syscall.open));
    try std.testing.expectEqual(@as(u16, 6), @intFromEnum(Syscall.close));
    try std.testing.expectEqual(@as(u16, 7), @intFromEnum(Syscall.wait));
    try std.testing.expectEqual(@as(u16, 17), @intFromEnum(Syscall.sbrk)); // "brk"
    try std.testing.expectEqual(@as(u16, 19), @intFromEnum(Syscall.lseek));
    try std.testing.expectEqual(@as(u16, 59), @intFromEnum(Syscall.execve)); // "exec"
    // UNIX-PC specific
    try std.testing.expectEqual(@as(u16, 68), @intFromEnum(Syscall.syslocal));
    try std.testing.expectEqual(@as(u16, 69), @intFromEnum(Syscall.openi));
    try std.testing.expectEqual(@as(u16, 70), @intFromEnum(Syscall.swrite));
}

test "magics recognized" {
    try std.testing.expect(isMc68kMagic(0o520));
    try std.testing.expect(isMc68kMagic(0o521));
    try std.testing.expect(isMc68kMagic(0o522));
    try std.testing.expect(!isMc68kMagic(0o407));
}

test "struct sizes" {
    try std.testing.expectEqual(@as(u32, 30), STAT_SIZE);
    try std.testing.expectEqual(@as(u32, 16), DIRECT_SIZE);
}
