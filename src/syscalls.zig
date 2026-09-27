//! Syscall dispatcher. Keyed off the abi.Syscall table. Reads args per the
//! trap #0 convention (Runner.arg), invokes the handler, writes back the
//! return value / errno-with-carry, and drives strace-style tracing plus
//! fail-fast diagnostics for unimplemented calls.
//!
//! Task 8 implements the framework plus a minimal set (exit, getpid, write to
//! host stdio). File syscalls (Task 9) and misc/mem (Task 10) plug in here.

const std = @import("std");
const abi = @import("abi.zig");
const mem = @import("mem.zig");
const cpu = @import("cpu.zig");
const runloop = @import("runloop.zig");
const trace = @import("trace.zig");
const diag = @import("diag.zig");
const fsmod = @import("fs.zig");
const procmodel = @import("procmodel.zig");

extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn getpid() c_int;

/// Module-global "current runner" so the trace arg accessor (a plain fn ptr)
/// can reach the stack args.
var cur: ?*runloop.Runner = null;


fn traceArg(n: u32) u32 {
    const r = cur orelse return 0;
    return r.arg(n);
}

/// The dispatcher entry point, installed as Runner.handler.
pub fn dispatch(runner: *runloop.Runner, number: u16) runloop.SyscallOutcome {
    cur = runner;

    trace.entry(runner.memory, number, traceArg);

    const sc: abi.Syscall = @enumFromInt(number);
    const outcome = handle(runner, sc, number);

    // For exit, print a trailing newline for the trace (no result line).
    if (sc == .exit) {
        trace.newline();
    }
    return outcome;
}

fn fsOf(runner: *runloop.Runner) ?*fsmod.Fs {
    const p = runner.fs orelse return null;
    return @ptrCast(@alignCast(p));
}

/// Signal success with a value, and trace it.
fn ok(runner: *runloop.Runner, value: u32) runloop.SyscallOutcome {
    runner.ret(value);
    trace.result(value, false, 0);
    return .cont;
}

/// Signal failure with errno, and trace it.
fn err(runner: *runloop.Runner, errno: u16) runloop.SyscallOutcome {
    runner.fail(errno);
    trace.result(0, true, errno);
    return .cont;
}

fn handle(runner: *runloop.Runner, sc: abi.Syscall, number: u16) runloop.SyscallOutcome {
    switch (sc) {
        .exit => {
            runner.exit_status = runner.arg(1);
            return .exit;
        },
        .getpid => {
            // Return the real host pid so each (forked) guest process sees a
            // DISTINCT pid. The toolchain builds temp filenames from getpid()
            // (e.g. cc's /tmp/ctm<pid>); a constant pid makes nested cc/cpp/as
            // under make collide on temp files and corrupt each other. Mask to
            // 16 bits to fit the guest's short pid_t.
            const hp: u32 = @as(u32, @intCast(getpid())) & 0x7fff;
            runner.ret2(hp, 0); // pid=host pid, ppid=0
            trace.result(hp, false, 0);
            return .cont;
        },
        .write, .swrite => return sysWrite(runner),
        .read => return sysRead(runner),
        .open => return sysOpen(runner),
        .creat => return sysCreat(runner),
        .close => return sysClose(runner),
        .lseek => return sysLseek(runner),
        .unlink => return sysUnlink(runner),
        .access => return sysAccess(runner),
        .link => return sysLink(runner),
        .utime => return sysUtime(runner),
        .chdir => return sysChdir(runner),
        .dup => return sysDup(runner),
        .chmod => return sysChmod(runner),
        .chown => return sysChown(runner),
        .stat => return sysStat(runner, false),
        .fstat => return sysStat(runner, true),
        // --- memory / misc (Task 10) ---
        .sbrk => return sysSbrk(runner),
        .time => return sysTime(runner),
        .getuid => {
            runner.ret2(1, 1); // uid=1, euid=1 (D1)
            trace.result(1, false, 0);
            return .cont;
        },
        .getgid => {
            runner.ret2(1, 1); // gid=1, egid=1 (D1)
            trace.result(1, false, 0);
            return .cont;
        },
        .setuid, .setgid => return ok(runner, 0), // pretend success
        .umask => {
            const old = runner.umask;
            runner.umask = runner.arg(1) & 0o777;
            return ok(runner, old);
        },
        .fcntl => return sysFcntl(runner),
        .ioctl => return sysIoctl(runner),
        // Old terminal syscalls gtty/stty — behave like ioctl on a non-tty.
        .gtty, .stty => return err(runner, @intFromEnum(abi.Errno.ENOTTY)),
        .signal => return sysSignal(runner),
        .alarm => return ok(runner, 0), // no timers yet; return 0 (no prev alarm)
        .pause => {
            // No signals delivered yet; pause would block forever. Treat as
            // interrupted to avoid hanging the emulator.
            return err(runner, @intFromEnum(abi.Errno.EINTR));
        },
        .syslocal => return sysSyslocal(runner),
        .times => return sysTimes(runner),
        .sync => return ok(runner, 0),
        .nice => return ok(runner, 0),
        // --- process model (Task 11) ---
        .fork => return sysFork(runner),
        .execve => return sysExec(runner),
        .wait => return sysWait(runner),
        .pipe => return sysPipe(runner),
        else => {
            failFast(runner, number);
            return .exit;
        },
    }
}

// --- memory / misc implementations -----------------------------------------

/// Syscall 17 on the UNIX PC is `brk`: the argument is the ABSOLUTE new break
/// address (the libc `sbrk` wrapper converts increments to absolute and tracks
/// the old break in userland — see docs/shlib.md). The kernel sets the break
/// and returns 0 on success, or -1/ENOMEM.
fn sysSbrk(runner: *runloop.Runner) runloop.SyscallOutcome {
    const newbrk = runner.arg(1);
    if (newbrk < abi.VUSER_START or newbrk >= abi.USRSTACK) {
        return err(runner, @intFromEnum(abi.Errno.ENOMEM));
    }
    const old = runner.brk;
    if (newbrk > old) {
        // Grow: zero-fill and map the new region rw.
        const was = runner.memory.enforce;
        runner.memory.enforce = false;
        runner.memory.zero(old, newbrk - old);
        runner.memory.addRegion(old, newbrk - old, .{ .read = true, .write = true }) catch {};
        runner.memory.enforce = was;
    }
    runner.brk = newbrk;
    return ok(runner, 0);
}

extern "c" fn time(t: ?*c_long) c_long;

fn sysTime(runner: *runloop.Runner) runloop.SyscallOutcome {
    const now: u32 = @truncate(@as(u64, @bitCast(@as(i64, time(null)))));
    // If a non-null pointer arg is given, store the time there too.
    const tptr = runner.arg(1);
    if (tptr != 0) runner.memory.write32(tptr, now);
    return ok(runner, now);
}

fn sysFcntl(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    const gfd = runner.arg(1);
    const cmd = runner.arg(2);
    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    // F_DUPFD=0, F_GETFD=1, F_SETFD=2, F_GETFL=3, F_SETFL=4 (fcntl.h)
    switch (cmd) {
        0 => { // F_DUPFD: duplicate to lowest guest fd >= arg3 (the minimum).
            const min = runner.arg(3);
            const newh = fsmod.c.dup(hfd);
            if (newh < 0) return err(runner, fsmod.hostErrno());
            const gnew = fs.allocFdFrom(newh, min) orelse {
                _ = fsmod.c.close(newh);
                return err(runner, @intFromEnum(abi.Errno.EMFILE));
            };
            return ok(runner, gnew);
        },
        1, 3 => return ok(runner, 0), // F_GETFD/F_GETFL: report no special flags
        2, 4 => return ok(runner, 0), // F_SETFD/F_SETFL: accept and ignore
        else => return err(runner, @intFromEnum(abi.Errno.EINVAL)),
    }
}

fn sysIoctl(runner: *runloop.Runner) runloop.SyscallOutcome {
    const gfd = runner.arg(1);
    const cmd = runner.arg(2);
    const argp = runner.arg(3);

    // Mapped raw disk devices answer the 3B1 disk ioctls from the image's
    // Volume Home Block (VHB), so tools like `iv` and `fsck` can learn the
    // disk geometry and partition layout. Everything else keeps the ENOTTY
    // behavior below.
    if (fsOf(runner)) |fs| {
        if (fs.isDevice(gfd)) {
            if (cmd == abi.GDGETA) return gdgeta(runner, fs, gfd, argp);
            // Other disk ioctls (GDSETA/GDFORMAT/...) aren't emulated yet.
            return err(runner, @intFromEnum(abi.Errno.EINVAL));
        }
    }

    // The toolchain / shell probe tty-ness via ioctl. We don't emulate a tty,
    // so report "not a typewriter" for querying fds that aren't the host tty,
    // and success (0) otherwise. Returning ENOTTY is what isatty() expects for
    // non-terminals and keeps cc/sh happy when they check.
    return err(runner, @intFromEnum(abi.Errno.ENOTTY));
}

/// GDGETA: fill the guest `struct gdctl` from the disk image's VHB.
///
/// Layouts (big-endian m68k), from the 3B1 <sys/gdisk.h> / <sys/gdioctl.h>:
///   struct gdswprt {          // 18 bytes
///     char   name[6];         // @0
///     ushort cyls;            // @6
///     ushort heads;           // @8
///     ushort psectrk;         // @10
///     ushort pseccyl;         // @12
///     char   flags;           // @14
///     char   step;            // @15
///     ushort sectorsz;        // @16
///   };
///   struct vhbd { uint magic@0; int chksum@4; struct gdswprt dsk@8; ... };
///   struct gdctl { ushort status@0; struct gdswprt params@2; short dsktyp@20; };
///
/// We copy the 18-byte gdswprt straight from VHB+8 into gdctl+2 (both are the
/// same big-endian layout), set status = VALID_VHB|DRV_READY, and pick dsktyp
/// from the drive name ("WINCHE" -> Winchester HD).
fn gdgeta(runner: *runloop.Runner, fs: *fsmod.Fs, gfd: u32, argp: u32) runloop.SyscallOutcome {
    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    if (argp == 0) return err(runner, @intFromEnum(abi.Errno.EFAULT));

    // Read the VHB (first sector) without disturbing the guest's file offset.
    var vhb: [512]u8 = undefined;
    const n = fsmod.c.pread(hfd, &vhb, vhb.len, 0);
    if (n < @as(isize, @intCast(vhb.len))) return err(runner, @intFromEnum(abi.Errno.EIO));

    // Validate the VHB magic (big-endian 0x55515651 == "UQVQ").
    const magic = (@as(u32, vhb[0]) << 24) | (@as(u32, vhb[1]) << 16) |
        (@as(u32, vhb[2]) << 8) | @as(u32, vhb[3]);
    if (magic != abi.VHBMAGIC) return err(runner, @intFromEnum(abi.Errno.EINVAL));

    // gdctl.status @0: VALID_VHB (0x0002) | DRV_READY (0x0004).
    runner.memory.write16(argp + 0, abi.VHB_STATUS_VALID | abi.VHB_STATUS_READY);

    // gdctl.params @2 = VHB.dsk @8, 18 bytes copied verbatim (same BE layout).
    var i: u32 = 0;
    while (i < 18) : (i += 1) runner.memory.write8(argp + 2 + i, vhb[8 + i]);

    // gdctl.dsktyp @20: choose from the drive name in dsk.name[6] (VHB+8).
    // "WINCHE"->HD(0), "FLOPPY"->FD(2); default HD.
    const dsktyp: u16 = if (std.mem.startsWith(u8, vhb[8..14], "FLOPPY") or
        std.mem.startsWith(u8, vhb[8..14], "FD")) abi.GD_FD else abi.GD_HD;
    runner.memory.write16(argp + 20, dsktyp);

    return ok(runner, 0);
}

fn sysSignal(runner: *runloop.Runner) runloop.SyscallOutcome {
    // signal(sig, handler): record the new disposition and RETURN THE PREVIOUS
    // one. We don't deliver async signals, but tracking the disposition is
    // essential: the toolchain does `if (signal(SIGINT, SIG_IGN) != SIG_IGN)
    // signal(SIGINT, cleanup)`. Always returning SIG_DFL made cc take the wrong
    // branch and later fault. Dispositions inherit across fork (host fork()
    // copies this table), matching UNIX semantics for ignored signals.
    const sig = runner.arg(1);
    const handler = runner.arg(2);
    if (sig == 0 or sig >= runner.sig_disp.len) {
        return err(runner, @intFromEnum(abi.Errno.EINVAL));
    }
    const prev = runner.sig_disp[sig];
    runner.sig_disp[sig] = handler;
    return ok(runner, prev);
}

/// times(struct tms *buf): fill {utime, stime, cutime, cstime} (4 longs) and
/// return elapsed clock ticks in D0. We don't track guest CPU time, so report
/// zeros for the tms fields and a monotonically-derived tick count (HZ=60).
fn sysTimes(runner: *runloop.Runner) runloop.SyscallOutcome {
    const buf = runner.arg(1);
    if (buf != 0) {
        runner.memory.write32(buf + 0, 0); // tms_utime
        runner.memory.write32(buf + 4, 0); // tms_stime
        runner.memory.write32(buf + 8, 0); // tms_cutime
        runner.memory.write32(buf + 12, 0); // tms_cstime
    }
    // elapsed ticks since epoch at HZ=60 (low 32 bits) — good enough for tools
    // that just want a changing value.
    const ticks: u32 = @truncate(@as(u64, @bitCast(@as(i64, time(null)))) *% 60);
    return ok(runner, ticks);
}

fn sysSyslocal(runner: *runloop.Runner) runloop.SyscallOutcome {
    // syslocal(cmd, ...) — the machine-type/identity call. SYSL_SYSTEM=0
    // returns the machine class; report SYSL_MITI(2) (a plausible 3B1 value).
    const cmd = runner.arg(1);
    switch (cmd) {
        0 => return ok(runner, 2), // SYSL_SYSTEM -> SYSL_MITI
        else => return ok(runner, 0),
    }
}

// --- process model implementations -----------------------------------------

fn pmOf(runner: *runloop.Runner) ?procmodel.ProcessModel {
    const p = runner.procmodel orelse return null;
    const hp: *procmodel.HostProcess = @ptrCast(@alignCast(p));
    return hp.model();
}

fn sysFork(runner: *runloop.Runner) runloop.SyscallOutcome {
    const pm = pmOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EAGAIN));
    const rc = pm.doFork() catch |e| switch (e) {
        error.NotSupported => return err(runner, @intFromEnum(abi.Errno.ENOMEM)),
        else => return err(runner, @intFromEnum(abi.Errno.EAGAIN)),
    };
    // 3B1 fork ABI: the kernel returns the child pid in D0 to BOTH processes
    // and uses D1 as the parent/child discriminator (the libc fork stub does
    // `tstw d1; beq keep; clrl d0` — D1==0 => parent keeps pid, D1!=0 => child
    // zeroes d0). Host fork() gives the parent the child pid and the child 0;
    // we set D1 to match so the stub distinguishes them. (In the child D0 is
    // don't-care since the stub clears it.)
    const is_child = (rc == 0);
    if (is_child) {
        runner.ret2(0, 1); // D0=0 (cleared anyway), D1=1 => child
    } else {
        runner.ret2(rc, 0); // D0=child pid, D1=0 => parent
    }
    trace.result(rc, false, 0);
    return .cont;
}

fn sysExec(runner: *runloop.Runner) runloop.SyscallOutcome {
    const pm = pmOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    // execve(path, argv, envp): argv/envp are guest pointer arrays (NULL-term).
    var pbuf: [1024]u8 = undefined;
    const path = runner.argStr(1, &pbuf);
    const argv_ptr = runner.arg(2);
    const envp_ptr = runner.arg(3);

    // Marshal argv/envp from guest memory into host-side slices.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const argv = readGuestStrArray(runner, argv_ptr, a) catch return err(runner, @intFromEnum(abi.Errno.EFAULT));
    const envp = readGuestStrArray(runner, envp_ptr, a) catch return err(runner, @intFromEnum(abi.Errno.EFAULT));

    pm.doExec(path, argv, envp) catch |e| switch (e) {
        error.ExecFailed => return err(runner, @intFromEnum(abi.Errno.ENOEXEC)),
        error.NotSupported => return err(runner, @intFromEnum(abi.Errno.EINVAL)),
        else => return err(runner, @intFromEnum(abi.Errno.ENOENT)),
    };
    // exec succeeded: reset the program break to the new image's, so the new
    // program's malloc/brk doesn't inherit the previous program's break.
    const hp: *procmodel.HostProcess = @ptrCast(@alignCast(runner.procmodel.?));
    runner.brk = hp.new_brk;
    // PC/regs already point at the new entry. Do not advance past the trap.
    return .restart;
}

/// Read a NUL-terminated array of guest char* into an allocated slice of
/// host strings (each duped in the arena).
fn readGuestStrArray(runner: *runloop.Runner, arr_ptr: u32, a: std.mem.Allocator) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    if (arr_ptr == 0) return list.toOwnedSlice(a);
    var i: u32 = 0;
    while (i < 1024) : (i += 1) {
        const p = runner.memory.read32(arr_ptr + i * 4);
        if (p == 0) break;
        var sbuf: [1024]u8 = undefined;
        const s = runner.memory.readCStr(p, &sbuf);
        try list.append(a, try a.dupe(u8, s));
    }
    return list.toOwnedSlice(a);
}

fn sysWait(runner: *runloop.Runner) runloop.SyscallOutcome {
    const pm = pmOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.ECHILD));
    const wr = pm.doWait() catch |e| switch (e) {
        error.NoChild => return err(runner, @intFromEnum(abi.Errno.ECHILD)),
        else => return err(runner, @intFromEnum(abi.Errno.ECHILD)),
    };
    // wait(statusptr): if the pointer arg is non-null, store the status word.
    const stat_ptr = runner.arg(1);
    if (stat_ptr != 0) runner.memory.write32(stat_ptr, wr.status);
    // Return the child pid in D0; some libc wait() variants expect status in D1.
    runner.ret2(wr.pid, wr.status);
    trace.result(wr.pid, false, 0);
    return .cont;
}

fn sysPipe(runner: *runloop.Runner) runloop.SyscallOutcome {
    const pm = pmOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EMFILE));
    const fds = pm.doPipe() catch return err(runner, @intFromEnum(abi.Errno.EMFILE));
    // pipe() returns read fd in D0, write fd in D1 (SVR m68k convention).
    runner.ret2(fds[0], fds[1]);
    trace.result(fds[0], false, 0);
    return .cont;
}

// --- file syscall implementations ------------------------------------------

/// Read `len` bytes from a mapped device fd, translating the partition-relative
/// logical position to physical image offsets one logical sector at a time
/// (to honor the 17th-sector interleave), copying into guest memory at `buf`.
/// Advances the fd's logical cursor. Returns the syscall outcome.
fn deviceRead(runner: *runloop.Runner, g: *fsmod.DeviceGeom, hfd: i32, buf: u32, len: u32) runloop.SyscallOutcome {
    const secsz: i64 = @intCast(g.secsz);
    var total: u32 = 0;
    var addr = buf;
    var remaining = len;
    var chunk: [512]u8 = undefined;
    while (remaining > 0) {
        // Bytes left in the current logical sector (so we never cross a sector
        // boundary in one pread — physOf is only linear within a sector).
        const in_sec: i64 = g.log_pos - @divFloor(g.log_pos, secsz) * secsz;
        const room: u32 = @intCast(secsz - in_sec);
        const n = @min(@min(remaining, room), @as(u32, chunk.len));
        const phys = g.physOf(g.log_pos);
        const r = fsmod.c.pread(hfd, &chunk, n, @intCast(phys));
        if (r < 0) return err(runner, fsmod.hostErrno());
        if (r == 0) break; // EOF
        const ru: u32 = @intCast(r);
        var i: u32 = 0;
        while (i < ru) : (i += 1) runner.memory.write8(addr + i, chunk[i]);
        total += ru;
        addr += ru;
        remaining -= ru;
        g.log_pos += ru;
        if (ru < n) break;
    }
    return ok(runner, total);
}

/// Write `len` bytes to a mapped device fd with the same per-sector interleave
/// translation as deviceRead. Advances the fd's logical cursor.
fn deviceWrite(runner: *runloop.Runner, g: *fsmod.DeviceGeom, hfd: i32, buf: u32, len: u32) runloop.SyscallOutcome {
    const secsz: i64 = @intCast(g.secsz);
    var total: u32 = 0;
    var addr = buf;
    var remaining = len;
    var chunk: [512]u8 = undefined;
    while (remaining > 0) {
        const in_sec: i64 = g.log_pos - @divFloor(g.log_pos, secsz) * secsz;
        const room: u32 = @intCast(secsz - in_sec);
        const n = @min(@min(remaining, room), @as(u32, chunk.len));
        var i: u32 = 0;
        while (i < n) : (i += 1) chunk[i] = runner.memory.read8(addr + i);
        const phys = g.physOf(g.log_pos);
        const w = fsmod.c.pwrite(hfd, &chunk, n, @intCast(phys));
        if (w < 0) return err(runner, fsmod.hostErrno());
        const wu: u32 = @intCast(w);
        total += wu;
        addr += wu;
        remaining -= wu;
        g.log_pos += wu;
        if (wu < n) break;
    }
    return ok(runner, total);
}

fn sysWrite(runner: *runloop.Runner) runloop.SyscallOutcome {
    const gfd = runner.arg(1);
    const buf = runner.arg(2);
    const len = runner.arg(3);
    const fs = fsOf(runner) orelse {
        // No fs: only host stdout/stderr passthrough (used by bare stubs).
        if (gfd == 1 or gfd == 2) {
            if (capture != null) return ok(runner, hostWriteFromGuest(runner.memory, @intCast(gfd), buf, len));
            return ok(runner, hostWriteFromGuest(runner.memory, @intCast(gfd), buf, len));
        }
        return err(runner, @intFromEnum(abi.Errno.EBADF));
    };
    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    // Mapped device: write through the logical->physical interleave.
    if (fs.devGeom(gfd)) |g| return deviceWrite(runner, g, hfd, buf, len);
    // If this fd maps to the real host stdout/stderr AND a test capture sink is
    // active, route through capture (keeps `zig build test` stdout IPC clean).
    if ((hfd == 1 or hfd == 2) and capture != null) {
        return ok(runner, hostWriteFromGuest(runner.memory, @intCast(hfd), buf, len));
    }
    var total: u32 = 0;
    var remaining = len;
    var addr = buf;
    var chunk: [1024]u8 = undefined;
    while (remaining > 0) {
        const n = @min(remaining, chunk.len);
        var i: u32 = 0;
        while (i < n) : (i += 1) chunk[i] = runner.memory.read8(addr + i);
        const w = fsmod.c.write(hfd, &chunk, n);
        if (w < 0) return err(runner, fsmod.hostErrno());
        const wu: u32 = @intCast(w);
        total += wu;
        addr += wu;
        remaining -= wu;
        if (wu < n) break;
    }
    return ok(runner, total);
}

fn sysRead(runner: *runloop.Runner) runloop.SyscallOutcome {
    const gfd = runner.arg(1);
    const buf = runner.arg(2);
    const len = runner.arg(3);
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));

    // Directory read: synthesize 3B1 struct direct records (16 bytes each:
    // 2-byte big-endian d_ino + 14-byte d_name).
    if (fs.dirOf(gfd)) |dh| {
        var written: u32 = 0;
        var addr = buf;
        while (written + abi.DIRECT_SIZE <= len) {
            var ino: c_ulong = 0;
            var name: [14]u8 = undefined;
            const r = fsmod.upc_dirread(dh, &ino, &name);
            if (r <= 0) break; // end of directory (or error)
            runner.memory.write16(addr, @truncate(ino)); // d_ino (16-bit)
            var i: u32 = 0;
            while (i < 14) : (i += 1) runner.memory.write8(addr + 2 + i, name[i]);
            addr += abi.DIRECT_SIZE;
            written += abi.DIRECT_SIZE;
        }
        return ok(runner, written);
    }

    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    // Mapped device: read through the logical->physical interleave.
    if (fs.devGeom(gfd)) |g| return deviceRead(runner, g, hfd, buf, len);
    var total: u32 = 0;
    var remaining = len;
    var addr = buf;
    var chunk: [1024]u8 = undefined;
    while (remaining > 0) {
        const n = @min(remaining, chunk.len);
        const r = fsmod.c.read(hfd, &chunk, n);
        if (r < 0) return err(runner, fsmod.hostErrno());
        if (r == 0) break; // EOF
        const ru: u32 = @intCast(r);
        var i: u32 = 0;
        while (i < ru) : (i += 1) runner.memory.write8(addr + i, chunk[i]);
        total += ru;
        addr += ru;
        remaining -= ru;
        if (ru < n) break;
    }
    return ok(runner, total);
}

/// Open a mapped raw-device slice: open the host image, tag the fd as a device
/// (so GDGETA works), compute the partition base offset from the VHB, and seek
/// the host fd to that base so guest offset 0 == partition start. Shared by
/// open(2) and creat(2). `host_flags` are already host-translated O_* flags.
fn openMappedDevice(
    runner: *runloop.Runner,
    fs: *fsmod.Fs,
    dev: fsmod.Fs.DeviceHit,
    host_flags: c_int,
    mode: u32,
) runloop.SyscallOutcome {
    // A device is never "created"; strip O_CREAT/O_TRUNC so creat() on a device
    // just opens it writable instead of truncating the whole image file.
    var of: std.c.O = @bitCast(host_flags);
    of.CREAT = false;
    of.TRUNC = false;
    // Prefer O_RDWR on the backing image: we need to read the VHB (to compute
    // the partition offset) even when the guest asked for write-only, and the
    // guest's access-mode restriction doesn't need enforcing against our image.
    // Fall back to the guest's requested mode if the image is read-only.
    const want = of.ACCMODE;
    of.ACCMODE = .RDWR;
    var hfd = fsmod.c.open(dev.host.ptr, @bitCast(of), mode);
    if (hfd < 0) {
        of.ACCMODE = want;
        hfd = fsmod.c.open(dev.host.ptr, @bitCast(of), mode);
    }
    if (hfd < 0) return err(runner, fsmod.hostErrno());
    // Read this slice's geometry (start track + interleave params) from the
    // image VHB. A bad/missing VHB leaves geom inactive -> plain access.
    const geom: fsmod.DeviceGeom = fsmod.Fs.readDeviceGeom(hfd, dev.slice) catch .{};
    const gfd = fs.allocFd(hfd) orelse {
        _ = fsmod.c.close(hfd);
        return err(runner, @intFromEnum(abi.Errno.EMFILE));
    };
    fs.setDevice(gfd); // route disk ioctls (GDGETA) to VHB emulation
    fs.setDeviceGeom(gfd, geom); // logical<->physical interleave + cursor
    return ok(runner, gfd);
}

fn sysOpen(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    const flags = runner.arg(2);
    const mode = runner.arg(3);

    // Mapped raw device (--map-device GUEST=HOST): open the host image file
    // directly instead of resolving under the guest root. A raw device is a
    // plain seekable file on the host, so once opened, read/write/lseek/close
    // operate on the host fd unchanged (no dir-stream, no stat special-casing).
    if (fs.deviceLookup(gpath)) |dev| {
        return openMappedDevice(runner, fs, dev, fsmod.translateOpenFlags(flags), mode);
    }

    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));

    // Directory? The 3B1 reads directories with read(2); back it with a
    // dir-stream (Linux/macOS forbid read() on directory fds).
    var st: HostStat = std.mem.zeroes(HostStat);
    if (host_stat(hpath.ptr, &st) == 0 and (st.mode & 0o170000) == 0o040000) {
        const dh = fsmod.upc_diropen(hpath.ptr);
        if (dh < 0) return err(runner, fsmod.hostErrno());
        // Also open the fd normally so fstat etc. work; but read routes to dir.
        const hfd = fsmod.c.open(hpath.ptr, 0, 0);
        if (hfd < 0) {
            fsmod.upc_dirclose(dh);
            return err(runner, fsmod.hostErrno());
        }
        const gfd = fs.allocFd(hfd) orelse {
            _ = fsmod.c.close(hfd);
            fsmod.upc_dirclose(dh);
            return err(runner, @intFromEnum(abi.Errno.EMFILE));
        };
        fs.setDir(gfd, dh);
        return ok(runner, gfd);
    }

    const hfd = fsmod.c.open(hpath.ptr, fsmod.translateOpenFlags(flags), mode);
    if (hfd < 0) return err(runner, fsmod.hostErrno());
    const gfd = fs.allocFd(hfd) orelse {
        _ = fsmod.c.close(hfd);
        return err(runner, @intFromEnum(abi.Errno.EMFILE));
    };
    return ok(runner, gfd);
}

fn sysCreat(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    const mode = runner.arg(2);

    // creat() on a mapped raw device just opens it writable (a device isn't
    // created/truncated). openMappedDevice strips O_CREAT/O_TRUNC.
    if (fs.deviceLookup(gpath)) |dev| {
        return openMappedDevice(runner, fs, dev, fsmod.translateOpenFlags(abi.O_WRONLY), mode);
    }

    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    // creat(path, mode) == open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)
    const flags = fsmod.translateOpenFlags(abi.O_WRONLY | abi.O_CREAT | abi.O_TRUNC);
    const hfd = fsmod.c.open(hpath.ptr, flags, mode);
    if (hfd < 0) return err(runner, fsmod.hostErrno());
    const gfd = fs.allocFd(hfd) orelse {
        _ = fsmod.c.close(hfd);
        return err(runner, @intFromEnum(abi.Errno.EMFILE));
    };
    return ok(runner, gfd);
}

fn sysClose(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    const gfd = runner.arg(1);
    if (!fs.closeFd(gfd)) return err(runner, @intFromEnum(abi.Errno.EBADF));
    return ok(runner, 0);
}

fn sysLseek(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    const gfd = runner.arg(1);
    const off: i32 = @bitCast(runner.arg(2));
    const whence: c_int = @intCast(runner.arg(3));
    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));

    // Mapped device: seeks are partition-relative *logical* positions. We track
    // the cursor ourselves (physical translation happens per read/write), so no
    // host lseek is issued. SEEK_END is relative to the partition's logical
    // size, which we don't track precisely; the filesystem tools always seek
    // with SEEK_SET/SEEK_CUR, so END is unsupported for devices.
    if (fs.devGeom(gfd)) |g| {
        const soff: i64 = @as(i64, @as(i32, @bitCast(runner.arg(2))));
        const newpos: i64 = switch (whence) {
            0 => soff, // SEEK_SET
            1 => g.log_pos + soff, // SEEK_CUR
            else => return err(runner, @intFromEnum(abi.Errno.EINVAL)),
        };
        if (newpos < 0) return err(runner, @intFromEnum(abi.Errno.EINVAL));
        g.log_pos = newpos;
        return ok(runner, @intCast(newpos));
    }

    const r = fsmod.c.lseek(hfd, off, whence);
    if (r < 0) return err(runner, fsmod.hostErrno());
    return ok(runner, @intCast(r));
}

fn sysUnlink(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    if (fsmod.c.unlink(hpath.ptr) < 0) return err(runner, fsmod.hostErrno());
    return ok(runner, 0);
}

fn sysAccess(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    const amode: c_int = @intCast(runner.arg(2));
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    if (fsmod.c.access(hpath.ptr, amode) < 0) return err(runner, fsmod.hostErrno());
    return ok(runner, 0);
}

fn sysChdir(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    // Validate the target exists under root.
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    if (fsmod.c.access(hpath.ptr, 0) < 0) return err(runner, fsmod.hostErrno());
    fs.chdir(gpath) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    return ok(runner, 0);
}

fn sysChmod(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    const mode = runner.arg(2);
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    if (fsmod.c.chmod(hpath.ptr, mode & 0o7777) < 0) return err(runner, fsmod.hostErrno());
    return ok(runner, 0);
}

fn sysChown(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    // Best-effort; chown typically fails for non-root but tools don't care.
    _ = fsmod.c.chown(hpath.ptr, runner.arg(2), runner.arg(3));
    return ok(runner, 0);
}

fn sysDup(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    const gfd = runner.arg(1);
    const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
    const newh = fsmod.c.dup(hfd);
    if (newh < 0) return err(runner, fsmod.hostErrno());
    const gnew = fs.allocFd(newh) orelse {
        _ = fsmod.c.close(newh);
        return err(runner, @intFromEnum(abi.Errno.EMFILE));
    };
    return ok(runner, gnew);
}

/// link(oldpath, newpath): create a hard link. Both paths resolve under the
/// guest root. make(1)/ar(1) use link+unlink for atomic file replacement.
fn sysLink(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var obuf: [1024]u8 = undefined;
    var nbuf: [1024]u8 = undefined;
    const gold = runner.argStr(1, &obuf);
    const gnew = runner.argStr(2, &nbuf);
    var hold: [1200]u8 = undefined;
    var hnew: [1200]u8 = undefined;
    const holdp = fs.resolve(gold, &hold) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    const hnewp = fs.resolve(gnew, &hnew) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    if (fsmod.c.link(holdp.ptr, hnewp.ptr) < 0) return err(runner, fsmod.hostErrno());
    return ok(runner, 0);
}

/// utime(path, times): set access/modification times. `times` is a guest
/// pointer to two 32-bit big-endian longs {actime, modtime}, or NULL to use
/// the current time. make(1) calls this to stamp built targets, so getting a
/// success return (and honoring the times when given) unblocks make-driven
/// builds.
fn sysUtime(runner: *runloop.Runner) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var pbuf: [1024]u8 = undefined;
    const gpath = runner.argStr(1, &pbuf);
    var hbuf: [1200]u8 = undefined;
    const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
    const times_ptr = runner.arg(2);
    var use_now: c_int = 1;
    var actime: c_long = 0;
    var modtime: c_long = 0;
    if (times_ptr != 0) {
        use_now = 0;
        actime = @intCast(runner.memory.read32(times_ptr));
        modtime = @intCast(runner.memory.read32(times_ptr + 4));
    }
    if (upc_host_utime(hpath.ptr, use_now, actime, modtime) < 0)
        return err(runner, fsmod.hostErrno());
    return ok(runner, 0);
}

/// stat/fstat: fill the guest `struct stat` (30 bytes, big-endian) at the
/// pointer argument. For stat, arg1=path, arg2=statbuf. For fstat, arg1=fd,
/// arg2=statbuf.
fn sysStat(runner: *runloop.Runner, is_fstat: bool) runloop.SyscallOutcome {
    const fs = fsOf(runner) orelse return err(runner, @intFromEnum(abi.Errno.EACCES));
    var st: HostStat = std.mem.zeroes(HostStat);
    if (is_fstat) {
        const gfd = runner.arg(1);
        const hfd = fs.get(gfd) orelse return err(runner, @intFromEnum(abi.Errno.EBADF));
        if (host_fstat(hfd, &st) < 0) return err(runner, fsmod.hostErrno());
    } else {
        var pbuf: [1024]u8 = undefined;
        const gpath = runner.argStr(1, &pbuf);
        var hbuf: [1200]u8 = undefined;
        const hpath = fs.resolve(gpath, &hbuf) catch return err(runner, @intFromEnum(abi.Errno.ENOENT));
        if (host_stat(hpath.ptr, &st) < 0) return err(runner, fsmod.hostErrno());
    }
    const sbuf = runner.arg(2);
    writeGuestStat(runner.memory, sbuf, &st);
    return ok(runner, 0);
}

// --- host stat bindings + guest struct stat packing ------------------------
// We use a fixed-layout host stat via the libc stat() into our own struct is
// fragile across platforms; instead call libc stat/fstat into the host struct
// through small C shims declared with the fields we read.

const HostStat = extern struct {
    mode: u32 = 0,
    nlink: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    size: i64 = 0,
    atime: i64 = 0,
    mtime: i64 = 0,
    ctime: i64 = 0,
    dev: u64 = 0,
    ino: u64 = 0,
    rdev: u64 = 0,
};

extern fn upc_host_stat(path: [*:0]const u8, out: *HostStat) c_int;
extern fn upc_host_fstat(fd: c_int, out: *HostStat) c_int;
extern fn upc_host_utime(path: [*:0]const u8, use_now: c_int, actime: c_long, modtime: c_long) c_int;

fn host_stat(path: [*:0]const u8, out: *HostStat) c_int {
    return upc_host_stat(path, out);
}
fn host_fstat(fd: c_int, out: *HostStat) c_int {
    return upc_host_fstat(fd, out);
}

/// Write the guest struct stat (big-endian) from a host stat.
/// Layout (30 bytes): st_dev(2) st_ino(2) st_mode(2) st_nlink(2) st_uid(2)
///   st_gid(2) st_rdev(2) st_size(4) st_atime(4) st_mtime(4) st_ctime(4)
fn writeGuestStat(memory: *mem.Memory, addr: u32, st: *const HostStat) void {
    memory.write16(addr + 0, @truncate(st.dev));
    memory.write16(addr + 2, @truncate(st.ino));
    memory.write16(addr + 4, @truncate(st.mode));
    memory.write16(addr + 6, @truncate(st.nlink));
    memory.write16(addr + 8, @truncate(st.uid));
    memory.write16(addr + 10, @truncate(st.gid));
    memory.write16(addr + 12, @truncate(st.rdev));
    memory.write32(addr + 14, @truncate(@as(u64, @bitCast(st.size))));
    memory.write32(addr + 18, @truncate(@as(u64, @bitCast(st.atime))));
    memory.write32(addr + 22, @truncate(@as(u64, @bitCast(st.mtime))));
    memory.write32(addr + 26, @truncate(@as(u64, @bitCast(st.ctime))));
}

/// Test-only capture sink. When non-null, guest writes to fd 1/2 are appended
/// here instead of being sent to the host stdout/stderr. This keeps tests from
/// writing to the real stdout, which would corrupt the `zig build test` runner
/// IPC channel (it multiplexes results over stdout).
pub var capture: ?*std.ArrayListUnmanaged(u8) = null;
pub var capture_alloc: ?std.mem.Allocator = null;

/// Copy `len` bytes from guest memory to host fd (1 or 2). Returns bytes written.
fn hostWriteFromGuest(memory: *mem.Memory, fd: c_int, guest_addr: u32, len: u32) u32 {
    var remaining = len;
    var addr = guest_addr;
    var total: u32 = 0;
    var chunk: [512]u8 = undefined;
    while (remaining > 0) {
        const n = @min(remaining, chunk.len);
        var i: u32 = 0;
        while (i < n) : (i += 1) chunk[i] = memory.read8(addr + i);
        if (capture) |cap| {
            cap.appendSlice(capture_alloc.?, chunk[0..n]) catch {};
            total += n;
            addr += n;
            remaining -= n;
        } else {
            const wrote = write(fd, &chunk, n);
            if (wrote <= 0) break;
            const w: u32 = @intCast(wrote);
            total += w;
            addr += w;
            remaining -= w;
            if (w < n) break;
        }
    }
    return total;
}

fn failFast(runner: *runloop.Runner, number: u16) void {
    runner.aborted = true;
    const pc = cpu.getReg(cpu.Reg.pc);
    const sc: abi.Syscall = @enumFromInt(number);
    const reason: diag.Reason = if (std.mem.eql(u8, sc.name(), "UNKNOWN"))
        .{ .bad_syscall = number }
    else
        .{ .unimplemented_syscall = number };
    diag.dump(runner.memory, pc, reason);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const proc = @import("process.zig");

/// Assemble a small program in guest memory and run it with the real
/// dispatcher installed. Returns the Runner after execution.
fn runProg(memory: *mem.Memory, code: []const u8) runloop.Runner {
    mem.setActive(memory);
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;
    memory.writeBytes(abi.VUSER_START, code);
    runloop.installHaltPad(memory) catch unreachable;

    const argv = [_][]const u8{"t"};
    const envp = [_][]const u8{};
    const layout = proc.buildStack(memory, abi.USRSTACK, &argv, &envp) catch unreachable;

    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(abi.VUSER_START, layout);
    memory.enforce = true;

    var runner = runloop.Runner{ .memory = memory, .handler = dispatch };
    _ = runloop.run(&runner);
    return runner;
}

test "write to stdout then exit via dispatcher" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);

    // Program (assembled offsets):
    //   lea msg(pc),a0 ; push len,buf,fd,retaddr ; movew #4,d0 ; trap #0
    //   lea 16(sp),sp  ; push status,retaddr ; movew #1,d0 ; trap #0 ; stop
    // We hand-encode with msg right after. Easier: just do write(1, msg, 3)
    // where msg is at a fixed guest address we poke separately.
    const msg_addr: u32 = abi.VUSER_START + 0x100;
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;
    memory.writeBytes(msg_addr, "hi\n");

    // Encode: movel #3,-(sp); movel #msg,-(sp); movel #1,-(sp); movel #0,-(sp);
    //         movew #4,d0; trap #0; movel #0,-(sp); movel #0,-(sp); movew #1,d0; trap #0
    var buf: [128]u8 = undefined;
    var p: usize = 0;
    const w16 = struct {
        fn f(b: []u8, o: *usize, v: u16) void {
            std.mem.writeInt(u16, b[o.*..][0..2], v, .big);
            o.* += 2;
        }
    }.f;
    const w32 = struct {
        fn f(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .big);
            o.* += 4;
        }
    }.f;
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, 3); // push len=3
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, msg_addr); // push buf
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, 1); // push fd=1
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, 0); // push retaddr
    w16(&buf, &p, 0x303c);
    w16(&buf, &p, 4); // movew #4,d0 (write)
    w16(&buf, &p, 0x4e40); // trap #0
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, 0); // push status
    w16(&buf, &p, 0x2f3c);
    w32(&buf, &p, 0); // push retaddr
    w16(&buf, &p, 0x303c);
    w16(&buf, &p, 1); // movew #1,d0 (exit)
    w16(&buf, &p, 0x4e40); // trap #0

    // Capture guest stdout instead of writing to the real fd 1 (which would
    // corrupt the zig build test runner's stdout IPC).
    var cap: std.ArrayListUnmanaged(u8) = .empty;
    defer cap.deinit(std.testing.allocator);
    capture = &cap;
    capture_alloc = std.testing.allocator;
    defer {
        capture = null;
        capture_alloc = null;
    }

    const runner = runProg(&memory, buf[0..p]);
    try std.testing.expectEqual(@as(?u32, 0), runner.exit_status);
    try std.testing.expect(!runner.aborted);
    try std.testing.expectEqual(@as(u64, 2), runner.syscall_count); // write + exit
    try std.testing.expectEqualStrings("hi\n", cap.items);
}

test "unimplemented syscall triggers fail-fast abort" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);

    // movel #0,-(sp); movel #0,-(sp); movew #21,d0 (mount, unimplemented); trap
    var buf: [32]u8 = undefined;
    var p: usize = 0;
    std.mem.writeInt(u16, buf[0..2], 0x2f3c, .big);
    std.mem.writeInt(u32, buf[2..6], 0, .big);
    std.mem.writeInt(u16, buf[6..8], 0x2f3c, .big);
    std.mem.writeInt(u32, buf[8..12], 0, .big);
    std.mem.writeInt(u16, buf[12..14], 0x303c, .big);
    std.mem.writeInt(u16, buf[14..16], 21, .big); // mount — unimplemented
    std.mem.writeInt(u16, buf[16..18], 0x4e40, .big);
    p = 18;

    const runner = runProg(&memory, buf[0..p]);
    try std.testing.expect(runner.aborted);
}

/// Like runProg but also installs a filesystem.
fn runProgFs(memory: *mem.Memory, fs: *fsmod.Fs, code: []const u8) runloop.Runner {
    mem.setActive(memory);
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;
    memory.writeBytes(abi.VUSER_START, code);
    runloop.installHaltPad(memory) catch unreachable;
    const argv = [_][]const u8{"t"};
    const envp = [_][]const u8{};
    const layout = proc.buildStack(memory, abi.USRSTACK, &argv, &envp) catch unreachable;
    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(abi.VUSER_START, layout);
    memory.enforce = true;
    var runner = runloop.Runner{ .memory = memory, .handler = dispatch, .fs = fs };
    _ = runloop.run(&runner);
    return runner;
}

test "open/read a file under guestroot" {
    const t = std.testing;
    // Create a temp guestroot with a file using libc directly (avoids the
    // churning std.Io test-dir API and matches how fs.zig does host I/O).
    const root = "/tmp/runupc_test_gr";
    _ = fsmod.c.mkdir(root, 0o755); // ignore EEXIST
    const dpath = root ++ "/data.txt";
    // Remove any stale file from a previous interrupted run so O_CREAT starts
    // clean (a leftover 0-perm file would make the guest's open() fail EACCES).
    _ = fsmod.c.unlink(dpath);
    // Host open flags are OS-specific; build them from std.c.O so this works on
    // macOS as well as Linux (raw octals here would be Linux-only values).
    const wflags: c_int = @bitCast(std.c.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const fd = fsmod.c.open(dpath, wflags, 0o644);
    try t.expect(fd >= 0);
    _ = fsmod.c.write(fd, "ABCDE", 5);
    _ = fsmod.c.close(fd);
    // Ensure the file is readable regardless of the process umask, so the
    // emulated open() under test can read it.
    _ = fsmod.c.chmod(dpath, 0o644);
    defer _ = fsmod.c.unlink(dpath);

    var memory = try mem.Memory.init(t.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    var fs = try fsmod.Fs.init(t.allocator, root, &.{});
    defer fs.deinit();

    // Program: open("/data.txt",0)->d7; read(d7, buf, 5); exit(count).
    // buf placed at VUSER_START+0x100. path string at VUSER_START+0x80.
    const path_addr: u32 = abi.VUSER_START + 0x80;
    const buf_addr: u32 = abi.VUSER_START + 0x100;
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;
    memory.writeBytes(path_addr, "/data.txt\x00");

    var buf: [128]u8 = undefined;
    var p: usize = 0;
    const e16 = struct {
        fn f(b: []u8, o: *usize, v: u16) void {
            std.mem.writeInt(u16, b[o.*..][0..2], v, .big);
            o.* += 2;
        }
    }.f;
    const e32 = struct {
        fn f(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .big);
            o.* += 4;
        }
    }.f;
    // open("/data.txt", 0): push flags=0, path, retaddr; movew #5,d0; trap
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 0); // flags
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, path_addr); // path
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 0); // retaddr
    e16(&buf, &p, 0x303c);
    e16(&buf, &p, 5); // open
    e16(&buf, &p, 0x4e40);
    // d7 = d0 (fd): movel d0,d7 = 0x2e00
    e16(&buf, &p, 0x2e00);
    // read(d7, buf, 5): push count=5, buf, d7, retaddr; movew #3,d0; trap
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 5); // count
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, buf_addr); // buf
    e16(&buf, &p, 0x2f07); // movel d7,-(sp)
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 0); // retaddr
    e16(&buf, &p, 0x303c);
    e16(&buf, &p, 3); // read
    e16(&buf, &p, 0x4e40);
    // exit(d0): movel d0,-(sp); push retaddr; movew #1,d0; trap
    e16(&buf, &p, 0x2f00); // movel d0,-(sp) = status (read count)
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 0); // retaddr
    e16(&buf, &p, 0x303c);
    e16(&buf, &p, 1); // exit
    e16(&buf, &p, 0x4e40);

    const runner = runProgFs(&memory, &fs, buf[0..p]);
    try t.expect(!runner.aborted);
    try t.expectEqual(@as(?u32, 5), runner.exit_status); // read returned 5
    // Verify the bytes landed in guest memory.
    var got: [5]u8 = undefined;
    for (0..5) |k| got[k] = memory.read8(buf_addr + @as(u32, @intCast(k)));
    try t.expectEqualStrings("ABCDE", &got);
}

test "sbrk grows the break and new memory is usable" {
    const t = std.testing;
    var memory = try mem.Memory.init(t.allocator);
    defer memory.deinit();
    defer mem.setActive(null);

    // Program: sbrk(4096)->a0; store 0xAA55 word at a0; exit(*(word*)a0).
    // movel #4096,-(sp); movel #0,-(sp); movew #17,d0; trap; lea 8(sp),sp
    // movel d0,a0; movew #0xAA55... -> then exit low byte.
    var buf: [96]u8 = undefined;
    var p: usize = 0;
    const e16 = struct {
        fn f(b: []u8, o: *usize, v: u16) void {
            std.mem.writeInt(u16, b[o.*..][0..2], v, .big);
            o.* += 2;
        }
    }.f;
    const e32 = struct {
        fn f(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .big);
            o.* += 4;
        }
    }.f;
    // Syscall 17 = brk (ABSOLUTE new break). Set break to VUSER_START+0x2000,
    // which grows and maps [initial_brk, 0x2000). Then write 0x1234 to a word
    // in the newly-grown region (VUSER_START+0x1800) and exit(that long).
    const target_brk: u32 = abi.VUSER_START + 0x2000;
    const heap_addr: u32 = abi.VUSER_START + 0x1800;
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, target_brk); // push absolute new break
    e16(&buf, &p, 0x2f3c);
    e32(&buf, &p, 0); // dummy retaddr
    e16(&buf, &p, 0x303c);
    e16(&buf, &p, 17); // brk (syscall 17)
    e16(&buf, &p, 0x4e40); // trap
    e16(&buf, &p, 0x4fef); // lea 8(sp),sp
    e16(&buf, &p, 0x0008);
    // movea.l #heap_addr, a0 : 207c <imm32>
    e16(&buf, &p, 0x207c);
    e32(&buf, &p, heap_addr);
    // move.w #0x1234,(a0): 30bc 1234
    e16(&buf, &p, 0x30bc);
    e16(&buf, &p, 0x1234);
    // push (a0) as long, exit(it). move.l (a0),-(sp): 2f10
    e16(&buf, &p, 0x2f10);
    e16(&buf, &p, 0x2f3c); // push dummy retaddr
    e32(&buf, &p, 0);
    e16(&buf, &p, 0x303c);
    e16(&buf, &p, 1); // exit
    e16(&buf, &p, 0x4e40);

    mem.setActive(&memory);
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;
    memory.writeBytes(abi.VUSER_START, buf[0..p]);
    runloop.installHaltPad(&memory) catch unreachable;
    const argv = [_][]const u8{"t"};
    const envp = [_][]const u8{};
    const layout = proc.buildStack(&memory, abi.USRSTACK, &argv, &envp) catch unreachable;
    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(abi.VUSER_START, layout);
    memory.enforce = true;
    // Initial break just past the code so brk(target) grows into the heap.
    var runner = runloop.Runner{ .memory = &memory, .handler = dispatch, .brk = abi.VUSER_START + 0x100 };
    _ = runloop.run(&runner);
    try t.expect(!runner.aborted);
    // 0x1234 stored as a word at heap_addr; read back as a long -> high half is
    // 0x1234, low half 0 (zero-filled by brk growth) => exit status 0x12340000.
    try t.expectEqual(@as(?u32, 0x12340000), runner.exit_status);
}

test "dispatch table covers known syscalls without crashing arg decode" {
    // Smoke test: ensure enum mapping + name() are consistent for the numbers
    // we dispatch on. (Full behavioral tests live in the C-linked runloop
    // tests and Task 9 file-syscall tests.)
    try std.testing.expectEqualStrings("exit", (@as(abi.Syscall, @enumFromInt(1))).name());
    try std.testing.expectEqualStrings("write", (@as(abi.Syscall, @enumFromInt(4))).name());
    try std.testing.expectEqualStrings("getpid", (@as(abi.Syscall, @enumFromInt(20))).name());
    try std.testing.expectEqualStrings("UNKNOWN", (@as(abi.Syscall, @enumFromInt(200))).name());
}
