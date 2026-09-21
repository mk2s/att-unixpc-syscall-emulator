//! Process model: fork / exec / wait / pipe / _exit.
//!
//! This is the abstraction seam the plan calls for. Syscall handlers call
//! through `ProcessModel` so the backend can be swapped without touching them.
//! The default backend (`HostProcess`) maps guest processes onto host
//! processes: guest fork == host fork() (which copies the whole emulator,
//! including guest memory, for free); guest exec loads a new COFF into the
//! current address space; guest wait == host waitpid; guest pipe == host pipe
//! wired into the guest fd table.
//!
//! KNOWN LIMITATION: host fork() does not exist on Windows, so the host-process
//! backend is Linux/macOS only. The interface is designed so an in-process
//! backend (multiple CPU contexts in one host process) can replace it for
//! Windows without changing the syscall handlers. See docs and Task 14.

const std = @import("std");
const builtin = @import("builtin");
const abi = @import("abi.zig");
const mem = @import("mem.zig");
const cpu = @import("cpu.zig");
const coff = @import("coff.zig");
const proc = @import("process.zig");
const fsmod = @import("fs.zig");

// --- libc process primitives -----------------------------------------------
// fork/waitpid/pipe are POSIX-only. On Windows these symbols don't exist, so
// we only declare them off-Windows; the host backend returns NotSupported on
// Windows (see the ProcessModel seam / docs for the future in-process backend).
const is_posix = builtin.os.tag != .windows;
const libc = if (is_posix) struct {
    pub extern "c" fn fork() c_int;
    pub extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
    pub extern "c" fn pipe(fds: *[2]c_int) c_int;
    pub extern "c" fn getpid() c_int;
} else struct {};

pub const ProcError = error{ NotSupported, ForkFailed, ExecFailed, PipeFailed, NoChild };



/// Interface. A backend provides these; the host backend is below.
pub const ProcessModel = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// fork: returns child pid to parent, 0 to child, or error.
        fork: *const fn (ctx: *anyopaque) ProcError!u32,
        /// exec: replace the current image with the COFF at guest path.
        /// On success does not return (the caller's run loop continues at the
        /// new entry); on failure returns an errno.
        exec: *const fn (ctx: *anyopaque, path: []const u8, argv: []const []const u8, envp: []const []const u8) ProcError!void,
        /// wait: block for a child to exit; returns {pid, status-word}.
        wait: *const fn (ctx: *anyopaque) ProcError!WaitResult,
        /// pipe: create a pipe; returns two guest fds {read, write}.
        pipe: *const fn (ctx: *anyopaque) ProcError![2]u32,
    };

    pub fn doFork(self: ProcessModel) ProcError!u32 {
        return self.vtable.fork(self.ctx);
    }
    pub fn doExec(self: ProcessModel, path: []const u8, argv: []const []const u8, envp: []const []const u8) ProcError!void {
        return self.vtable.exec(self.ctx, path, argv, envp);
    }
    pub fn doWait(self: ProcessModel) ProcError!WaitResult {
        return self.vtable.wait(self.ctx);
    }
    pub fn doPipe(self: ProcessModel) ProcError![2]u32 {
        return self.vtable.pipe(self.ctx);
    }
};

pub const WaitResult = struct {
    pid: u32,
    /// SVR wait status word: low byte = signal/stop, high byte = exit code.
    /// For a normal exit(code): status = (code & 0xff) << 8.
    status: u32,
};

// ---------------------------------------------------------------------------
// Host-process backend.
// ---------------------------------------------------------------------------

pub const HostProcess = struct {
    memory: *mem.Memory,
    fs: *fsmod.Fs,
    /// Guest root for exec path resolution / new-image loading.
    guestroot: []const u8,
    allocator: std.mem.Allocator,
    /// Set by exec to signal the run loop to restart at a new entry point.
    exec_entry: ?u32 = null,
    /// Program break for the just-exec'd image (end of highest section). The
    /// syscall layer copies this into the Runner after a successful exec, so
    /// the new program's malloc/brk starts from the right place instead of
    /// inheriting the previous program's break (which corrupts the heap).
    new_brk: u32 = 0,

    pub fn model(self: *HostProcess) ProcessModel {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = ProcessModel.VTable{
        .fork = hostFork,
        .exec = hostExec,
        .wait = hostWait,
        .pipe = hostPipe,
    };

    fn hostFork(ctx: *anyopaque) ProcError!u32 {
        _ = ctx;
        if (!is_posix) return error.NotSupported;
        const rc = libc.fork();
        if (rc < 0) return error.ForkFailed;
        // In the child, rc==0; in the parent, rc==child pid. The child is a
        // full copy of this process (guest memory included), so it simply
        // continues emulating with fork() returning 0 in D0.
        return @intCast(rc);
    }

    fn hostExec(
        ctx: *anyopaque,
        path: []const u8,
        argv: []const []const u8,
        envp: []const []const u8,
    ) ProcError!void {
        const self: *HostProcess = @ptrCast(@alignCast(ctx));

        // Resolve the guest path to a host path and read the COFF.
        var hbuf: [1200]u8 = undefined;
        const hpath = self.fs.resolve(path, &hbuf) catch return error.ExecFailed;

        const bytes = readFileAlloc(self.allocator, hpath) catch return error.ExecFailed;
        defer self.allocator.free(bytes);

        // Parse first so we don't clobber memory on a bad image.
        var image = coff.parse(self.allocator, bytes) catch return error.ExecFailed;
        defer image.deinit();

        // Clear the guest address space regions and map the new image.
        self.memory.clearRegions();
        self.memory.enforce = false;
        // Discard the entire previous user address space (text/data/bss/heap/
        // stack). A real exec(2) replaces the address space wholesale and the
        // kernel hands the new program zero-filled memory; but our host-fork
        // backend copied the PARENT's guest memory, so without this the new
        // image would inherit the parent's stack/heap/bss bytes. That breaks
        // programs that read an uninitialized auto or bss slot (harmless on
        // real hardware where those are zero) — e.g. cc picks up a stale parent
        // stack pointer and faults. Zeroing here (before mapInto lays down the
        // new image, and before buildStack builds the fresh stack) makes exec
        // hand off a clean user space, matching UNIX semantics. The shlib
        // region and low null-read page are outside [VUSER_START,VUSER_END) and
        // are (re)established separately.
        self.memory.zero(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START);
        coff.mapInto(&image, self.memory, bytes) catch return error.ExecFailed;
        // Re-install the halt pad (clearRegions removed its mapping).
        @import("runloop.zig").installHaltPad(self.memory) catch {};

        // If the new image is shared-linked, map the shared library too.
        if (image.is_shared) {
            self.mapShlib() catch {}; // best-effort; guest will fault if truly needed
        }

        // Compute the new program break = end of the highest loaded section
        // (exact, not page-rounded — matches what crt0 hands to shlbat).
        var brk: u32 = abi.VUSER_START;
        for (image.sections) |*s| {
            const end = s.vaddr + s.size;
            if (end > brk and s.vaddr < abi.USRSTACK) brk = end;
        }
        self.new_brk = brk;

        // New stack + registers.
        try self.setupStackAndEntry(image, argv, envp);
        self.exec_entry = image.entry;
    }

    fn mapShlib(self: *HostProcess) !void {
        const shlib = @import("shlib.zig");
        var pbuf: [1200]u8 = undefined;
        const path = try std.fmt.bufPrint(&pbuf, "{s}/lib/shlib", .{self.guestroot});
        // NUL-terminate for libc open.
        var zpath: [1201]u8 = undefined;
        @memcpy(zpath[0..path.len], path);
        zpath[path.len] = 0;
        const bytes = try readFileAlloc(self.allocator, zpath[0..path.len :0]);
        defer self.allocator.free(bytes);
        try shlib.loadFromRoot(self.allocator, self.memory, bytes);
    }

    fn setupStackAndEntry(
        self: *HostProcess,
        image: coff.Image,
        argv: []const []const u8,
        envp: []const []const u8,
    ) ProcError!void {
        // Low memory read-only (see main.zig): page 0 present, null reads -> 0.
        self.memory.addRegion(0, abi.VUSER_START, .{ .read = true, .write = false, .exec = false }) catch {};
        // Give the user region rwx (details refined by loader perms already).
        self.memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch {};
        const layout = proc.buildStack(self.memory, abi.USRSTACK, argv, envp) catch return error.ExecFailed;
        proc.applyToCpu(image.entry, layout);
        self.memory.enforce = true;
    }

    fn hostWait(ctx: *anyopaque) ProcError!WaitResult {
        _ = ctx;
        if (!is_posix) return error.NotSupported;
        var status: c_int = 0;
        const pid = libc.waitpid(-1, &status, 0);
        if (pid < 0) {
            // ECHILD or other; report no child.
            return error.NoChild;
        }
        // Translate host wait status to the guest SVR status word. For a normal
        // exit, glibc encodes (code<<8); we re-encode canonically as (code&0xff)<<8.
        const exit_code: u32 = @intCast((@as(u32, @bitCast(status)) >> 8) & 0xff);
        const guest_status: u32 = (exit_code & 0xff) << 8;
        return .{ .pid = @intCast(pid), .status = guest_status };
    }

    fn hostPipe(ctx: *anyopaque) ProcError![2]u32 {
        if (!is_posix) return error.NotSupported;
        const self: *HostProcess = @ptrCast(@alignCast(ctx));
        var fds: [2]c_int = undefined;
        if (libc.pipe(&fds) < 0) return error.PipeFailed;
        const rfd = self.fs.allocFd(fds[0]) orelse return error.PipeFailed;
        const wfd = self.fs.allocFd(fds[1]) orelse return error.PipeFailed;
        return .{ rfd, wfd };
    }
};

fn readFileAlloc(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    const fd = fsmod.c.open(path.ptr, 0, 0); // O_RDONLY
    if (fd < 0) return error.OpenFailed;
    defer _ = fsmod.c.close(fd);
    var list: std.ArrayListUnmanaged(u8) = .empty;
    errdefer list.deinit(allocator);
    var buf: [8192]u8 = undefined;
    while (true) {
        const r = fsmod.c.read(fd, &buf, buf.len);
        if (r < 0) return error.ReadFailed;
        if (r == 0) break;
        try list.appendSlice(allocator, buf[0..@intCast(r)]);
    }
    return list.toOwnedSlice(allocator);
}

comptime {
    if (builtin.is_test) {
        _ = mem.Callbacks;
        _ = @import("runloop.zig").Hook;
    }
}

test "wait status encoding" {
    // exit(42) -> status word 42<<8 = 0x2A00
    const code: u32 = 42;
    const status: u32 = (code & 0xff) << 8;
    try std.testing.expectEqual(@as(u32, 0x2A00), status);
}
