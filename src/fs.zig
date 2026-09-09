//! Guest filesystem: chroot-style path resolution under a host guest-root
//! directory, plus a per-process file-descriptor table mapping guest fds to
//! host fds. All guest paths resolve under `root` and cannot escape it.
//!
//! Uses libc file ops directly (open/read/write/close/lseek/stat/...) for
//! stability across the churning std I/O API and to get real errno values.

const std = @import("std");
const abi = @import("abi.zig");

// --- libc bindings ---------------------------------------------------------
pub const c = struct {
    pub extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
    pub extern "c" fn close(fd: c_int) c_int;
    pub extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
    pub extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
    pub extern "c" fn lseek(fd: c_int, off: c_long, whence: c_int) c_long;
    pub extern "c" fn unlink(path: [*:0]const u8) c_int;
    pub extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;
    pub extern "c" fn dup(fd: c_int) c_int;
    pub extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
    pub extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
    pub extern "c" fn chown(path: [*:0]const u8, owner: c_uint, group: c_uint) c_int;
};

/// Portable errno accessor (src/host_stat.c). Avoids the glibc-specific
/// __errno_location, which doesn't exist on macOS/Windows.
pub extern fn upc_errno() c_int;

// Directory-stream shim (src/host_dir.c).
pub extern fn upc_diropen(path: [*:0]const u8) c_int;
pub extern fn upc_dirread(handle: c_int, ino_out: *c_ulong, name_out: [*]u8) c_int;
pub extern fn upc_dirclose(handle: c_int) void;

/// Host O_* flags (Linux/glibc values). We translate the guest's flags to
/// these. Guest values differ (see abi.zig).
const H_O_RDONLY: c_int = 0;
const H_O_WRONLY: c_int = 1;
const H_O_RDWR: c_int = 2;
const H_O_CREAT: c_int = 0o100;
const H_O_EXCL: c_int = 0o200;
const H_O_TRUNC: c_int = 0o1000;
const H_O_APPEND: c_int = 0o2000;
const H_O_NONBLOCK: c_int = 0o4000;

pub fn hostErrno() u16 {
    const e = upc_errno();
    return if (e < 0 or e > 65535) 22 else @intCast(e); // clamp to guest EINVAL
}

/// Translate guest open flags (abi.O_*) to host flags.
pub fn translateOpenFlags(guest: u32) c_int {
    var h: c_int = switch (guest & 0x3) {
        abi.O_WRONLY => H_O_WRONLY,
        abi.O_RDWR => H_O_RDWR,
        else => H_O_RDONLY,
    };
    if (guest & abi.O_CREAT != 0) h |= H_O_CREAT;
    if (guest & abi.O_EXCL != 0) h |= H_O_EXCL;
    if (guest & abi.O_TRUNC != 0) h |= H_O_TRUNC;
    if (guest & abi.O_APPEND != 0) h |= H_O_APPEND;
    if (guest & abi.O_NDELAY != 0) h |= H_O_NONBLOCK;
    return h;
}

pub const MAX_FD: usize = abi.NOFILE; // 80

pub const Fs = struct {
    /// Host directory that is the guest's root ("/"). No trailing slash.
    root: []const u8,
    /// Guest current working directory, always absolute, guest-relative
    /// (starts with '/'). Used to resolve relative paths.
    cwd: []u8,
    cwd_len: usize,
    /// fd table: guest fd -> host fd (or -1 if closed). fds 0,1,2 preassigned
    /// to host stdin/stdout/stderr.
    host_fd: [MAX_FD]i32,
    /// Directory-stream handle per fd (-1 if the fd is not a directory). The
    /// 3B1 reads directories with read(2), so we back those with opendir/readdir
    /// via the host_dir.c shim.
    dir_handle: [MAX_FD]i32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, root: []const u8) !Fs {
        var fs = Fs{
            .root = root,
            .cwd = try allocator.alloc(u8, 1024),
            .cwd_len = 1,
            .host_fd = undefined,
            .dir_handle = undefined,
            .allocator = allocator,
        };
        fs.cwd[0] = '/';
        for (&fs.host_fd) |*h| h.* = -1;
        for (&fs.dir_handle) |*d| d.* = -1;
        fs.host_fd[0] = 0;
        fs.host_fd[1] = 1;
        fs.host_fd[2] = 2;
        return fs;
    }

    pub fn deinit(self: *Fs) void {
        // Close any open guest fds > 2.
        var i: usize = 3;
        while (i < MAX_FD) : (i += 1) {
            if (self.host_fd[i] >= 0) _ = c.close(self.host_fd[i]);
        }
        self.allocator.free(self.cwd);
    }

    fn cwdSlice(self: *const Fs) []const u8 {
        return self.cwd[0..self.cwd_len];
    }

    /// Resolve a guest path to a host path under `root`, collapsing "." and
    /// ".." and preventing escape above root. Writes a NUL-terminated host
    /// path into `out`; returns the slice (without NUL) or error.
    pub fn resolve(self: *const Fs, guest_path: []const u8, out: []u8) ![:0]const u8 {
        // Build the absolute guest path (relative to cwd if not absolute).
        var abspath: [2048]u8 = undefined;
        var n: usize = 0;
        if (guest_path.len == 0) return error.BadPath;
        if (guest_path[0] != '/') {
            const cw = self.cwdSlice();
            @memcpy(abspath[0..cw.len], cw);
            n = cw.len;
            if (n == 0 or abspath[n - 1] != '/') {
                abspath[n] = '/';
                n += 1;
            }
        }
        if (n + guest_path.len > abspath.len) return error.NameTooLong;
        @memcpy(abspath[n .. n + guest_path.len], guest_path);
        n += guest_path.len;

        // Canonicalize into components, applying . and ..
        var comps: [64][]const u8 = undefined;
        var ncomp: usize = 0;
        var it = std.mem.tokenizeScalar(u8, abspath[0..n], '/');
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp, ".")) continue;
            if (std.mem.eql(u8, comp, "..")) {
                if (ncomp > 0) ncomp -= 1; // clamp at root: cannot escape
                continue;
            }
            if (ncomp >= comps.len) return error.NameTooLong;
            comps[ncomp] = comp;
            ncomp += 1;
        }

        // Assemble host path: root + "/" + components.
        var w: usize = 0;
        if (self.root.len + 1 > out.len) return error.NameTooLong;
        @memcpy(out[0..self.root.len], self.root);
        w = self.root.len;
        var ci: usize = 0;
        while (ci < ncomp) : (ci += 1) {
            if (w + 1 + comps[ci].len + 1 > out.len) return error.NameTooLong;
            out[w] = '/';
            w += 1;
            @memcpy(out[w .. w + comps[ci].len], comps[ci]);
            w += comps[ci].len;
        }
        if (w == self.root.len) {
            // Root itself.
            if (w + 1 >= out.len) return error.NameTooLong;
            out[w] = '/';
            w += 1;
        }
        out[w] = 0;
        return out[0..w :0];
    }

    /// Allocate the LOWEST free guest fd and map it to `hfd`. Starts from 0 so
    /// that the classic "close(1); dup(x)" redirection idiom works: a closed
    /// standard fd (0/1/2) becomes available for reuse, matching Unix dup(2)
    /// which always returns the lowest free descriptor.
    pub fn allocFd(self: *Fs, hfd: i32) ?u32 {
        var i: usize = 0;
        while (i < MAX_FD) : (i += 1) {
            if (self.host_fd[i] < 0) {
                self.host_fd[i] = hfd;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn get(self: *const Fs, gfd: u32) ?i32 {
        if (gfd >= MAX_FD) return null;
        const h = self.host_fd[gfd];
        return if (h < 0) null else h;
    }

    pub fn closeFd(self: *Fs, gfd: u32) bool {
        if (gfd >= MAX_FD) return false;
        const h = self.host_fd[gfd];
        if (h < 0) return false;
        // Close an associated directory stream, if any.
        if (self.dir_handle[gfd] >= 0) {
            upc_dirclose(self.dir_handle[gfd]);
            self.dir_handle[gfd] = -1;
        }
        // Don't actually close host stdio (0,1,2) — just detach.
        if (gfd > 2) _ = c.close(h);
        self.host_fd[gfd] = -1;
        return true;
    }

    /// Mark an allocated guest fd as a directory backed by dir-stream `handle`.
    pub fn setDir(self: *Fs, gfd: u32, handle: c_int) void {
        if (gfd < MAX_FD) self.dir_handle[gfd] = handle;
    }

    pub fn dirOf(self: *const Fs, gfd: u32) ?c_int {
        if (gfd >= MAX_FD) return null;
        const h = self.dir_handle[gfd];
        return if (h < 0) null else h;
    }

    /// Change the guest cwd (guest-absolute path). Validates it resolves.
    pub fn chdir(self: *Fs, guest_path: []const u8) !void {
        // Compute the canonical guest-absolute path (same algorithm as resolve
        // but keep it guest-relative for storing as cwd).
        var abspath: [2048]u8 = undefined;
        var n: usize = 0;
        if (guest_path.len == 0) return error.BadPath;
        if (guest_path[0] != '/') {
            const cw = self.cwdSlice();
            @memcpy(abspath[0..cw.len], cw);
            n = cw.len;
            if (n == 0 or abspath[n - 1] != '/') {
                abspath[n] = '/';
                n += 1;
            }
        }
        @memcpy(abspath[n .. n + guest_path.len], guest_path);
        n += guest_path.len;

        var comps: [64][]const u8 = undefined;
        var ncomp: usize = 0;
        var it = std.mem.tokenizeScalar(u8, abspath[0..n], '/');
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp, ".")) continue;
            if (std.mem.eql(u8, comp, "..")) {
                if (ncomp > 0) ncomp -= 1;
                continue;
            }
            comps[ncomp] = comp;
            ncomp += 1;
        }
        // Rebuild guest cwd string.
        var w: usize = 0;
        self.cwd[0] = '/';
        w = 1;
        var ci: usize = 0;
        while (ci < ncomp) : (ci += 1) {
            if (w > 1) {
                self.cwd[w] = '/';
                w += 1;
            }
            @memcpy(self.cwd[w .. w + comps[ci].len], comps[ci]);
            w += comps[ci].len;
        }
        self.cwd_len = if (w == 1) 1 else w;
    }
};

// ---------------------------------------------------------------------------
// Tests (path resolution — no host FS access needed)
// ---------------------------------------------------------------------------

test "resolve stays under root" {
    var fs = try Fs.init(std.testing.allocator, "/guestroot");
    defer fs.deinit();
    var out: [512]u8 = undefined;

    try std.testing.expectEqualStrings("/guestroot/bin/echo", try fs.resolve("/bin/echo", &out));
    try std.testing.expectEqualStrings("/guestroot/etc/passwd", try fs.resolve("/etc/../etc/passwd", &out));
    // escape attempts are clamped at root
    try std.testing.expectEqualStrings("/guestroot/x", try fs.resolve("/../../../x", &out));
    try std.testing.expectEqualStrings("/guestroot/", try fs.resolve("/", &out));
}

test "relative paths resolve against cwd" {
    var fs = try Fs.init(std.testing.allocator, "/gr");
    defer fs.deinit();
    var out: [512]u8 = undefined;
    try fs.chdir("/usr/bin");
    try std.testing.expectEqualStrings("/usr/bin", fs.cwd[0..fs.cwd_len]);
    try std.testing.expectEqualStrings("/gr/usr/bin/cc", try fs.resolve("cc", &out));
    try std.testing.expectEqualStrings("/gr/usr/lib", try fs.resolve("../lib", &out));
}

test "fd table alloc and close" {
    var fs = try Fs.init(std.testing.allocator, "/gr");
    defer fs.deinit();
    try std.testing.expectEqual(@as(i32, 0), fs.get(0).?);
    try std.testing.expectEqual(@as(i32, 1), fs.get(1).?);
    // With 0/1/2 open, the lowest free fd is 3.
    const g = fs.allocFd(99).?;
    try std.testing.expectEqual(@as(u32, 3), g);
    try std.testing.expectEqual(@as(i32, 99), fs.get(3).?);
    fs.host_fd[3] = -1; // detach without closing bogus host fd 99
    try std.testing.expect(fs.get(3) == null);
    // After closing fd 1, allocFd reuses it (lowest free) — the redirection idiom.
    _ = fs.closeFd(1);
    const g1 = fs.allocFd(77).?;
    try std.testing.expectEqual(@as(u32, 1), g1);
}
