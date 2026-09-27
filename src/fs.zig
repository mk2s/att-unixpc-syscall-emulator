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
    // Positional read: read `n` bytes at absolute `off` WITHOUT moving the fd's
    // file position. Used to fetch the disk VHB for the GDGETA ioctl while the
    // guest may hold its own current offset.
    pub extern "c" fn pread(fd: c_int, buf: [*]u8, n: usize, off: c_long) isize;
    /// Positional write at absolute `off` without moving the fd position.
    pub extern "c" fn pwrite(fd: c_int, buf: [*]const u8, n: usize, off: c_long) isize;
    pub extern "c" fn unlink(path: [*:0]const u8) c_int;
    pub extern "c" fn link(oldp: [*:0]const u8, newp: [*:0]const u8) c_int;
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

pub fn hostErrno() u16 {
    const e = upc_errno();
    return if (e < 0 or e > 65535) 22 else @intCast(e); // clamp to guest EINVAL
}

/// Translate guest open flags (abi.O_*) to the host's O_* flags as a c_int
/// suitable for the C library open().
///
/// The host flag values are OS-specific (e.g. O_CREAT is 0o100 on Linux but
/// 0x0200 on macOS). Using std.c.O — a per-target packed struct — keeps this
/// correct across hosts instead of hardcoding Linux/glibc values.
pub fn translateOpenFlags(guest: u32) c_int {
    var o: std.c.O = .{};
    o.ACCMODE = switch (guest & 0x3) {
        abi.O_WRONLY => .WRONLY,
        abi.O_RDWR => .RDWR,
        else => .RDONLY,
    };
    if (guest & abi.O_CREAT != 0) o.CREAT = true;
    if (guest & abi.O_EXCL != 0) o.EXCL = true;
    if (guest & abi.O_TRUNC != 0) o.TRUNC = true;
    if (guest & abi.O_APPEND != 0) o.APPEND = true;
    if (guest & abi.O_NDELAY != 0) o.NONBLOCK = true;
    return @bitCast(o);
}

pub const MAX_FD: usize = abi.NOFILE; // 80

/// A guest-device-path -> host-file mapping (from `--map-device G=H`).
/// When the guest opens `guest` (a raw device like /dev/rfp002), the open is
/// redirected to the host file `host` instead of resolving under `root`. This
/// lets tools like fsck operate on a disk *image* file on the host. `guest` is
/// stored in canonical guest-absolute form (leading '/', no '.'/'..'); `host`
/// is a NUL-terminated host path passed straight to open(2).
///
/// The mapping backs a whole physical drive: `drive` is decoded from the
/// mapping's device name (e.g. /dev/rfp002 -> drive 0). Any sibling slice on
/// the SAME drive (/dev/rfp000, /dev/rfp001, ...) then resolves to this same
/// image, with the partition offset for that slice computed from the image's
/// VHB at open time — mirroring how the real UnixPC gd driver keys off the
/// minor number. If the name can't be decoded, `drive` is null and only the
/// exact `guest` path matches.
pub const DeviceMap = struct {
    guest: []const u8,
    host: [:0]const u8,
    drive: ?u8 = null,
};

/// Decoded UnixPC disk device identity: drive (0..3) and slice/partition
/// (0..15), per <sys/gdisk.h> minor-number encoding.
pub const DiskId = struct { drive: u8, slice: u8 };

/// Per-device-fd geometry for translating a partition-relative *logical* byte
/// offset (what the guest/filesystem uses) into a *physical* image byte offset
/// (what freebee-style / raw-capture images store).
///
/// The UnixPC gd driver maps logical sectors around the alternate (17th)
/// sector of each track: only `sectrk = psectrk & ~1` sectors per track are in
/// the logical map, but the physical image has all `psectrk` sectors present.
/// So for a partition starting at track `strk`:
///   co        = strk*sectrk + logical_sector            (absolute logical sector)
///   phys_sec  = (co / sectrk)*psectrk + (co % sectrk)    (skip the spare sector)
///   phys_byte = phys_sec * secsz  (+ intra-sector remainder)
/// When psectrk is even (no spare sector) this reduces to a plain base offset.
pub const DeviceGeom = struct {
    active: bool = false,
    strk: u32 = 0, // partition start track
    psectrk: u32 = 1, // physical sectors per track (e.g. 17)
    sectrk: u32 = 1, // logical sectors per track (psectrk & ~1, e.g. 16)
    secsz: u32 = 512, // bytes per sector
    log_pos: i64 = 0, // current partition-relative logical byte position

    /// Translate a partition-relative logical byte offset to a physical image
    /// byte offset. Callers must not cross a logical-sector boundary in a
    /// single call (chunk at secsz); the intra-sector remainder is preserved.
    pub fn physOf(self: *const DeviceGeom, logical_off: i64) i64 {
        const secsz: i64 = @intCast(self.secsz);
        const sectrk: i64 = @intCast(self.sectrk);
        const psectrk: i64 = @intCast(self.psectrk);
        const strk: i64 = @intCast(self.strk);
        const logsec = @divFloor(logical_off, secsz);
        const rem = logical_off - logsec * secsz;
        const co = strk * sectrk + logsec;
        const phys_sec = @divFloor(co, sectrk) * psectrk + @mod(co, sectrk);
        return phys_sec * secsz + rem;
    }
};

/// Parse a UnixPC raw/block disk device path or name into {drive, slice}.
///
/// Names are `[r]fp<hex>` where <hex> is the minor number in hexadecimal
/// (e.g. rfp002 -> minor 0x02, fp021 -> minor 0x21, rfp100 -> minor 0x100).
/// Per <sys/gdisk.h>: slice = minor & 0xF (low 4 bits), drive = (minor>>4) & 3.
/// Accepts a full path (uses the last component) or a bare name. Returns null
/// if it isn't a decodable fp/rfp disk name.
pub fn parseDiskName(path: []const u8) ?DiskId {
    // Take the last path component.
    var name = path;
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| name = path[i + 1 ..];
    // Optional leading 'r' (raw/character device).
    if (name.len > 0 and name[0] == 'r') name = name[1..];
    // Require the "fp" prefix.
    if (name.len < 3 or name[0] != 'f' or name[1] != 'p') return null;
    const hex = name[2..];
    if (hex.len == 0) return null;
    const minor = std.fmt.parseInt(u32, hex, 16) catch return null;
    return .{
        .drive = @intCast((minor >> 4) & 0x3), // DRVSHIFT=4, DRVMSK=3
        .slice = @intCast(minor & 0xF), // SLCMSK=0xF
    };
}

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
    /// Per-fd flag: true if this fd is a mapped raw device (from --map-device).
    /// Device fds answer disk ioctls (GDGETA) from the image VHB instead of the
    /// blanket ENOTTY stub. Parallel to host_fd/dir_handle.
    is_device: [MAX_FD]bool,
    /// Per-fd device geometry (logical<->physical sector interleave + logical
    /// position cursor). Only meaningful when is_device[fd] is true.
    dev_geom: [MAX_FD]DeviceGeom,
    /// Raw-device -> host-image mappings from `--map-device`. Consulted by the
    /// open path before normal root-relative resolution. Empty by default.
    device_map: []const DeviceMap,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, root: []const u8, device_map: []const DeviceMap) !Fs {
        var fs = Fs{
            .root = root,
            .cwd = try allocator.alloc(u8, 1024),
            .cwd_len = 1,
            .host_fd = undefined,
            .dir_handle = undefined,
            .is_device = undefined,
            .dev_geom = undefined,
            .device_map = device_map,
            .allocator = allocator,
        };
        fs.cwd[0] = '/';
        for (&fs.host_fd) |*h| h.* = -1;
        for (&fs.dir_handle) |*d| d.* = -1;
        for (&fs.is_device) |*d| d.* = false;
        for (&fs.dev_geom) |*g| g.* = .{};
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

    /// Canonicalize a guest path to guest-absolute form (leading '/', with
    /// '.'/'..' collapsed and clamped at root), writing into `out`. Returns the
    /// slice. This is the same normalization `resolve` applies before it
    /// prepends `root`; factored out so device-map lookups match on the exact
    /// same canonical form the resolver would produce.
    pub fn canonicalizeGuest(self: *const Fs, guest_path: []const u8, out: []u8) ![]const u8 {
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

        var comps: [64][]const u8 = undefined;
        var ncomp: usize = 0;
        var it = std.mem.tokenizeScalar(u8, abspath[0..n], '/');
        while (it.next()) |comp| {
            if (std.mem.eql(u8, comp, ".")) continue;
            if (std.mem.eql(u8, comp, "..")) {
                if (ncomp > 0) ncomp -= 1;
                continue;
            }
            if (ncomp >= comps.len) return error.NameTooLong;
            comps[ncomp] = comp;
            ncomp += 1;
        }

        var w: usize = 0;
        if (out.len == 0) return error.NameTooLong;
        out[w] = '/';
        w += 1;
        var ci: usize = 0;
        while (ci < ncomp) : (ci += 1) {
            if (ci > 0) {
                if (w + 1 > out.len) return error.NameTooLong;
                out[w] = '/';
                w += 1;
            }
            if (w + comps[ci].len > out.len) return error.NameTooLong;
            @memcpy(out[w .. w + comps[ci].len], comps[ci]);
            w += comps[ci].len;
        }
        return out[0..w];
    }

    /// Result of a device lookup: which host image backs the open, and which
    /// disk slice (partition) the guest asked for.
    pub const DeviceHit = struct { host: [:0]const u8, slice: u8 };

    /// If `guest_path` names a mapped raw device, return the host image to open
    /// and the requested slice. Matches two ways:
    ///   1. Exact canonical path equal to a mapping's `guest` (always works,
    ///      even for names we can't decode).
    ///   2. Any `[r]fp<hex>` disk name whose DRIVE equals a mapping's drive —
    ///      so one `--map-device /dev/rfp002=img` mapping also serves
    ///      /dev/rfp000, /dev/rfp001, ... on the same drive, each with its own
    ///      slice (offset computed later from the image VHB).
    /// Returns null if unmapped; the caller then does normal root resolution.
    pub fn deviceLookup(self: *const Fs, guest_path: []const u8) ?DeviceHit {
        if (self.device_map.len == 0) return null;
        var cbuf: [2048]u8 = undefined;
        const canon = self.canonicalizeGuest(guest_path, &cbuf) catch return null;
        const id = parseDiskName(canon);
        for (self.device_map) |dm| {
            // Exact match: use the mapping's own slice if decodable, else 0.
            if (std.mem.eql(u8, dm.guest, canon)) {
                const slice: u8 = if (parseDiskName(dm.guest)) |mid| mid.slice else 0;
                return .{ .host = dm.host, .slice = slice };
            }
            // Same-drive match: this disk name belongs to a mapped drive.
            if (id) |gid| {
                if (dm.drive) |ddrive| {
                    if (gid.drive == ddrive) return .{ .host = dm.host, .slice = gid.slice };
                }
            }
        }
        return null;
    }

    /// Back-compat helper: just the host image path (used where the slice is
    /// irrelevant). Returns null if unmapped.
    pub fn deviceHostPath(self: *const Fs, guest_path: []const u8) ?[:0]const u8 {
        return if (self.deviceLookup(guest_path)) |h| h.host else null;
    }

    /// Allocate the LOWEST free guest fd and map it to `hfd`. Starts from 0 so
    /// that the classic "close(1); dup(x)" redirection idiom works: a closed
    /// standard fd (0/1/2) becomes available for reuse, matching Unix dup(2)
    /// which always returns the lowest free descriptor.
    pub fn allocFd(self: *Fs, hfd: i32) ?u32 {
        return self.allocFdFrom(hfd, 0);
    }

    /// Allocate the lowest free guest fd that is >= `min`, mapping it to `hfd`.
    /// This is the fcntl(F_DUPFD, min) contract: the shell relocates a script
    /// fd to a high number (e.g. 19) and then reads from exactly that number,
    /// so honoring `min` is required for the ENOEXEC "run as shell script"
    /// fallback to work.
    pub fn allocFdFrom(self: *Fs, hfd: i32, min: u32) ?u32 {
        var i: usize = @min(min, MAX_FD);
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
        self.is_device[gfd] = false;
        self.dev_geom[gfd] = .{};
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

    /// Mark an allocated guest fd as a mapped raw device (backed by a disk
    /// image). Disk ioctls on it are served from the image VHB.
    pub fn setDevice(self: *Fs, gfd: u32) void {
        if (gfd < MAX_FD) self.is_device[gfd] = true;
    }

    pub fn isDevice(self: *const Fs, gfd: u32) bool {
        return gfd < MAX_FD and self.is_device[gfd];
    }

    /// Set the per-fd device geometry (from the VHB at open time).
    pub fn setDeviceGeom(self: *Fs, gfd: u32, geom: DeviceGeom) void {
        if (gfd < MAX_FD) self.dev_geom[gfd] = geom;
    }

    /// Mutable pointer to a device fd's geometry (for updating log_pos), or
    /// null if the fd isn't an active device.
    pub fn devGeom(self: *Fs, gfd: u32) ?*DeviceGeom {
        if (gfd >= MAX_FD) return null;
        return if (self.dev_geom[gfd].active) &self.dev_geom[gfd] else null;
    }

    /// Read the image VHB (via pread at absolute 0, not moving the fd position)
    /// and build the DeviceGeom for disk `slice`: its start track plus the
    /// physical/logical sectors-per-track needed for the interleave translation
    /// done by DeviceGeom.physOf.
    ///
    /// We store the FULL physical geometry (psectrk, e.g. 17), matching the
    /// on-disk image layout used by freebee (the hardware-level UnixPC
    /// emulator) and by raw MFM captures: freebee's WD2010 seeks with
    /// lba = (track*heads*spt + head*spt + sector)*secsz where spt=psectrk, and
    /// both freebee .dsk images and real captures have file size exactly
    /// cyls*heads*psectrk*sectorsz. The logical filesystem written by the real
    /// gd(7) driver uses sectrk = psectrk & ~1 (the 17th sector of each track
    /// is a spare), so physOf skips that spare per track when translating
    /// logical filesystem offsets to physical image offsets.
    ///
    /// `error.BadVhb` if the magic is wrong or the table can't be decoded.
    pub fn readDeviceGeom(hfd: i32, slice: u8) !DeviceGeom {
        var vhb: [512]u8 = undefined;
        const n = c.pread(hfd, &vhb, vhb.len, 0);
        if (n < @as(isize, @intCast(vhb.len))) return error.BadVhb;
        const be32 = struct {
            fn f(b: []const u8) u32 {
                return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) |
                    (@as(u32, b[2]) << 8) | @as(u32, b[3]);
            }
        }.f;
        const be16 = struct {
            fn f(b: []const u8) u16 {
                return (@as(u16, b[0]) << 8) | @as(u16, b[1]);
            }
        }.f;
        if (be32(vhb[0..4]) != abi.VHBMAGIC) return error.BadVhb;
        // gdswprt @8: psectrk@+10 (=vhb 18), sectorsz@+16 (=vhb 24), flags@+14 (=vhb 22).
        const psectrk = be16(vhb[18..20]);
        const sectorsz = be16(vhb[24..26]);
        const flags = vhb[22];
        const new_style = (flags & 0x08) != 0; // NEWPARTTAB
        if (slice >= 16) return error.BadVhb;
        // partab @ 8 + sizeof(gdswprt=18) = 26; entries are 4 bytes each.
        const ent = 26 + @as(usize, slice) * 4;
        const strk: u32 = if (new_style)
            be32(vhb[ent .. ent + 4])
        else
            be16(vhb[ent .. ent + 2]); // old style: start track is a u16
        const sectrk: u32 = if (psectrk >= 2) psectrk & ~@as(u32, 1) else psectrk;
        return .{
            .active = true,
            .strk = strk,
            .psectrk = psectrk,
            .sectrk = sectrk,
            .secsz = if (sectorsz == 0) 512 else sectorsz,
            .log_pos = 0,
        };
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
    var fs = try Fs.init(std.testing.allocator, "/guestroot", &.{});
    defer fs.deinit();
    var out: [512]u8 = undefined;

    try std.testing.expectEqualStrings("/guestroot/bin/echo", try fs.resolve("/bin/echo", &out));
    try std.testing.expectEqualStrings("/guestroot/etc/passwd", try fs.resolve("/etc/../etc/passwd", &out));
    // escape attempts are clamped at root
    try std.testing.expectEqualStrings("/guestroot/x", try fs.resolve("/../../../x", &out));
    try std.testing.expectEqualStrings("/guestroot/", try fs.resolve("/", &out));
}

test "relative paths resolve against cwd" {
    var fs = try Fs.init(std.testing.allocator, "/gr", &.{});
    defer fs.deinit();
    var out: [512]u8 = undefined;
    try fs.chdir("/usr/bin");
    try std.testing.expectEqualStrings("/usr/bin", fs.cwd[0..fs.cwd_len]);
    try std.testing.expectEqualStrings("/gr/usr/bin/cc", try fs.resolve("cc", &out));
    try std.testing.expectEqualStrings("/gr/usr/lib", try fs.resolve("../lib", &out));
}

test "fd table alloc and close" {
    var fs = try Fs.init(std.testing.allocator, "/gr", &.{});
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

test "device map resolves guest device path to host image" {
    const maps = [_]DeviceMap{
        .{ .guest = "/dev/rfp002", .host = "disk.img" },
        .{ .guest = "/dev/rfp000", .host = "/tmp/root.img" },
    };
    var fs = try Fs.init(std.testing.allocator, "/gr", &maps);
    defer fs.deinit();

    // Exact match.
    try std.testing.expectEqualStrings("disk.img", fs.deviceHostPath("/dev/rfp002").?);
    try std.testing.expectEqualStrings("/tmp/root.img", fs.deviceHostPath("/dev/rfp000").?);

    // Canonicalization: '.'/'..' and redundant slashes still match the mapping.
    try std.testing.expectEqualStrings("disk.img", fs.deviceHostPath("/dev/./rfp002").?);
    try std.testing.expectEqualStrings("disk.img", fs.deviceHostPath("//dev/foo/../rfp002").?);

    // Relative device path resolves against cwd before matching.
    try fs.chdir("/dev");
    try std.testing.expectEqualStrings("disk.img", fs.deviceHostPath("rfp002").?);

    // Non-mapped paths return null (fall through to normal resolution).
    try std.testing.expect(fs.deviceHostPath("/dev/rfp999") == null);
    try std.testing.expect(fs.deviceHostPath("/etc/passwd") == null);
}

test "empty device map never matches" {
    var fs = try Fs.init(std.testing.allocator, "/gr", &.{});
    defer fs.deinit();
    try std.testing.expect(fs.deviceHostPath("/dev/rfp002") == null);
}
