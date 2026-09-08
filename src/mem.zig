//! Guest address space model for the UNIX PC user-mode emulator.
//!
//! A flat, big-endian backing store covering the guest virtual address range
//! up to SHLIB_END (0x380000). Coarse region permissions are enforced; an
//! out-of-range or permission-violating access records a fault which the run
//! loop turns into a fail-fast diagnostic (Task 8). Task 7's run loop and
//! Task 4's Musashi callbacks route through the global `active` instance,
//! because Musashi's C callbacks carry no user-data pointer.

const std = @import("std");
const abi = @import("abi.zig");

pub const Perm = packed struct {
    read: bool = false,
    write: bool = false,
    exec: bool = false,
};

pub const FaultKind = enum { none, unmapped, no_read, no_write, no_exec };

pub const Fault = struct {
    kind: FaultKind = .none,
    address: u32 = 0,
    /// PC at time of fault, filled by the run loop if known.
    pc: u32 = 0,
};

/// A contiguous permission region [start, start+len).
pub const Region = struct {
    start: u32,
    len: u32,
    perm: Perm,

    fn contains(self: Region, addr: u32) bool {
        return addr >= self.start and addr < self.start +% self.len;
    }
};

pub const Memory = struct {
    /// Backing store sized to cover the whole guest range [0, size).
    bytes: []u8,
    /// Permission regions (checked in order; first match wins).
    regions: std.ArrayListUnmanaged(Region) = .empty,
    allocator: std.mem.Allocator,
    /// Last fault recorded (sticky until cleared by the run loop).
    fault: Fault = .{},
    /// When true, permission checks are enforced. Disabled during loading.
    enforce: bool = false,

    /// Total addressable size. We cover up to SHLIB_END.
    pub const size: u32 = abi.SHLIB_END; // 0x380000 = 3.5 MiB

    pub fn init(allocator: std.mem.Allocator) !Memory {
        const buf = try allocator.alloc(u8, size);
        @memset(buf, 0);
        return Memory{ .bytes = buf, .allocator = allocator };
    }

    pub fn deinit(self: *Memory) void {
        self.regions.deinit(self.allocator);
        self.allocator.free(self.bytes);
    }

    pub fn addRegion(self: *Memory, start: u32, len: u32, perm: Perm) !void {
        try self.regions.append(self.allocator, .{ .start = start, .len = len, .perm = perm });
    }

    pub fn clearRegions(self: *Memory) void {
        self.regions.clearRetainingCapacity();
    }

    pub fn clearFault(self: *Memory) void {
        self.fault = .{};
    }

    fn permFor(self: *const Memory, addr: u32) ?Perm {
        for (self.regions.items) |r| {
            if (r.contains(addr)) return r.perm;
        }
        return null;
    }

    fn recordFault(self: *Memory, kind: FaultKind, addr: u32) void {
        if (self.fault.kind == .none) {
            self.fault = .{ .kind = kind, .address = addr };
        }
    }

    /// Check an access of `n` bytes at `addr` for `kind` of permission.
    /// Returns false and records a fault on violation.
    fn checkAccess(self: *Memory, addr: u32, n: u32, comptime want: enum { read, write, exec }) bool {
        // Range check first.
        if (addr > size or n > size or addr +% n > size) {
            self.recordFault(.unmapped, addr);
            return false;
        }
        if (!self.enforce) return true;
        const p = self.permFor(addr) orelse {
            self.recordFault(.unmapped, addr);
            return false;
        };
        switch (want) {
            .read => if (!p.read) {
                self.recordFault(.no_read, addr);
                return false;
            },
            .write => if (!p.write) {
                self.recordFault(.no_write, addr);
                return false;
            },
            .exec => if (!p.exec) {
                self.recordFault(.no_exec, addr);
                return false;
            },
        }
        return true;
    }

    // -- Big-endian typed access (guest is big-endian) ----------------------

    pub fn read8(self: *Memory, addr: u32) u8 {
        if (!self.checkAccess(addr, 1, .read)) return 0;
        return self.bytes[addr];
    }
    pub fn read16(self: *Memory, addr: u32) u16 {
        if (!self.checkAccess(addr, 2, .read)) return 0;
        return std.mem.readInt(u16, self.bytes[addr..][0..2], .big);
    }
    pub fn read32(self: *Memory, addr: u32) u32 {
        if (!self.checkAccess(addr, 4, .read)) return 0;
        return std.mem.readInt(u32, self.bytes[addr..][0..4], .big);
    }

    pub fn write8(self: *Memory, addr: u32, value: u8) void {
        if (!self.checkAccess(addr, 1, .write)) return;
        self.bytes[addr] = value;
    }
    pub fn write16(self: *Memory, addr: u32, value: u16) void {
        if (!self.checkAccess(addr, 2, .write)) return;
        std.mem.writeInt(u16, self.bytes[addr..][0..2], value, .big);
    }
    pub fn write32(self: *Memory, addr: u32, value: u32) void {
        if (!self.checkAccess(addr, 4, .write)) return;
        std.mem.writeInt(u32, self.bytes[addr..][0..4], value, .big);
    }

    // -- Bulk helpers (used by the loader / stack setup) --------------------

    /// Copy host bytes into guest memory, bypassing permission enforcement
    /// (used during loading). Range-checked.
    pub fn writeBytes(self: *Memory, addr: u32, src: []const u8) void {
        const end = addr +% @as(u32, @intCast(src.len));
        if (end > size or end < addr) {
            self.recordFault(.unmapped, addr);
            return;
        }
        @memcpy(self.bytes[addr..end], src);
    }

    /// Read a NUL-terminated guest C string starting at addr into a slice of
    /// the caller-provided buffer. Returns the string (without NUL).
    pub fn readCStr(self: *Memory, addr: u32, buf: []u8) []const u8 {
        var i: u32 = 0;
        while (i < buf.len) : (i += 1) {
            const a = addr + i;
            if (a >= size) break;
            const ch = self.bytes[a];
            if (ch == 0) break;
            buf[i] = ch;
        }
        return buf[0..i];
    }

    pub fn zero(self: *Memory, addr: u32, len: u32) void {
        const end = addr +% len;
        if (end > size or end < addr) {
            self.recordFault(.unmapped, addr);
            return;
        }
        @memset(self.bytes[addr..end], 0);
    }
};

// ---------------------------------------------------------------------------
// Global active instance + Musashi C callbacks.
//
// Musashi's read/write callbacks are global C functions with no user pointer,
// so we route them through a module-global pointer set by the run loop.
// ---------------------------------------------------------------------------

pub var active: ?*Memory = null;

pub fn setActive(m: ?*Memory) void {
    active = m;
}

// These are the real (non-test) Musashi callbacks. main.zig must NOT also
// define them; it should `_ = @import("mem.zig")` (or reference Callbacks) so
// the linker pulls these in. Guarded to non-test builds to avoid clashing with
// cpu.zig's test callbacks.
const builtin = @import("builtin");

pub const Callbacks = struct {
    export fn m68k_read_memory_8(address: c_uint) callconv(.c) c_uint {
        const m = active orelse return 0;
        return m.read8(@intCast(address));
    }
    export fn m68k_read_memory_16(address: c_uint) callconv(.c) c_uint {
        const m = active orelse return 0;
        return m.read16(@intCast(address));
    }
    export fn m68k_read_memory_32(address: c_uint) callconv(.c) c_uint {
        const m = active orelse return 0;
        return m.read32(@intCast(address));
    }
    export fn m68k_write_memory_8(address: c_uint, value: c_uint) callconv(.c) void {
        const m = active orelse return;
        m.write8(@intCast(address), @truncate(value));
    }
    export fn m68k_write_memory_16(address: c_uint, value: c_uint) callconv(.c) void {
        const m = active orelse return;
        m.write16(@intCast(address), @truncate(value));
    }
    export fn m68k_write_memory_32(address: c_uint, value: c_uint) callconv(.c) void {
        const m = active orelse return;
        m.write32(@intCast(address), @truncate(value));
    }
    export fn m68k_read_disassembler_8(address: c_uint) callconv(.c) c_uint {
        const m = active orelse return 0;
        if (address >= Memory.size) return 0;
        return m.bytes[@intCast(address)];
    }
    export fn m68k_read_disassembler_16(address: c_uint) callconv(.c) c_uint {
        return (m68k_read_disassembler_8(address) << 8) | m68k_read_disassembler_8(address + 1);
    }
    export fn m68k_read_disassembler_32(address: c_uint) callconv(.c) c_uint {
        return (m68k_read_disassembler_16(address) << 16) | m68k_read_disassembler_16(address + 2);
    }
    // NOTE: upc_instr_hook lives in runloop.zig (Hook), which the executable
    // pulls in. m68kconf.h binds M68K_INSTRUCTION_CALLBACK -> upc_instr_hook.
};

comptime {
    _ = Callbacks;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "big-endian round trips" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.enforce = false;

    m.write32(0x1000, 0x11223344);
    try std.testing.expectEqual(@as(u8, 0x11), m.read8(0x1000));
    try std.testing.expectEqual(@as(u8, 0x22), m.read8(0x1001));
    try std.testing.expectEqual(@as(u8, 0x33), m.read8(0x1002));
    try std.testing.expectEqual(@as(u8, 0x44), m.read8(0x1003));
    try std.testing.expectEqual(@as(u16, 0x1122), m.read16(0x1000));
    try std.testing.expectEqual(@as(u32, 0x11223344), m.read32(0x1000));
}

test "permission enforcement records faults" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    // text: r-x at 0x80000, data: rw at 0x90000
    try m.addRegion(0x80000, 0x1000, .{ .read = true, .exec = true });
    try m.addRegion(0x90000, 0x1000, .{ .read = true, .write = true });
    m.enforce = true;

    // write to read-only text => fault
    m.clearFault();
    m.write8(0x80000, 0x42);
    try std.testing.expectEqual(FaultKind.no_write, m.fault.kind);

    // write to data => ok
    m.clearFault();
    m.write8(0x90000, 0x42);
    try std.testing.expectEqual(FaultKind.none, m.fault.kind);
    try std.testing.expectEqual(@as(u8, 0x42), m.read8(0x90000));

    // read unmapped => fault
    m.clearFault();
    _ = m.read8(0x200000);
    try std.testing.expectEqual(FaultKind.unmapped, m.fault.kind);
}

test "out of range access faults" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.enforce = false;
    m.clearFault();
    _ = m.read32(Memory.size - 2); // straddles the end
    try std.testing.expectEqual(FaultKind.unmapped, m.fault.kind);
}

test "readCStr" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.enforce = false;
    m.writeBytes(0x2000, "hello\x00world");
    var buf: [32]u8 = undefined;
    const s = m.readCStr(0x2000, &buf);
    try std.testing.expectEqualStrings("hello", s);
}
