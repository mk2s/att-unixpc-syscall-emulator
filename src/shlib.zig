//! 3B1 shared-library ("early shared binary") support.
//!
//! The shared library `/tmp/upc/lib/shlib` maps at FIXED virtual addresses and
//! exposes a jump table at `_tbase`. Shared-linked programs make absolute
//! `jsr <_tbase+off>` calls into it, so no relocation is needed — the loader
//! just maps the image at its fixed vaddrs. See docs/shlib.md.
//!
//! This module provides parsing of the shlib COFF image and the verified
//! facts. The actual `mapInto(mem)` wiring lands in Task 12 once the memory
//! model and COFF loader exist; it is stubbed here against those interfaces.

const std = @import("std");
const abi = @import("abi.zig");

/// Verified fixed layout of the shared library (from docs/shlib.md).
pub const Layout = struct {
    /// Jump table base (== aouthdr text_start).
    pub const tbase: u32 = 0x310000;
    /// Data globals base (== aouthdr data_start region; _dbase = 0x301000).
    pub const dbase: u32 = 0x301000;
    /// Region the shared library occupies (within SHLIB_START..SHLIB_END).
    pub const region_start: u32 = abi.SHLIB_START; // 0x300000
    pub const region_end: u32 = abi.SHLIB_END; // 0x380000
    /// Jump-table slot stride: 6 bytes = `jmp <abs32>` (0x4ef9 + 4).
    pub const slot_stride: u32 = 6;
    /// A few well-known entry points (offset from tbase), from shlib.ifile.
    pub const off_shlbat: u32 = 0x0;
    pub const off_access: u32 = 0xc;
    pub const off_exit: u32 = 0x78;
    pub const off_printf: u32 = 0x39c;
    pub const off_putchar: u32 = 0x3c6;
    /// environ global (in data region): _dbase + 0x4.
    pub const addr_environ: u32 = dbase + 0x4;
    /// errno global: _dbase + 0x0.
    pub const addr_errno: u32 = dbase + 0x0;
};

/// The `.lib` section name marks a shared-linked binary.
pub const LIB_SECTION_NAME = ".lib";

fn be16(d: []const u8, o: usize) u16 {
    return std.mem.readInt(u16, d[o..][0..2], .big);
}
fn be32(d: []const u8, o: usize) u32 {
    return std.mem.readInt(u32, d[o..][0..4], .big);
}

pub const Section = struct {
    name: [8]u8,
    vaddr: u32,
    size: u32,
    scnptr: u32,

    pub fn nameSlice(self: *const Section) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..end];
    }
};

pub const ShlibImage = struct {
    magic: u16,
    text_start: u32,
    data_start: u32,
    sections: []Section,
    raw: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ShlibImage) void {
        self.allocator.free(self.sections);
        self.allocator.free(self.raw);
    }

    pub fn findSection(self: *const ShlibImage, name: []const u8) ?*const Section {
        for (self.sections) |*s| {
            if (std.mem.eql(u8, s.nameSlice(), name)) return s;
        }
        return null;
    }
};

/// Parse a shlib (or any 68k COFF) image from bytes.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !ShlibImage {
    if (bytes.len < 20) return error.TooSmall;
    const magic = be16(bytes, 0);
    if (!abi.isMc68kMagic(magic)) return error.BadMagic;
    const nscns = be16(bytes, 2);
    const opthdr = be16(bytes, 16);

    var text_start: u32 = 0;
    var data_start: u32 = 0;
    if (opthdr >= 28) {
        text_start = be32(bytes, 20 + 20);
        data_start = be32(bytes, 20 + 24);
    }

    const raw = try allocator.dupe(u8, bytes);
    errdefer allocator.free(raw);

    var sections = try allocator.alloc(Section, nscns);
    errdefer allocator.free(sections);

    var off: usize = 20 + opthdr;
    var i: usize = 0;
    while (i < nscns) : (i += 1) {
        var s: Section = undefined;
        @memcpy(&s.name, bytes[off .. off + 8]);
        s.vaddr = be32(bytes, off + 12);
        s.size = be32(bytes, off + 16);
        s.scnptr = be32(bytes, off + 20);
        sections[i] = s;
        off += 40;
    }

    return ShlibImage{
        .magic = magic,
        .text_start = text_start,
        .data_start = data_start,
        .sections = sections,
        .raw = raw,
        .allocator = allocator,
    };
}

/// Map a parsed shlib image into guest memory at its fixed vaddrs. Copies
/// .text/.data raw bytes and zero-fills .bss, and registers permission regions
/// (text r-x, data/bss rw). Because the shared library is always mapped at the
/// same address, the absolute jump-table calls and data references in
/// shared-linked programs resolve with no relocation (see docs/shlib.md).
pub fn mapInto(img: *const ShlibImage, memory: anytype) !void {
    const memmod = @import("mem.zig");
    const was = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was;

    for (img.sections) |*s| {
        const nm = s.nameSlice();
        if (s.size == 0) continue;
        if (s.vaddr < abi.SHLIB_START or s.vaddr + s.size > abi.SHLIB_END) {
            return error.OutOfShlibRegion;
        }
        const is_bss = std.mem.eql(u8, nm, ".bss");
        const is_text = std.mem.eql(u8, nm, ".text");
        if (is_bss or s.scnptr == 0) {
            memory.zero(s.vaddr, s.size);
        } else {
            const end = @as(usize, s.scnptr) + @as(usize, s.size);
            if (end > img.raw.len) return error.BadSection;
            memory.writeBytes(s.vaddr, img.raw[s.scnptr..end]);
        }
        const perm: memmod.Perm = if (is_text)
            .{ .read = true, .exec = true }
        else
            .{ .read = true, .write = true };
        memory.addRegion(s.vaddr, s.size, perm) catch return error.BadSection;
    }
}

/// Read the shlib file from the guest root and map it. `readFile` is a caller-
/// provided function (path -> owned bytes) so this module stays free of a
/// specific I/O backend. The shlib lives at "/lib/shlib" in the guest tree.
pub fn loadFromRoot(
    allocator: std.mem.Allocator,
    memory: anytype,
    shlib_bytes: []const u8,
) !void {
    var img = try parse(allocator, shlib_bytes);
    defer img.deinit();
    try mapInto(&img, memory);
}

// ---------------------------------------------------------------------------
// Tests: verified-facts fixture (docs/shlib.md) + parse against the real image
// when available.
// ---------------------------------------------------------------------------

test "verified shlib layout constants" {
    try std.testing.expectEqual(@as(u32, 0x310000), Layout.tbase);
    try std.testing.expectEqual(@as(u32, 0x301000), Layout.dbase);
    try std.testing.expectEqual(@as(u32, 6), Layout.slot_stride);
    try std.testing.expectEqual(@as(u32, 0x301004), Layout.addr_environ);
    // jump-table entry addresses (tbase + offset), from shlib.ifile
    try std.testing.expectEqual(@as(u32, 0x31000c), Layout.tbase + Layout.off_access);
    try std.testing.expectEqual(@as(u32, 0x310078), Layout.tbase + Layout.off_exit);
    try std.testing.expectEqual(@as(u32, 0x3103c6), Layout.tbase + Layout.off_putchar);
    // region within reserved shared window
    try std.testing.expect(Layout.tbase >= abi.SHLIB_START and Layout.tbase < abi.SHLIB_END);
}

test "mapInto places jump table at tbase" {
    const memmod = @import("mem.zig");
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        "/tmp/upc/lib/shlib",
        std.testing.allocator,
        .limited(2 * 1024 * 1024),
    ) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    defer std.testing.allocator.free(bytes);

    var memory = try memmod.Memory.init(std.testing.allocator);
    defer memory.deinit();

    var img = try parse(std.testing.allocator, bytes);
    defer img.deinit();
    try mapInto(&img, &memory);

    // The first jump-table slot at tbase must be a `jmp <abs32>` (0x4ef9).
    try std.testing.expectEqual(@as(u16, 0x4ef9), memory.read16(Layout.tbase));
    // The data region base should be mapped (environ area readable).
    _ = memory.read32(Layout.addr_environ); // no fault expected
    try std.testing.expectEqual(memmod.FaultKind.none, memory.fault.kind);
}

test "parse real shlib image if present" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        "/tmp/upc/lib/shlib",
        std.testing.allocator,
        .limited(4 * 1024 * 1024),
    ) catch |e| switch (e) {
        error.FileNotFound => return, // reference tree not present; skip
        else => return e,
    };
    defer std.testing.allocator.free(bytes);

    var img = try parse(std.testing.allocator, bytes);
    defer img.deinit();

    try std.testing.expectEqual(abi.MC68KPGMAGIC, img.magic);
    try std.testing.expectEqual(Layout.tbase, img.text_start); // 0x310000
    const text = img.findSection(".text") orelse return error.NoText;
    try std.testing.expectEqual(Layout.tbase, text.vaddr);
    const data = img.findSection(".data") orelse return error.NoData;
    try std.testing.expectEqual(@as(u32, 0x300000), data.vaddr);

    // Verify the first jump-table slot is `jmp <abs32>` (0x4ef9).
    const jt = img.raw[text.scnptr .. text.scnptr + 2];
    try std.testing.expectEqual(@as(u16, 0x4ef9), std.mem.readInt(u16, jt[0..2], .big));
}
