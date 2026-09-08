//! COFF loader for AT&T UNIX PC (3B1) executables.
//!
//! Parses the COFF file header + optional (a.out) header + section headers,
//! all big-endian, validates the 68k magic (0520/0521/0522), maps .text/.data
//! into guest memory at their virtual addresses, zero-fills .bss, and records
//! the entry point. A `.lib` section marks a shared-linked binary (see
//! docs/shlib.md); shared mapping itself is wired in Task 12.

const std = @import("std");
const abi = @import("abi.zig");
const mem = @import("mem.zig");

pub const LoadError = error{
    TooSmall,
    BadMagic,
    NotExecutable,
    NoOptionalHeader,
    BadSection,
};

pub const FileHeader = struct {
    f_magic: u16,
    f_nscns: u16,
    f_timdat: u32,
    f_symptr: u32,
    f_nsyms: u32,
    f_opthdr: u16,
    f_flags: u16,
};

pub const AoutHeader = struct {
    magic: u16,
    vstamp: u16,
    tsize: u32,
    dsize: u32,
    bsize: u32,
    entry: u32,
    text_start: u32,
    data_start: u32,
};

pub const Section = struct {
    name: [8]u8,
    paddr: u32,
    vaddr: u32,
    size: u32,
    scnptr: u32,
    flags: u32,

    pub fn nameSlice(self: *const Section) []const u8 {
        const end = std.mem.indexOfScalar(u8, &self.name, 0) orelse self.name.len;
        return self.name[0..end];
    }
};

pub const Image = struct {
    file: FileHeader,
    aout: AoutHeader,
    sections: []Section,
    /// True if the binary references the shared library (has a `.lib` section).
    is_shared: bool,
    /// Entry point (from aouthdr).
    entry: u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Image) void {
        self.allocator.free(self.sections);
    }

    pub fn findSection(self: *const Image, name: []const u8) ?*const Section {
        for (self.sections) |*s| {
            if (std.mem.eql(u8, s.nameSlice(), name)) return s;
        }
        return null;
    }
};

fn be16(d: []const u8, o: usize) u16 {
    return std.mem.readInt(u16, d[o..][0..2], .big);
}
fn be32(d: []const u8, o: usize) u32 {
    return std.mem.readInt(u32, d[o..][0..4], .big);
}

/// Parse COFF headers from raw bytes (does not touch guest memory).
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) LoadError!Image {
    if (bytes.len < 20) return error.TooSmall;

    const fh = FileHeader{
        .f_magic = be16(bytes, 0),
        .f_nscns = be16(bytes, 2),
        .f_timdat = be32(bytes, 4),
        .f_symptr = be32(bytes, 8),
        .f_nsyms = be32(bytes, 12),
        .f_opthdr = be16(bytes, 16),
        .f_flags = be16(bytes, 18),
    };

    if (!abi.isMc68kMagic(fh.f_magic)) return error.BadMagic;
    if (fh.f_opthdr < 28) return error.NoOptionalHeader;
    if (bytes.len < 20 + @as(usize, fh.f_opthdr)) return error.TooSmall;

    const ao = AoutHeader{
        .magic = be16(bytes, 20),
        .vstamp = be16(bytes, 22),
        .tsize = be32(bytes, 24),
        .dsize = be32(bytes, 28),
        .bsize = be32(bytes, 32),
        .entry = be32(bytes, 36),
        .text_start = be32(bytes, 40),
        .data_start = be32(bytes, 44),
    };

    const scn_off: usize = 20 + @as(usize, fh.f_opthdr);
    if (bytes.len < scn_off + @as(usize, fh.f_nscns) * 40) return error.TooSmall;

    var sections = allocator.alloc(Section, fh.f_nscns) catch return error.BadSection;
    errdefer allocator.free(sections);

    var is_shared = false;
    var off = scn_off;
    var i: usize = 0;
    while (i < fh.f_nscns) : (i += 1) {
        var s: Section = undefined;
        @memcpy(&s.name, bytes[off .. off + 8]);
        s.paddr = be32(bytes, off + 8);
        s.vaddr = be32(bytes, off + 12);
        s.size = be32(bytes, off + 16);
        s.scnptr = be32(bytes, off + 20);
        s.flags = be32(bytes, off + 36);
        sections[i] = s;
        if (std.mem.eql(u8, s.nameSlice(), ".lib")) is_shared = true;
        off += 40;
    }

    return Image{
        .file = fh,
        .aout = ao,
        .sections = sections,
        .is_shared = is_shared,
        .entry = ao.entry,
        .allocator = allocator,
    };
}

/// Map an already-parsed image's sections into guest memory. Copies section
/// raw data at the section vaddrs, zero-fills .bss, and sets up permission
/// regions. Memory enforcement is disabled during this call and left enabled
/// afterward.
pub fn mapInto(image: *const Image, memory: *mem.Memory, bytes: []const u8) LoadError!void {
    const was_enforce = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was_enforce;

    for (image.sections) |*s| {
        const nm = s.nameSlice();
        const is_bss = std.mem.eql(u8, nm, ".bss") or (s.flags & abi.STYP_BSS) != 0;
        const is_text = std.mem.eql(u8, nm, ".text") or (s.flags & abi.STYP_TEXT) != 0;

        if (s.size == 0) continue;
        if (s.vaddr + s.size > mem.Memory.size) return error.BadSection;

        if (is_bss) {
            memory.zero(s.vaddr, s.size);
        } else if (s.scnptr != 0) {
            const end = @as(usize, s.scnptr) + @as(usize, s.size);
            if (end > bytes.len) return error.BadSection;
            memory.writeBytes(s.vaddr, bytes[s.scnptr..end]);
        }

        // Permission region. Text is r-x for read-only/paged text magics
        // (0521/0522). For writable-text (0407 = MC68KWRMAGIC) the text
        // segment is writable, matching the SVR "impure" format used by the
        // toolchain's relocatable/small executables and our test stubs.
        const writable_text = image.aout.magic == abi.MC68KWRMAGIC;
        const perm: mem.Perm = if (is_text)
            (if (writable_text)
                mem.Perm{ .read = true, .write = true, .exec = true }
            else
                mem.Perm{ .read = true, .exec = true })
        else
            .{ .read = true, .write = true };
        memory.addRegion(s.vaddr, s.size, perm) catch return error.BadSection;
    }
}

/// Convenience: parse + map. Returns the parsed Image (caller must deinit).
pub fn load(allocator: std.mem.Allocator, memory: *mem.Memory, bytes: []const u8) LoadError!Image {
    var image = try parse(allocator, bytes);
    errdefer image.deinit();
    try mapInto(&image, memory, bytes);
    return image;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn readTestFile(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(4 * 1024 * 1024)) catch null;
}

test "parse real shared binary /tmp/upc/bin/echo" {
    const bytes = readTestFile(std.testing.allocator, "/tmp/upc/bin/echo") orelse return;
    defer std.testing.allocator.free(bytes);

    var img = try parse(std.testing.allocator, bytes);
    defer img.deinit();

    try std.testing.expectEqual(abi.MC68KPGMAGIC, img.file.f_magic);
    try std.testing.expectEqual(@as(u16, 0o413), img.aout.magic);
    try std.testing.expectEqual(@as(u32, 0x80000), img.entry);
    try std.testing.expect(img.is_shared); // has .lib section

    const text = img.findSection(".text") orelse return error.NoText;
    try std.testing.expectEqual(@as(u32, 0x80000), text.vaddr);
    const data = img.findSection(".data") orelse return error.NoData;
    try std.testing.expectEqual(@as(u32, 0x90000), data.vaddr);
}

test "map echo into memory places bytes at vaddr" {
    const bytes = readTestFile(std.testing.allocator, "/tmp/upc/bin/echo") orelse return;
    defer std.testing.allocator.free(bytes);

    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();

    var img = try load(std.testing.allocator, &memory, bytes);
    defer img.deinit();

    // The first instruction of echo's .text should be present at 0x80000.
    // echo begins with a call sequence; verify the raw file bytes match memory.
    const text = img.findSection(".text").?;
    const first_word = memory.read16(text.vaddr);
    const file_first_word = be16(bytes, text.scnptr);
    try std.testing.expectEqual(file_first_word, first_word);
}

test "reject non-68k magic" {
    var bogus: [64]u8 = @splat(0);
    // put a non-68k magic (ELF-ish 0x7f) and an opthdr
    bogus[0] = 0x00;
    bogus[1] = 0x99;
    try std.testing.expectError(error.BadMagic, parse(std.testing.allocator, &bogus));
}

test "static vs shared classification" {
    // Synthesize a minimal COFF with one .text section and no .lib -> static.
    var buf: [20 + 28 + 40]u8 = @splat(0);
    // filehdr: magic 0520, nscns 1, opthdr 28
    std.mem.writeInt(u16, buf[0..2], abi.MC68KWRMAGIC, .big);
    std.mem.writeInt(u16, buf[2..4], 1, .big);
    std.mem.writeInt(u16, buf[16..18], 28, .big);
    // aouthdr: magic 0407, entry 0x80000
    std.mem.writeInt(u16, buf[20..22], 0o407, .big);
    std.mem.writeInt(u32, buf[36..40], 0x80000, .big);
    // section header at 48: name ".text"
    const so = 20 + 28;
    @memcpy(buf[so .. so + 5], ".text");
    std.mem.writeInt(u32, buf[so + 12 .. so + 16][0..4], 0x80000, .big); // vaddr
    std.mem.writeInt(u32, buf[so + 16 .. so + 20][0..4], 0, .big); // size 0

    var img = try parse(std.testing.allocator, &buf);
    defer img.deinit();
    try std.testing.expect(!img.is_shared);
    try std.testing.expectEqual(@as(u32, 0x80000), img.entry);
}
