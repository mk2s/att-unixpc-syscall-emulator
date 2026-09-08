//! Process startup: initial stack (argc/argv/envp), and initial CPU registers.
//!
//! The crt0 contract (verified by disassembling /tmp/upc/lib/crt0.o) is:
//!   A0 = SP
//!   argc  = *A0++            ; long at SP+0
//!   argv  = A0               ; pointer array begins at SP+4
//!   (scan argv pointers until a NULL long)
//!   envp  = A0               ; first envp pointer, just past argv's NULL
//!   main(argc, argv, envp)
//!
//! So the initial stack (at USRSTACK, growing down) is laid out low-to-high:
//!   [argc][argv[0]..argv[argc-1]][NULL][envp[0]..][NULL][string bytes...]
//!
//! We place the argument/environment strings at the very top of the user
//! stack region, then the pointer arrays and argc just below them, and set
//! SP to point at argc.

const std = @import("std");
const abi = @import("abi.zig");
const mem = @import("mem.zig");
const cpu = @import("cpu.zig");

pub const StartError = error{ ArgsTooLong, OutOfStack };

/// Result of building the initial stack.
pub const StackLayout = struct {
    sp: u32, // initial stack pointer (points at argc)
    argc: u32,
    argv_ptr: u32, // guest address of argv[0] slot (== sp + 4)
    envp_ptr: u32, // guest address of envp[0] slot
};

/// Status-register value for user mode: supervisor bit clear, interrupts
/// enabled (mask 0). The UNIX PC runs user code in user mode.
pub const USER_SR: u32 = 0x0000;

/// 68k SR supervisor bit. When set, CPU is in supervisor mode. We want it
/// CLEAR for user code, but Musashi resets into supervisor mode; we set SR
/// explicitly and use the USP for the user stack.
const SR_SUPERVISOR: u32 = 0x2000;

/// Build the initial user stack in `memory` for the given argv/envp, and
/// return the layout. Does not touch CPU registers (see applyToCpu).
///
/// `stack_top` is the highest address of the stack (exclusive); the UNIX PC
/// uses USRSTACK = 0x300000. Strings and arrays are packed downward from there.
pub fn buildStack(
    memory: *mem.Memory,
    stack_top: u32,
    argv: []const []const u8,
    envp: []const []const u8,
) StartError!StackLayout {
    // Enforcement off while we scribble the stack image.
    const was_enforce = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was_enforce;

    // 1. Compute total string bytes (each NUL-terminated). Enforce NCARGS.
    var strbytes: usize = 0;
    for (argv) |a| strbytes += a.len + 1;
    for (envp) |e| strbytes += e.len + 1;
    if (strbytes > abi.NCARGS) return error.ArgsTooLong;

    // 2. Place strings at the top, 2-byte aligned base. Copy them in,
    //    remembering each string's guest address.
    var string_area: u32 = stack_top - @as(u32, @intCast(strbytes));
    string_area &= ~@as(u32, 1); // even alignment for safety

    const MAX_VEC = 1024;
    if (argv.len > MAX_VEC or envp.len > MAX_VEC) return error.ArgsTooLong;
    var argv_addrs: [MAX_VEC]u32 = undefined;
    var envp_addrs: [MAX_VEC]u32 = undefined;

    var cursor = string_area;
    for (argv, 0..) |a, i| {
        memory.writeBytes(cursor, a);
        memory.write8(cursor + @as(u32, @intCast(a.len)), 0);
        argv_addrs[i] = cursor;
        cursor += @intCast(a.len + 1);
    }
    for (envp, 0..) |e, i| {
        memory.writeBytes(cursor, e);
        memory.write8(cursor + @as(u32, @intCast(e.len)), 0);
        envp_addrs[i] = cursor;
        cursor += @intCast(e.len + 1);
    }

    // 3. Below the string area, lay out (high to low):
    //      argc (1 long)
    //      argv[] pointers + NULL
    //      envp[] pointers + NULL
    //    all as 4-byte longs. Total longs:
    const n_argv = argv.len;
    const n_envp = envp.len;
    const total_longs: u32 = 1 // argc
    + @as(u32, @intCast(n_argv)) + 1 // argv ptrs + NULL
    + @as(u32, @intCast(n_envp)) + 1; // envp ptrs + NULL
    const table_bytes = total_longs * 4;

    var sp = string_area - table_bytes;
    sp &= ~@as(u32, 3); // longword align the SP

    if (sp < abi.VUSER_START) return error.OutOfStack;

    // 4. Write argc, argv[], NULL, envp[], NULL from sp upward.
    var w = sp;
    memory.write32(w, @intCast(n_argv));
    w += 4;
    const argv_ptr = w;
    for (argv_addrs[0..n_argv]) |addr| {
        memory.write32(w, addr);
        w += 4;
    }
    memory.write32(w, 0); // argv NULL terminator
    w += 4;
    const envp_ptr = w;
    for (envp_addrs[0..n_envp]) |addr| {
        memory.write32(w, addr);
        w += 4;
    }
    memory.write32(w, 0); // envp NULL terminator
    w += 4;

    return StackLayout{
        .sp = sp,
        .argc = @intCast(n_argv),
        .argv_ptr = argv_ptr,
        .envp_ptr = envp_ptr,
    };
}

/// Set the CPU up to begin executing at `entry` with the given stack. Puts the
/// CPU in user mode with SP = layout.sp.
pub fn applyToCpu(entry: u32, layout: StackLayout) void {
    // Musashi resets in supervisor mode. Set SR to user mode first so that
    // A7 maps to the user stack pointer, then set the stack and PC.
    cpu.setReg(cpu.Reg.sr, USER_SR);
    cpu.setReg(cpu.Reg.usp, layout.sp);
    cpu.setReg(cpu.Reg.sp, layout.sp);
    cpu.setReg(cpu.Reg.pc, entry);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "stack layout matches crt0 contract" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();

    const argv = [_][]const u8{ "echo", "hello", "world" };
    const envp = [_][]const u8{ "PATH=/bin", "HOME=/" };

    const layout = try buildStack(&memory, abi.USRSTACK, &argv, &envp);

    // argc at sp
    try std.testing.expectEqual(@as(u32, 3), memory.read32(layout.sp));
    // argv pointer array begins at sp+4
    try std.testing.expectEqual(layout.sp + 4, layout.argv_ptr);

    // Verify argv[0..2] point to the right strings.
    var buf: [64]u8 = undefined;
    const a0 = memory.read32(layout.argv_ptr + 0);
    const a1 = memory.read32(layout.argv_ptr + 4);
    const a2 = memory.read32(layout.argv_ptr + 8);
    try std.testing.expectEqualStrings("echo", memory.readCStr(a0, &buf));
    try std.testing.expectEqualStrings("hello", memory.readCStr(a1, &buf));
    try std.testing.expectEqualStrings("world", memory.readCStr(a2, &buf));

    // argv NULL terminator at argv_ptr + 12
    try std.testing.expectEqual(@as(u32, 0), memory.read32(layout.argv_ptr + 12));

    // envp starts right after; envp_ptr just past the argv NULL.
    try std.testing.expectEqual(layout.argv_ptr + 16, layout.envp_ptr);
    const e0 = memory.read32(layout.envp_ptr + 0);
    const e1 = memory.read32(layout.envp_ptr + 4);
    try std.testing.expectEqualStrings("PATH=/bin", memory.readCStr(e0, &buf));
    try std.testing.expectEqualStrings("HOME=/", memory.readCStr(e1, &buf));
    // envp NULL terminator
    try std.testing.expectEqual(@as(u32, 0), memory.read32(layout.envp_ptr + 8));
}

test "simulate crt0 pointer walk finds envp" {
    // Reproduce crt0's algorithm on our stack image and confirm it lands on
    // the same envp pointer we computed.
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();

    const argv = [_][]const u8{ "prog", "a", "bb" };
    const envp = [_][]const u8{"X=1"};
    const layout = try buildStack(&memory, abi.USRSTACK, &argv, &envp);

    // A0 = SP; argc = *A0++ ; argv = A0 ; scan until NULL ; envp = A0
    var a0 = layout.sp;
    const argc = memory.read32(a0);
    a0 += 4;
    try std.testing.expectEqual(@as(u32, 3), argc);
    const argv_start = a0;
    try std.testing.expectEqual(layout.argv_ptr, argv_start);
    while (memory.read32(a0) != 0) a0 += 4;
    a0 += 4; // step past NULL
    try std.testing.expectEqual(layout.envp_ptr, a0);
}

test "NCARGS enforced" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var big: [abi.NCARGS + 10]u8 = @splat('x');
    big[big.len - 1] = 0;
    const argv = [_][]const u8{big[0 .. big.len - 1]};
    const envp = [_][]const u8{};
    try std.testing.expectError(error.ArgsTooLong, buildStack(&memory, abi.USRSTACK, &argv, &envp));
}
