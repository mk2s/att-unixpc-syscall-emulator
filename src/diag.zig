//! Fail-fast diagnostics: on an unimplemented syscall or an abnormal
//! condition, dump the full CPU state, the offending syscall, a stack window,
//! and the disassembly of the faulting instruction. Output goes to stderr.

const std = @import("std");
const cpu = @import("cpu.zig");
const mem = @import("mem.zig");
const abi = @import("abi.zig");

extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

fn eprint(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = write(2, s.ptr, s.len);
}

pub const Reason = union(enum) {
    unimplemented_syscall: u16,
    bad_syscall: u16,
    memory_fault: mem.Fault,
    message: []const u8,
};

/// Print a full diagnostic dump. `pc` is the guest PC at the point of failure
/// (typically the address of the trap instruction).
pub fn dump(memory: *mem.Memory, pc: u32, reason: Reason) void {
    eprint("\n==== runupc fail-fast diagnostic ====\n", .{});

    switch (reason) {
        .unimplemented_syscall => |n| {
            const sc: abi.Syscall = @enumFromInt(n);
            eprint("reason: unimplemented syscall {d} ({s})\n", .{ n, sc.name() });
        },
        .bad_syscall => |n| eprint("reason: unknown syscall number {d}\n", .{n}),
        .memory_fault => |f| eprint("reason: memory fault {s} @ 0x{X:0>6}\n", .{ @tagName(f.kind), f.address }),
        .message => |m| eprint("reason: {s}\n", .{m}),
    }

    // Registers.
    eprint("registers:\n", .{});
    eprint("  D0={X:0>8} D1={X:0>8} D2={X:0>8} D3={X:0>8}\n", .{
        cpu.getReg(cpu.Reg.d0), cpu.getReg(cpu.Reg.d1),
        cpu.getReg(cpu.Reg.d2), cpu.getReg(cpu.Reg.d3),
    });
    eprint("  D4={X:0>8} D5={X:0>8} D6={X:0>8} D7={X:0>8}\n", .{
        cpu.getReg(cpu.Reg.d4), cpu.getReg(cpu.Reg.d5),
        cpu.getReg(cpu.Reg.d6), cpu.getReg(cpu.Reg.d7),
    });
    eprint("  A0={X:0>8} A1={X:0>8} A2={X:0>8} A3={X:0>8}\n", .{
        cpu.getReg(cpu.Reg.a0), cpu.getReg(cpu.Reg.a1),
        cpu.getReg(cpu.Reg.a2), cpu.getReg(cpu.Reg.a3),
    });
    eprint("  A4={X:0>8} A5={X:0>8} A6={X:0>8} A7={X:0>8}\n", .{
        cpu.getReg(cpu.Reg.a4), cpu.getReg(cpu.Reg.a5),
        cpu.getReg(cpu.Reg.a6), cpu.getReg(cpu.Reg.a7),
    });
    eprint("  PC={X:0>6}  SR={X:0>4}  SP={X:0>6}\n", .{
        cpu.getReg(cpu.Reg.pc), cpu.getReg(cpu.Reg.sr), cpu.getReg(cpu.Reg.sp),
    });

    // Faulting instruction disassembly.
    var dbuf: [128]u8 = undefined;
    const size = cpu.disassemble(&dbuf, pc);
    const dlen = std.mem.indexOfScalar(u8, &dbuf, 0) orelse dbuf.len;
    eprint("insn @ 0x{X:0>6} ({d} bytes): {s}\n", .{ pc, size, dbuf[0..dlen] });

    // Stack window (top 8 longs).
    const sp = cpu.getReg(cpu.Reg.sp);
    eprint("stack @ SP=0x{X:0>6}:\n", .{sp});
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const a = sp + i * 4;
        eprint("  [SP+{d: >2}] 0x{X:0>6} = 0x{X:0>8}\n", .{ i * 4, a, memory.read32(a) });
    }
    eprint("=====================================\n", .{});
}
