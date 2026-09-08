//! Dedicated root for the cpu core-init test. Kept separate from cpu.zig so
//! this test is NOT pulled into other C-linked test binaries (runloop,
//! syscalls) where it could observe leftover memory-callback state.

const std = @import("std");
const cpu = @import("cpu.zig");
const mem = @import("mem.zig");
const runloop = @import("runloop.zig");

// Provide the canonical Musashi C symbols for this test binary.
comptime {
    _ = mem.Callbacks;
    _ = runloop.Hook;
}

test "core initializes to 68010" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    mem.setActive(&memory);

    cpu.init();
    cpu.pulseReset();
    try std.testing.expectEqual(cpu.CPU_TYPE_68010, cpu.getReg(cpu.Reg.cpu_type));
}
