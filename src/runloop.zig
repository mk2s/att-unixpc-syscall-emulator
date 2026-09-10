//! Guest execution run loop and syscall trap interception.
//!
//! Interception strategy: the emulator enables Musashi's per-instruction hook
//! (M68K_INSTRUCTION_CALLBACK -> upc_instr_hook, set OPT_SPECIFY_HANDLER in
//! m68kconf.h). The hook fires with REG_PC pointing at the instruction about
//! to execute, *before* the opcode fetch. When we see the `trap #0` opcode
//! (0x4E40), we service the syscall entirely in Zig and advance PC past the
//! trap, so Musashi never takes the real exception. This keeps us fully in
//! user mode with no need to emulate the supervisor stack / vector table.
//!
//! Because Musashi's callbacks carry no user pointer, the run loop registers
//! itself in a module-global that upc_instr_hook consults.

const std = @import("std");
const builtin = @import("builtin");
const cpu = @import("cpu.zig");
const mem = @import("mem.zig");
const abi = @import("abi.zig");

pub const TRAP0_OPCODE: u16 = 0x4E40;

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

/// Per-run cycle budget in 20k-cycle slices. Generous by default so real
/// workloads (cc/cpp/ccom on deep-include kernel sources) complete; it exists
/// only to stop a truly wedged guest. Override with RUNUPC_MAX_SLICES.
fn maxSlicesBudget() u64 {
    if (getenv("RUNUPC_MAX_SLICES")) |s| {
        const span = std.mem.span(s);
        if (std.fmt.parseInt(u64, span, 10)) |v| {
            if (v > 0) return v;
        } else |_| {}
    }
    return 200_000; // 200k * 20k = 4e9 cycles
}

/// Outcome of servicing a syscall.
pub const SyscallOutcome = enum {
    /// Continue executing the guest (advance PC past the trap).
    cont,
    /// Stop the run loop (guest exited).
    exit,
    /// Continue, but PC was already set by the handler (e.g. exec). Do NOT
    /// advance PC past the trap.
    restart,
};

/// The syscall handler signature. Implemented by the dispatcher (Task 8);
/// Task 7 uses a minimal built-in handler for `exit` only.
pub const SyscallFn = *const fn (runner: *Runner, number: u16) SyscallOutcome;

/// Guest address of a "halt pad": two bytes holding `bra .` (0x60FE, branch
/// to self). On exit we point PC here so the CPU spins harmlessly for the rest
/// of the timeslice instead of executing whatever follows the trap. Placed in
/// a normally-unused low page that we map rwx at setup.
pub const HALT_PAD: u32 = 0x400;
pub const BRA_SELF: u16 = 0x60FE;

pub const Runner = struct {
    memory: *mem.Memory,
    /// Set when the guest exits; holds the process exit status.
    exit_status: ?u32 = null,
    /// True once a fatal fault/abort occurred (fail-fast).
    aborted: bool = false,
    /// True if the run loop hit its cycle budget (runaway guest).
    timed_out: bool = false,
    /// Syscall handler (dispatcher). If null, only `exit` is handled.
    handler: ?SyscallFn = null,
    /// Filesystem (guestroot + fd table). Set by the caller when file syscalls
    /// are needed. Type-erased to avoid an import cycle (runloop <- fs).
    fs: ?*anyopaque = null,
    /// Process model (fork/exec/wait/pipe). Type-erased for the same reason.
    procmodel: ?*anyopaque = null,
    /// Number of syscalls serviced (for tests/telemetry).
    syscall_count: u64 = 0,
    /// Current program break (top of the heap/data region). sbrk grows this
    /// toward the stack. Set by the loader to the end of bss.
    brk: u32 = 0,
    /// umask value (for creat/open mode masking; tracked, applied host-side).
    umask: u32 = 0,

    /// Read the Nth 32-bit syscall argument (1-based). Args live on the user
    /// stack just above the return address pushed by the `jsr` to the libc
    /// stub: arg1 at 4(sp), arg2 at 8(sp), ...
    pub fn arg(self: *Runner, n: u32) u32 {
        const sp = cpu.getReg(cpu.Reg.sp);
        return self.memory.read32(sp + 4 * n);
    }

    /// Read a NUL-terminated guest string whose pointer is the Nth arg.
    pub fn argStr(self: *Runner, n: u32, buf: []u8) []const u8 {
        return self.memory.readCStr(self.arg(n), buf);
    }

    /// Set the syscall return value (D0) and clear the carry flag (success).
    pub fn ret(self: *Runner, value: u32) void {
        _ = self;
        cpu.setReg(cpu.Reg.d0, value);
        clearCarry();
    }

    /// Set a second return value in D1 (used by pipe/getpid/etc.).
    pub fn ret2(self: *Runner, d0: u32, d1: u32) void {
        _ = self;
        cpu.setReg(cpu.Reg.d0, d0);
        cpu.setReg(cpu.Reg.d1, d1);
        clearCarry();
    }

    /// Signal a syscall error: errno in D0 and set the carry flag.
    pub fn fail(self: *Runner, errno: u16) void {
        _ = self;
        cpu.setReg(cpu.Reg.d0, errno);
        setCarry();
    }
};

fn clearCarry() void {
    const sr = cpu.getReg(cpu.Reg.sr);
    cpu.setReg(cpu.Reg.sr, sr & ~@as(u32, 0x0001));
}
fn setCarry() void {
    const sr = cpu.getReg(cpu.Reg.sr);
    cpu.setReg(cpu.Reg.sr, sr | 0x0001);
}

// ---------------------------------------------------------------------------
// Global hook wiring (Musashi callback has no user pointer).
// ---------------------------------------------------------------------------
var active_runner: ?*Runner = null;

pub fn setActiveRunner(r: ?*Runner) void {
    active_runner = r;
}

/// Minimal built-in syscall handling used when no dispatcher is installed.
/// Task 7 only needs `exit`.
fn builtinSyscall(runner: *Runner, number: u16) SyscallOutcome {
    const sc: abi.Syscall = @enumFromInt(number);
    switch (sc) {
        .exit => {
            runner.exit_status = runner.arg(1);
            return .exit;
        },
        else => {
            // Unhandled here; without a dispatcher we fail fast.
            runner.aborted = true;
            return .exit;
        },
    }
}

/// The Musashi per-instruction hook. Checks for `trap #0` and services the
/// syscall in Zig. Exported because m68kconf.h binds it by name.
pub const Hook = struct {
    export fn upc_instr_hook(pc: c_uint) callconv(.c) void {
        const runner = active_runner orelse return;
        if (runner.exit_status != null or runner.aborted) return;

        const addr: u32 = @intCast(pc);
        const opcode = runner.memory.read16(addr);
        if (opcode != TRAP0_OPCODE) return;

        // It's a syscall. Number is in D0 (low 16 bits).
        const number: u16 = @truncate(cpu.getReg(cpu.Reg.d0));
        runner.syscall_count += 1;

        const handler = runner.handler orelse builtinSyscall;
        const outcome = handler(runner, number);

        if (outcome == .exit) {
            // Terminate: redirect PC to the halt pad (bra .) so the instruction
            // Musashi executes right after this hook is a harmless self-branch,
            // never the (privileged) instruction following the trap. Then end
            // the timeslice; the run loop sees exit_status and stops.
            cpu.setReg(cpu.Reg.pc, HALT_PAD);
            cpu.endTimeslice();
            return;
        }

        // For exec (.restart), the handler already set PC to the new entry;
        // leave it alone. Otherwise advance PC past the trap #0 (2 bytes).
        if (outcome == .restart) return;
        cpu.setReg(cpu.Reg.pc, addr + 2);
    }
};

comptime {
    _ = Hook;
}

/// Install the halt pad (bra .) into guest memory and map it rx. Call once
/// during process setup, before run().
pub fn installHaltPad(memory: *mem.Memory) !void {
    const was = memory.enforce;
    memory.enforce = false;
    defer memory.enforce = was;
    // Fill a small pad with bra-self so prefetch of the following word is
    // always mapped and also a self-branch.
    var i: u32 = 0;
    while (i < 16) : (i += 2) memory.write16(HALT_PAD + i, BRA_SELF);
    try memory.addRegion(HALT_PAD, 16, .{ .read = true, .exec = true });
}

/// Assemble a minimal exit(status) program in guest memory at VUSER_START and
/// run it, returning the observed exit status. Test helper.
fn runExitStub(memory: *mem.Memory, status_val: u32) u32 {
    const proc = @import("process.zig");
    const entry = abi.VUSER_START;

    // Map the user region rwx and write the stub:
    //   move.l #status,-(sp)   2f3c <status:32>
    //   move.l #0,-(sp)        2f3c 0000 0000
    //   move.w #1,d0           303c 0001
    //   trap #0                4e40
    memory.enforce = false;
    memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true }) catch unreachable;

    var pc = entry;
    memory.write16(pc, 0x2f3c);
    memory.write32(pc + 2, status_val);
    pc += 6;
    memory.write16(pc, 0x2f3c);
    memory.write32(pc + 2, 0);
    pc += 6;
    memory.write16(pc, 0x303c);
    memory.write16(pc + 2, 0x0001);
    pc += 4;
    memory.write16(pc, TRAP0_OPCODE);

    installHaltPad(memory) catch unreachable;

    const argv = [_][]const u8{"stub"};
    const envp = [_][]const u8{};
    const layout = proc.buildStack(memory, abi.USRSTACK, &argv, &envp) catch unreachable;

    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(entry, layout);
    memory.enforce = true;

    var runner = Runner{ .memory = memory };
    return run(&runner);
}

/// Run the guest until it exits or aborts. Returns the exit status.
pub fn run(runner: *Runner) u32 {
    // Guard: the memory callbacks route through mem.active. If the runner's
    // memory is not the active one, every guest fetch would read 0 and the
    // CPU would spin forever. Make that a hard, immediate abort.
    if (mem.active == null or mem.active.? != runner.memory) {
        runner.aborted = true;
        return 0xFFFF_FFFF;
    }

    setActiveRunner(runner);
    defer setActiveRunner(null);

    // Execute in small slices until exit/abort. A cycle budget guards against
    // runaway guests (and buggy stubs) hanging the emulator. Real workloads
    // (e.g. cc/cpp/ccom processing a deep nested-include kernel source) can
    // legitimately run well past a few tens of millions of cycles, so the
    // budget is generous; it exists only to stop a truly wedged guest. Override
    // with RUNUPC_MAX_SLICES for pathological cases.
    var slices: u64 = 0;
    const max_slices: u64 = maxSlicesBudget();
    while (runner.exit_status == null and !runner.aborted) {
        _ = cpu.execute(20_000);
        // If a memory fault occurred, fail fast with a full diagnostic dump.
        if (runner.memory.fault.kind != .none) {
            const diag = @import("diag.zig");
            diag.dump(runner.memory, cpu.getReg(cpu.Reg.pc), .{ .memory_fault = runner.memory.fault });
            runner.aborted = true;
        }
        slices += 1;
        if (slices >= max_slices) {
            runner.aborted = true;
            runner.timed_out = true;
        }
    }
    return runner.exit_status orelse 0xFFFF_FFFF;
}

// ---------------------------------------------------------------------------
// Tests (require the Musashi C core; wired as a C-linked test in build.zig).
// ---------------------------------------------------------------------------

test "exit(0) stub exits 0" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    mem.setActive(&memory);
    try std.testing.expectEqual(@as(u32, 0), runExitStub(&memory, 0));
}

test "exit(42) stub exits 42" {
    var memory = try mem.Memory.init(std.testing.allocator);
    defer memory.deinit();
    defer mem.setActive(null);
    mem.setActive(&memory);
    try std.testing.expectEqual(@as(u32, 42), runExitStub(&memory, 42));
}
