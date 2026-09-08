//! Musashi 68010 core bindings and run loop.
//!
//! The Musashi C core is compiled via build.zig (zig cc). This module exposes
//! a thin Zig wrapper: CPU type, reset, register access, and the run loop.
//! Memory access callbacks (m68k_read/write_memory_*) and the instruction hook
//! (upc_instr_hook) are implemented in mem.zig / the run loop and exported as
//! C symbols the core links against.

const std = @import("std");

pub const c = @import("musashi");

/// CPU type constants (from m68k.h enum). 68010 for the UNIX PC.
pub const CPU_TYPE_68010: c_uint = c.M68K_CPU_TYPE_68010;

pub const Reg = struct {
    pub const d0 = c.M68K_REG_D0;
    pub const d1 = c.M68K_REG_D1;
    pub const d2 = c.M68K_REG_D2;
    pub const d3 = c.M68K_REG_D3;
    pub const d4 = c.M68K_REG_D4;
    pub const d5 = c.M68K_REG_D5;
    pub const d6 = c.M68K_REG_D6;
    pub const d7 = c.M68K_REG_D7;
    pub const a0 = c.M68K_REG_A0;
    pub const a1 = c.M68K_REG_A1;
    pub const a2 = c.M68K_REG_A2;
    pub const a3 = c.M68K_REG_A3;
    pub const a4 = c.M68K_REG_A4;
    pub const a5 = c.M68K_REG_A5;
    pub const a6 = c.M68K_REG_A6;
    pub const a7 = c.M68K_REG_A7;
    pub const pc = c.M68K_REG_PC;
    pub const sr = c.M68K_REG_SR;
    pub const sp = c.M68K_REG_SP;
    pub const usp = c.M68K_REG_USP;
    pub const isp = c.M68K_REG_ISP;
    pub const ppc = c.M68K_REG_PPC;
    pub const ir = c.M68K_REG_IR;
    pub const cpu_type = c.M68K_REG_CPU_TYPE;
};

/// Initialize the core and set it to 68010. Must be called once at startup.
pub fn init() void {
    c.m68k_init();
    c.m68k_set_cpu_type(CPU_TYPE_68010);
}

/// Pulse reset — required at least once before executing.
pub fn pulseReset() void {
    c.m68k_pulse_reset();
}

pub fn getReg(reg: c_uint) u32 {
    return c.m68k_get_reg(null, reg);
}

pub fn setReg(reg: c_uint, value: u32) void {
    c.m68k_set_reg(reg, value);
}

/// Execute up to num_cycles; returns cycles actually consumed.
pub fn execute(num_cycles: i32) i32 {
    return c.m68k_execute(num_cycles);
}

pub fn endTimeslice() void {
    c.m68k_end_timeslice();
}

/// Halt the CPU (as if the HALT pin were pulsed). Stops further execution
/// until the next reset. Used to terminate the guest cleanly on exit.
pub fn pulseHalt() void {
    c.m68k_pulse_halt();
}

pub fn setInstrHook(cb: ?*const fn (pc: c_uint) callconv(.c) void) void {
    c.m68k_set_instr_hook_callback(@ptrCast(@constCast(cb)));
}

/// Disassemble one instruction at pc into buf; returns instruction size.
pub fn disassemble(buf: []u8, pc: u32) u32 {
    return c.m68k_disassemble(buf.ptr, pc, CPU_TYPE_68010);
}

const builtin = @import("builtin");

// NOTE: cpu.zig intentionally has NO tests of its own. The core-init test
// lives in src/cpu_test.zig (a dedicated root for the cpu test target) so it
// does not get pulled into other C-linked test binaries (runloop/syscalls),
// where leftover memory-callback state could make it crash. Those binaries
// supply the canonical Musashi C symbols (mem.Callbacks, runloop.Hook)
// themselves via their own imports.
