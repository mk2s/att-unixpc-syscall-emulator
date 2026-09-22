//! AT&T UNIX PC (3B1) user-mode syscall emulator — entry point.
//!
//! Task 5 milestone: `--load <coff>` parses a COFF executable, maps it into
//! guest memory, and prints a section map + entry point + shared/static
//! classification. With no args, runs the init/memory self-check.
//!
//! Uses the Zig "full" main signature: `main(init: std.process.Init)` gives us
//! the gpa, io, arena, and command-line args directly (the reorganized std
//! removed the old std.process.argsAlloc free functions).

const std = @import("std");
const cpu = @import("cpu.zig");
const mem = @import("mem.zig");
const coff = @import("coff.zig");
const proc = @import("process.zig");
const abi = @import("abi.zig");
const runloop = @import("runloop.zig");
const syscalls = @import("syscalls.zig");
const trace = @import("trace.zig");
const fsmod = @import("fs.zig");
const procmodel = @import("procmodel.zig");
const shlib = @import("shlib.zig");

// Pull in the run loop's trap-0 instruction hook (exported upc_instr_hook).
comptime {
    _ = runloop.Hook;
}

// Pull in the real Musashi memory callbacks (exported C symbols).
comptime {
    _ = mem.Callbacks;
}

/// libc write(2) — stable across the churning std I/O API. libc is linked.
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

pub fn hostWrite(fd: c_int, bytes: []const u8) void {
    _ = write(fd, bytes.ptr, bytes.len);
}

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    hostWrite(1, s);
}

/// When true, suppress runupc's own status chatter (e.g. the per-process
/// "guest exited with status N" line). Set by the global `--quiet` flag. This
/// matters when the guest forks many children (cc/make), where the status line
/// would otherwise interleave noisily with the build's real output.
var quiet: bool = false;

/// Like out(), but only when not in --quiet mode. For runupc's own diagnostics
/// that are useful interactively but noise during a build.
fn outv(comptime fmt: []const u8, args: anytype) void {
    if (quiet) return;
    out(fmt, args);
}

fn cmdLoad(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(8 * 1024 * 1024));
    defer gpa.free(bytes);

    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    mem.setActive(&memory);

    var image = coff.load(gpa, &memory, bytes) catch |e| {
        out("load error: {s}\n", .{@errorName(e)});
        return;
    };
    defer image.deinit();

    out("COFF image: {s}\n", .{path});
    out("  file magic : 0o{o}\n", .{image.file.f_magic});
    out("  aout magic : 0o{o}\n", .{image.aout.magic});
    out("  entry      : 0x{X:0>6}\n", .{image.entry});
    out("  linkage    : {s}\n", .{if (image.is_shared) "shared (.lib present)" else "static"});
    out("  sections   :\n", .{});
    for (image.sections) |*s| {
        out("    {s: <8} vaddr=0x{X:0>6} size=0x{X:0>6} flags=0x{X}\n", .{
            s.nameSlice(), s.vaddr, s.size, s.flags,
        });
    }
}

fn cmdDumpStack(gpa: std.mem.Allocator, io: std.Io, path: []const u8, prog_args: []const []const u8) !void {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(8 * 1024 * 1024));
    defer gpa.free(bytes);

    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    mem.setActive(&memory);

    var image = coff.load(gpa, &memory, bytes) catch |e| {
        out("load error: {s}\n", .{@errorName(e)});
        return;
    };
    defer image.deinit();

    const envp = [_][]const u8{ "PATH=/bin:/usr/bin", "HOME=/", "TERM=s4" };
    const layout = proc.buildStack(&memory, abi.USRSTACK, prog_args, &envp) catch |e| {
        out("stack build error: {s}\n", .{@errorName(e)});
        return;
    };

    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(image.entry, layout);

    out("loaded {s} (entry 0x{X:0>6}, {s})\n", .{
        path, image.entry, if (image.is_shared) "shared" else "static",
    });
    out("initial registers:\n", .{});
    out("  PC = 0x{X:0>6}   SR = 0x{X:0>4}\n", .{ cpu.getReg(cpu.Reg.pc), cpu.getReg(cpu.Reg.sr) });
    out("  A7/SP = 0x{X:0>6} (USP=0x{X:0>6})\n", .{ cpu.getReg(cpu.Reg.sp), cpu.getReg(cpu.Reg.usp) });
    out("initial stack (crt0 view):\n", .{});
    out("  [SP+0] argc = {d}\n", .{memory.read32(layout.sp)});
    out("  argv @ 0x{X:0>6}:\n", .{layout.argv_ptr});
    var i: u32 = 0;
    while (true) : (i += 1) {
        const p = memory.read32(layout.argv_ptr + i * 4);
        if (p == 0) break;
        var b: [128]u8 = undefined;
        out("    argv[{d}] -> 0x{X:0>6} \"{s}\"\n", .{ i, p, memory.readCStr(p, &b) });
    }
    out("  envp @ 0x{X:0>6}:\n", .{layout.envp_ptr});
    i = 0;
    while (true) : (i += 1) {
        const p = memory.read32(layout.envp_ptr + i * 4);
        if (p == 0) break;
        var b: [128]u8 = undefined;
        out("    envp[{d}] -> 0x{X:0>6} \"{s}\"\n", .{ i, p, memory.readCStr(p, &b) });
    }
}

/// Load a COFF, set up its stack, and run it until exit. Returns the guest
/// exit status (or an error indication). Used by `run`.
pub fn runProgram(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    prog_args: []const []const u8,
    guestroot: ?[]const u8,
    extra_env: []const []const u8,
) !u32 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(8 * 1024 * 1024));
    defer gpa.free(bytes);

    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    mem.setActive(&memory);

    var fs = try fsmod.Fs.init(gpa, guestroot orelse ".");
    defer fs.deinit();

    var image = try coff.load(gpa, &memory, bytes);
    defer image.deinit();

    // Shared-linked binaries need the shared library mapped at its fixed
    // address (0x310000). Load <guestroot>/lib/shlib and map it.
    if (image.is_shared) {
        mapShlib(gpa, io, &memory, guestroot orelse ".") catch |e| {
            out("warning: could not map shared library: {s}\n", .{@errorName(e)});
        };
    }

    // Low memory (0 .. VUSER_START): map read-only. On the 3B1, page 0 is
    // present and a null-pointer *read* yields 0 rather than trapping; a lot of
    // period C (and the bundled toolchain, e.g. ccom's symbol handling) relies
    // on `*(T*)0` reading as 0. Keep it non-writable so a genuine null *store*
    // still fails fast. Without this, ccom null-reads fault as "unmapped @ 0x0"
    // and abort compiles of larger functions.
    try memory.addRegion(0, abi.VUSER_START, .{ .read = true, .write = false, .exec = false });

    // Stack region: give the top of the user region rw permission so the
    // stack works, then build the initial stack.
    try memory.addRegion(abi.VUSER_START, abi.VUSER_END - abi.VUSER_START, .{ .read = true, .write = true, .exec = true });
    // CCROOT is the prefix cc prepends to phase paths (CCROOT/lib/cpp,
    // CCROOT/lib/ccom, ...). Empty => absolute /lib/cpp etc., which is where
    // the phases live in the guest tree. Without it, cc's getenv("CCROOT")
    // returns null and its path-concat routine faults on the null prefix.
    // cc treats an empty CCROOT the same as unset (it skips the store when the
    // first byte is NUL), so use "/" — concat yields //lib/cpp which the path
    // resolver collapses to /lib/cpp where the phases live.
    // Guest environment: caller-supplied --env vars first, then base defaults
    // the toolchain needs. A base default is emitted ONLY if no --env entry
    // already defines that NAME= — so `--env PATH=...` cleanly OVERRIDES the
    // default rather than leaving two PATH entries (some guest tools honor the
    // first, others the last; a single entry is unambiguous).
    var env_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer env_list.deinit(gpa);
    for (extra_env) |e| try env_list.append(gpa, e);
    const base_env = [_][]const u8{ "PATH=/bin:/usr/bin", "HOME=/", "CCROOT=/" };
    for (base_env) |b| {
        // NAME= prefix of this base var (including the '=').
        const eq = (std.mem.indexOfScalar(u8, b, '=') orelse continue) + 1;
        var overridden = false;
        for (extra_env) |e| {
            if (e.len >= eq and std.mem.eql(u8, e[0..eq], b[0..eq])) {
                overridden = true;
                break;
            }
        }
        if (!overridden) try env_list.append(gpa, b);
    }
    const layout = try proc.buildStack(&memory, abi.USRSTACK, prog_args, env_list.items);

    try runloop.installHaltPad(&memory);

    cpu.init();
    cpu.pulseReset();
    proc.applyToCpu(image.entry, layout);
    memory.enforce = true;

    // Initial program break = end of the highest loaded data/bss section.
    // NOT page-rounded: the guest's crt0 passes this exact value to shlbat and
    // libc malloc grows from it via brk(2); rounding up would make small brk
    // requests look like shrinks and leave the heap unmapped.
    var brk: u32 = abi.VUSER_START;
    for (image.sections) |*s| {
        const end = s.vaddr + s.size;
        if (end > brk and s.vaddr < abi.USRSTACK) brk = end;
    }

    var hostproc = procmodel.HostProcess{
        .memory = &memory,
        .fs = &fs,
        .guestroot = guestroot orelse ".",
        .allocator = gpa,
    };

    var runner = runloop.Runner{
        .memory = &memory,
        .handler = syscalls.dispatch,
        .fs = &fs,
        .procmodel = &hostproc,
        .brk = brk,
    };
    const status = runloop.run(&runner);

    if (runner.aborted) {
        if (runner.timed_out) {
            out("guest aborted: cycle-budget timeout (syscalls={d}); " ++
                "raise RUNUPC_MAX_SLICES if this is a legitimate long run\n",
                .{runner.syscall_count});
        } else {
            out("guest aborted (fault: {s} @ 0x{X:0>6}, syscalls={d})\n", .{
                @tagName(memory.fault.kind), memory.fault.address, runner.syscall_count,
            });
        }
        return error.GuestAborted;
    }
    return status;
}

/// Load <guestroot>/lib/shlib and map it into guest memory at its fixed vaddrs.
fn mapShlib(gpa: std.mem.Allocator, io: std.Io, memory: *mem.Memory, guestroot: []const u8) !void {
    var pbuf: [1200]u8 = undefined;
    const shlib_path = try std.fmt.bufPrint(&pbuf, "{s}/lib/shlib", .{guestroot});
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, shlib_path, gpa, .limited(2 * 1024 * 1024));
    defer gpa.free(bytes);
    try shlib.loadFromRoot(gpa, memory, bytes);
}

fn cmdRun(gpa: std.mem.Allocator, io: std.Io, path: []const u8, prog_args: []const []const u8, guestroot: ?[]const u8, extra_env: []const []const u8) !u8 {
    const status = runProgram(gpa, io, path, prog_args, guestroot, extra_env) catch |e| {
        out("run error: {s}\n", .{@errorName(e)});
        return 1;
    };
    outv("guest exited with status {d}\n", .{status});
    return @truncate(status);
}

fn selfCheck(gpa: std.mem.Allocator) !void {
    var memory = try mem.Memory.init(gpa);
    defer memory.deinit();
    mem.setActive(&memory);
    cpu.init();
    cpu.pulseReset();
    memory.write32(0x1000, 0xDEADBEEF);
    const seen = cpu.c.m68k_read_memory_32(0x1000);
    out("Musashi 68010 core initialized (CPU type = {d})\n", .{cpu.getReg(cpu.Reg.cpu_type)});
    out("memory self-check: wrote 0xDEADBEEF, CPU read 0x{X:0>8}\n", .{seen});
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Global flags: --trace enables strace logging; --root <dir> sets guestroot;
    // --env NAME=VALUE (repeatable) adds a variable to the guest environment.
    var i: usize = 1;
    var guestroot: ?[]const u8 = null;
    var extra_env: std.ArrayListUnmanaged([]const u8) = .empty;
    while (i < args.len) {
        if (std.mem.eql(u8, args[i], "--trace")) {
            trace.enabled = true;
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--quiet")) {
            quiet = true;
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--root") and i + 1 < args.len) {
            guestroot = args[i + 1];
            i += 2;
        } else if (std.mem.eql(u8, args[i], "--env") and i + 1 < args.len) {
            try extra_env.append(init.arena.allocator(), args[i + 1]);
            i += 2;
        } else break;
    }
    const extra_env_slice = extra_env.items;
    const rest = args[i..]; // rest[0] = subcommand, rest[1] = binary, ...

    if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--load")) {
        try cmdLoad(gpa, io, rest[1]);
    } else if (rest.len >= 2 and std.mem.eql(u8, rest[0], "run")) {
        // argv passed to the guest = [binary, extra args...] (argv[0] = binary).
        const prog_args: []const []const u8 = rest[1..];
        const code = try cmdRun(gpa, io, rest[1], prog_args, guestroot, extra_env_slice);
        std.process.exit(code);
    } else if (rest.len >= 2 and std.mem.eql(u8, rest[0], "--dumpstack")) {
        const prog_args: []const []const u8 = rest[1..];
        try cmdDumpStack(gpa, io, rest[1], prog_args);
    } else {
        try selfCheck(gpa);
    }
}
