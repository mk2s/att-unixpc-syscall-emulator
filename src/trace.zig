//! strace-style syscall tracing. When enabled, each serviced syscall prints a
//! decoded line to stderr, e.g.:
//!   write(1, "hello\n", 6) = 6
//!   open("/etc/passwd", O_RDONLY) = 3
//!   exit(0)
//!
//! Decoding is best-effort per syscall; unknown args print as hex.

const std = @import("std");
const abi = @import("abi.zig");
const mem = @import("mem.zig");

extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

pub var enabled: bool = false;

fn eprint(comptime fmt: []const u8, args: anytype) void {
    if (!enabled) return;
    var buf: [1024]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = write(2, s.ptr, s.len);
}

/// Render a guest string argument as a quoted, escaped, length-limited literal.
fn quoteStr(memory: *mem.Memory, addr: u32, max: usize, out: []u8) []const u8 {
    var w: usize = 0;
    if (w < out.len) {
        out[w] = '"';
        w += 1;
    }
    var i: usize = 0;
    while (i < max and w + 2 < out.len) : (i += 1) {
        const ch = memory.read8(addr + @as(u32, @intCast(i)));
        if (ch == 0) break;
        switch (ch) {
            '\n' => {
                out[w] = '\\';
                out[w + 1] = 'n';
                w += 2;
            },
            '\t' => {
                out[w] = '\\';
                out[w + 1] = 't';
                w += 2;
            },
            '"', '\\' => {
                out[w] = '\\';
                out[w + 1] = ch;
                w += 2;
            },
            0x20...0x21, 0x23...0x5B, 0x5D...0x7E => {
                out[w] = ch;
                w += 1;
            },
            else => {
                // non-printable: show as .
                out[w] = '.';
                w += 1;
            },
        }
    }
    if (w < out.len) {
        out[w] = '"';
        w += 1;
    }
    return out[0..w];
}

/// Called before dispatch to print the syscall name + decoded args.
/// `getArg(n)` returns the nth (1-based) stack argument.
pub fn entry(
    memory: *mem.Memory,
    number: u16,
    getArg: *const fn (n: u32) u32,
) void {
    if (!enabled) return;
    const sc: abi.Syscall = @enumFromInt(number);
    var sbuf: [256]u8 = undefined;

    switch (sc) {
        .exit => eprint("exit({d})", .{getArg(1)}),
        .write, .swrite => {
            const fd = getArg(1);
            const buf = getArg(2);
            const len = getArg(3);
            const str = quoteStr(memory, buf, @min(len, 32), &sbuf);
            eprint("{s}({d}, {s}, {d})", .{ sc.name(), fd, str, len });
        },
        .read => eprint("read({d}, 0x{X:0>6}, {d})", .{ getArg(1), getArg(2), getArg(3) }),
        .open, .openi => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("{s}({s}, 0x{X})", .{ sc.name(), path, getArg(2) });
        },
        .close => eprint("close({d})", .{getArg(1)}),
        .creat => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("creat({s}, 0{o})", .{ path, getArg(2) });
        },
        .lseek => eprint("lseek({d}, {d}, {d})", .{ getArg(1), getArg(2), getArg(3) }),
        .unlink, .chdir, .chroot => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("{s}({s})", .{ sc.name(), path });
        },
        .stat => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("stat({s}, 0x{X:0>6})", .{ path, getArg(2) });
        },
        .fstat => eprint("fstat({d}, 0x{X:0>6})", .{ getArg(1), getArg(2) }),
        .access => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("access({s}, 0{o})", .{ path, getArg(2) });
        },
        .dup => eprint("dup({d})", .{getArg(1)}),
        .fork => eprint("fork()", .{}),
        .execve => {
            const path = quoteStr(memory, getArg(1), 128, &sbuf);
            eprint("execve({s}, [", .{path});
            // Decode the argv array (NUL-terminated list of char*).
            const argv_ptr = getArg(2);
            var i: u32 = 0;
            while (i < 32) : (i += 1) {
                const p = memory.read32(argv_ptr + i * 4);
                if (p == 0) break;
                var ab: [128]u8 = undefined;
                const a = quoteStr(memory, p, 100, &ab);
                if (i > 0) eprint(", ", .{});
                eprint("{s}", .{a});
            }
            eprint("])", .{});
        },
        .wait => eprint("wait(0x{X:0>6})", .{getArg(1)}),
        .getpid, .getuid, .getgid, .sync, .pause => eprint("{s}()", .{sc.name()}),
        .sbrk => eprint("brk(0x{X:0>6})", .{getArg(1)}), // syscall 17 = absolute brk
        .time => eprint("time(0x{X:0>6})", .{getArg(1)}),
        .signal => eprint("signal({d}, 0x{X:0>6})", .{ getArg(1), getArg(2) }),
        .ioctl => eprint("ioctl({d}, 0x{X}, 0x{X:0>6})", .{ getArg(1), getArg(2), getArg(3) }),
        .fcntl => eprint("fcntl({d}, {d}, 0x{X})", .{ getArg(1), getArg(2), getArg(3) }),
        else => eprint("{s}(0x{X}, 0x{X}, 0x{X})", .{ sc.name(), getArg(1), getArg(2), getArg(3) }),
    }
}

/// Called after dispatch to print the result.
pub fn result(rv: u32, is_error: bool, errno: u16) void {
    if (!enabled) return;
    if (is_error) {
        eprint(" = -1 (errno {d})\n", .{errno});
    } else {
        eprint(" = {d}\n", .{@as(i32, @bitCast(rv))});
    }
}

/// For exit (no return line).
pub fn newline() void {
    eprint("\n", .{});
}
