# Reading Zig as a C developer

This is a quick orientation to the Zig used in this project, written for
someone who knows C but hasn't used Zig. It focuses on the things you'll
actually hit reading `src/*.zig` and `build.zig`, and it uses real snippets
from this codebase. It is not a full language tour.

Zig sits close to C: manual memory, no hidden control flow, no garbage
collector, structs are just structs. The differences that trip up C readers
are mostly syntax, the module/import system, error handling, `comptime`, and
the build system. We'll go through those.

> Version note: this project tracks a `0.17.0-dev` toolchain. Some of what
> follows (the `std.Io` reorg, removal of `@cImport`, the "juicy main") is newer
> than older tutorials show. Where the API is in flux, `build.zig` and the
> `src/*.zig` comments record what actually works.

---

## 1. Syntax cheatsheet (C → Zig)

| C | Zig |
|---|-----|
| `int x = 5;` | `var x: i32 = 5;` (mutable) or `const x: i32 = 5;` |
| `#define N 80` | `const N = 80;` (a real typed constant) |
| `uint32_t` | `u32` (also `u8/u16/u64/i32/usize/isize`) |
| `struct Foo { ... };` | `const Foo = struct { ... };` |
| `enum E { A, B };` | `const E = enum { a, b };` |
| `Foo f = {0};` | `var f: Foo = .{};` (fields use defaults) |
| `p->field` / `p.field` | `p.field` (Zig auto-derefs one pointer level) |
| `arr[i]` | `arr[i]`; slices are `arr[a..b]` |
| `sizeof(x)` | `@sizeOf(T)` |
| `(T)x` cast | `@intCast(x)`, `@ptrCast(x)`, `@truncate(x)`, `@bitCast(x)` |
| `goto cleanup;` | `defer` / `errdefer` |
| `x && y` | `x and y`; `!x` is `!x` |
| function pointer | `*const fn (Args) Ret` |

Integer types are explicit widths. There is no implicit narrowing: assigning a
`u32` into a `u16` needs `@truncate` or `@intCast`. Overflow is checked in Debug
builds (it panics), which catches a lot of C-style bugs.

Casts are builtins that name the intent:
- `@intCast(x)` — value-preserving integer cast (panics if it doesn't fit).
- `@truncate(x)` — keep the low bits (like a C narrowing cast).
- `@bitCast(x)` — reinterpret the bits (e.g. `u32` ↔ `i32`, same size).
- `@ptrCast`/`@alignCast` — pointer reinterpretation.

Example from `src/runloop.zig` (reading a stack arg, note the widths):

```zig
pub fn arg(self: *Runner, n: u32) u32 {
    const sp = cpu.getReg(cpu.Reg.sp);
    return self.memory.read32(sp + 4 * n);
}
```

---

## 2. Optionals and errors instead of sentinels and errno

Zig has no null-pointer-by-default and no `errno`. Two dedicated features
replace the C idioms.

**Optionals** (`?T`) — a value that may be absent, like a nullable pointer but
checked by the compiler:

```zig
pub var active: ?*Memory = null;   // from src/mem.zig

// unwrap with `orelse` (provide a fallback / early return):
const m = active orelse return 0;  // if null, return 0
m.read8(addr);                     // here `m` is a plain *Memory
```

**Error unions** (`!T`) — a function returns either a value or an error. `try`
propagates the error (like `if (rc < 0) return rc;` but automatic), and `catch`
handles it:

```zig
// signature: returns u32 OR an error
pub fn runProgram(...) !u32 { ... }

// caller: propagate the error upward
const bytes = try readFile(path);

// caller: handle it inline
var image = coff.load(gpa, &memory, bytes) catch |e| {
    out("load error: {s}\n", .{@errorName(e)});
    return;
};
```

Errors are values from an error set, e.g. `src/coff.zig`:

```zig
pub const LoadError = error{ TooSmall, BadMagic, NotExecutable, BadSection };
```

There is no exception unwinding — an error is just a return value the compiler
forces you to handle.

---

## 3. `defer` and `errdefer` (cleanup without goto)

`defer` runs a statement when the current scope exits (success or error);
`errdefer` runs only if the scope exits via an error. This is how Zig does the
C `goto cleanup;` pattern:

```zig
var memory = try mem.Memory.init(gpa);
defer memory.deinit();          // always freed on scope exit

var sections = try allocator.alloc(Section, nscns);
errdefer allocator.free(sections);  // freed ONLY if a later `try` fails
```

---

## 4. Slices and allocators (no raw malloc)

A **slice** `[]T` is a pointer + length — the safe replacement for
`(T*, size_t)` pairs everywhere in C. `[]const u8` is the idiomatic "string /
byte buffer". Sentinel-terminated slices exist too: `[:0]const u8` is a
NUL-terminated string (useful for calling libc).

Zig has no global `malloc`. Allocation goes through an explicit
`std.mem.Allocator` passed around as a parameter — you can see who allocates.

```zig
const raw = try allocator.dupe(u8, bytes);   // like strdup for bytes
defer allocator.free(raw);

var list: std.ArrayListUnmanaged(u8) = .empty; // growable array
defer list.deinit(allocator);
try list.appendSlice(allocator, chunk[0..n]);
```

Note `ArrayListUnmanaged` takes the allocator on each call rather than storing
it — a common modern-Zig pattern. Its empty value is `.empty` (not `{}`).

Fixed arrays are zero-initialized with `@splat`:

```zig
var test_mem: [4096]u8 = @splat(0);
```

---

## 5. Structs, methods, and `.field` init

Structs hold methods (functions whose first parameter is `self`). There is no
separate class concept.

```zig
pub const Memory = struct {
    bytes: []u8,
    enforce: bool = false,               // field default

    pub fn init(allocator: std.mem.Allocator) !Memory { ... }
    pub fn deinit(self: *Memory) void { ... }
    pub fn read8(self: *Memory, addr: u32) u8 { ... }
};

// call site — method syntax, self is implicit:
var m = try Memory.init(gpa);
const b = m.read8(0x1000);
```

`.{ ... }` is an anonymous struct literal whose type is inferred from context.
You'll see it constantly for options and initializers:

```zig
try m.addRegion(0x80000, 0x1000, .{ .read = true, .exec = true });
//                                 ^ a Perm{} with write defaulting to false
```

Tagged unions carry a discriminant (like a C `union` + `enum` tag together),
matched with `switch`:

```zig
pub const Reason = union(enum) {
    unimplemented_syscall: u16,
    memory_fault: mem.Fault,
    message: []const u8,
};

switch (reason) {
    .unimplemented_syscall => |n| eprint("syscall {d}\n", .{n}),
    .memory_fault => |f| eprint("fault @ {x}\n", .{f.address}),
    .message => |m| eprint("{s}\n", .{m}),
}
```

---

## 6. `comptime` (compile-time execution)

Zig runs ordinary Zig at compile time. This replaces C's preprocessor, macros,
and templates. Generics are just functions that take a `type` and run at
`comptime`. In this project you mostly see `comptime` blocks used to force a
declaration to be analyzed/linked:

```zig
comptime {
    _ = mem.Callbacks;   // ensure these exported C symbols are compiled in
}
```

`@import(...)` itself is a compile-time operation (see next section).

---

## 7. Modules and `@import` (there is no `#include`)

Zig has no textual include and no header files. A `.zig` file **is** a struct,
and `@import("path.zig")` evaluates to that struct at compile time. You then
reach into it with `.`:

```zig
const std = @import("std");        // the standard library
const abi = @import("abi.zig");    // our module, by relative path
const cpu = @import("cpu.zig");

// use members with dot syntax:
const start = abi.VUSER_START;
cpu.init();
```

`pub` controls visibility: only `pub` declarations are reachable from other
modules (like an implicit header). A non-`pub` fn is file-private.

There are two kinds of names you import:
- A **relative path** like `@import("abi.zig")` — another source file.
- A **module name** like `@import("std")` or `@import("musashi")` — a named
  module wired up in `build.zig` (see §9).

Because files are structs, "circular imports" are fine as long as you don't
create a circular *type* dependency; two files can import each other.

A useful subtlety this project relies on: `@import` is lazy about analysis. A
file can `@import("cpu.zig")` (which itself imports the C `musashi` module), and
if nothing you actually reference pulls in the C bits, the tests can build
without the C toolchain. That's why some pure-Zig unit tests compile even though
their file imports a C-backed module.

---

## 8. Calling C (and why there's no `@cImport` here)

Zig links against C and calls C functions directly. Two pieces:

**Declaring C functions** with `extern`:

```zig
// from src/fs.zig — libc calls, stable across platforms
pub extern "c" fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
pub extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;

// our own C shim (src/host_stat.c), default (C) linkage:
pub extern fn upc_errno() c_int;
```

Note the C-flavored types: `c_int`, `c_uint`, `c_long`, and pointer forms
`[*:0]const u8` (NUL-terminated C string) and `[*]u8` (unknown-length C buffer).

**Exporting Zig functions to C** with `export` and `callconv(.c)` — this is how
the Musashi core (C) calls back into our Zig memory model:

```zig
export fn m68k_read_memory_8(address: c_uint) callconv(.c) c_uint {
    const m = active orelse return 0;
    return m.read8(@intCast(address));
}
```

`export` gives the symbol C linkage/name so the C object can find it at link
time. (Historically `callconv(.C)`; current toolchains use lowercase
`callconv(.c)`.)

### The `@cImport` change

Older Zig let you translate a C header inline:

```zig
// OLD — no longer available in this toolchain:
const c = @cImport({
    @cInclude("m68k.h");
});
```

`@cImport` has been **removed**. C headers are now translated by a build step
(`translate-c`) that produces a normal Zig module, which you import by name.
In `build.zig`:

```zig
const translate = b.addTranslateC(.{
    .root_source_file = b.path("src/musashi_c.h"),
    .target = target,
    .optimize = optimize,
    .link_libc = true,
});
translate.addIncludePath(b.path("vendor/musashi"));
root.addImport("musashi", translate.createModule());  // name it "musashi"
```

Then in Zig you use it like any other module:

```zig
pub const c = @import("musashi");   // src/cpu.zig
...
c.m68k_init();
c.m68k_set_cpu_type(c.M68K_CPU_TYPE_68010);
```

`src/musashi_c.h` is a tiny wrapper header that `#define`s the config and
`#include`s the real `m68k.h`; `translate-c` turns all of `m68k.h`'s functions,
enums, and `#define`d constants into Zig declarations under the `musashi`
module. The practical upshot for a reader: **look in `build.zig` to see which C
headers become which Zig module names.**

---

## 9. Reading `build.zig`

`build.zig` is not a config file — it's a normal Zig program with a `build`
function that the `zig build` command runs to construct a graph of steps. Think
of it as a Makefile written in Zig. Key concepts:

- `b: *std.Build` is the build context; `b.path("x")` makes a lazy path.
- **Options**: `b.standardTargetOptions(.{})` and `b.standardOptimizeOption(.{})`
  read `-Dtarget=...` / `-Doptimize=...` from the command line.
- **Modules**: `b.createModule(.{ .root_source_file = ..., .target, .optimize })`
  creates a compilation unit. You attach C sources and imports to a module:

  ```zig
  const root = b.createModule(.{
      .root_source_file = b.path("src/main.zig"),
      .target = target,
      .optimize = optimize,
  });
  root.addIncludePath(b.path("vendor/musashi"));
  root.addCSourceFiles(.{                    // compile C with `zig cc`
      .root = b.path("vendor/musashi"),
      .files = &.{ "m68kcpu.c", "m68kdasm.c", "m68kops.c", "softfloat/softfloat.c" },
      .flags = &.{ "-std=gnu11", "-DMUSASHI_CNF=\"m68kconf.h\"" },
  });
  root.link_libc = true;
  ```

- **Artifacts**: `b.addExecutable(.{ .name = "runupc", .root_module = root })`
  produces a binary. `b.addTest(.{ .root_module = ... })` produces a test
  binary.
- **Install / run / test steps**: you register named steps and wire
  dependencies between them:

  ```zig
  const install_exe = b.addInstallArtifact(exe, .{
      .dest_sub_path = "x86_64-linux/runupc",   // per-target output dir
  });
  b.getInstallStep().dependOn(&install_exe.step);

  const run_step = b.step("run", "Run the emulator");
  run_step.dependOn(&b.addRunArtifact(exe).step);

  const test_step = b.step("test", "Run unit tests");
  test_step.dependOn(&b.addRunArtifact(some_test).step);
  ```

So `zig build` runs the default (install) step, `zig build run` runs the `run`
step, `zig build test` runs the `test` step. Anything a step transitively
`dependOn`s gets built first.

This project builds several **test binaries**, not one: pure-Zig files are
grouped into cheap tests, while files that execute guest code get their own
C-linked test target (Musashi core + the translated `musashi` module + the C
shims). That's all just modules and steps assembled in `build.zig`.

---

## 10. Tests are part of the language

`test "name" { ... }` blocks live next to the code. `zig build test` (or
`zig test file.zig`) runs every reachable test. `std.testing` has the
assertions:

```zig
test "big-endian round trips" {
    var m = try Memory.init(std.testing.allocator);
    defer m.deinit();
    m.write32(0x1000, 0x11223344);
    try std.testing.expectEqual(@as(u8, 0x11), m.read8(0x1000));
}
```

`std.testing.allocator` is a leak-checking allocator, so a missing `deinit`
fails the test. Because tests are compiled into whatever binary imports the
file, be mindful of shared global state between tests (this project hit exactly
that — see the notes in `src/cpu_test.zig`).

---

## 11. The `main` entry point

Zig's `main` can take a rich init struct. This project uses the "full" form:

```zig
pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;                 // a general-purpose allocator
    const io = init.io;                   // the std.Io interface
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    ...
}
```

The runtime hands you the allocator, an `Io` handle, and the command-line args
directly — you don't call a separate `argsAlloc`. (`std.process.argsAlloc` was
removed in this toolchain; the init struct replaces it.) The `!void` return
means `main` can return an error, which the runtime turns into a nonzero exit.

---

## Where to look next

- `src/mem.zig` — clean example of a struct with methods, slices, and exported
  C callbacks.
- `src/cpu.zig` — importing and using the translated C `musashi` module.
- `build.zig` — modules, C sources via `zig cc`, translate-c, and per-target
  install.
- `src/abi.zig` — enums, constants, and a big `switch` (contrast with C's
  `#define` tables).

The official language reference (ziglang.org/documentation) is the
authoritative source; this file is just enough to read *this* codebase.
