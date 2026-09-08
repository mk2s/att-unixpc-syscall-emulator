# runupc — AT&T UNIX PC (3B1) user-mode syscall emulator

`runupc` runs native AT&T UNIX PC / 3B1 (Convergent Technologies System V,
MC68010) command-line binaries on a modern host. It loads a COFF executable,
emulates the 68010 with [Musashi](https://github.com/kstenerud/Musashi), and
services the guest's `trap #0` system calls against the host filesystem and
process model — the same idea as `qemu-user`, but for the 3B1.

It is a **user-mode** emulator: no ROM, no full-system hardware, no graphics or
phone peripherals. The target workload is the CLI toolchain (shell, compiler,
assembler, linker, and supporting utilities).

## Status

Working today (verified against real 3B1 binaries):

- Loads COFF executables (magics 0407/0410/0413), static and shared.
- Maps the 3B1 shared library (`/lib/shlib`) at its fixed address so
  shared-linked binaries run with no relocation (see `docs/shlib.md`).
- Runs real utilities: `echo`, `cat`, `pwd`, `date`, `ls` (directory reads),
  `expr`, and the shell `sh -c "..."` driving builtins, external commands
  (`fork`/`exec`/`wait`), sequential commands (`;`), and file redirection (`>`).
- File syscalls against a chroot-style guest root, `brk`/`sbrk` heap, and a set
  of misc syscalls (see `docs/abi.md`).
- strace-style syscall tracing and fail-fast diagnostics.

Known gaps (honest status):

- Two-process pipelines (`cmd | cmd`): a pipe-fd lifecycle bug across forked
  emulator processes prevents the second stage from running reliably.
- The full `cc` compile driver does not complete yet (faults marshalling
  sub-phase argv). The individual pieces (loader, shlib, fork/exec, file I/O)
  work; the driver needs more iteration.
- Windows: `fork`/`exec`/`wait`/`pipe` require host `fork()`, which Windows
  lacks. The build compiles for Windows and single-process programs work, but
  multi-process features return an error. See "Cross-platform" below.

## Building

Requires a recent Zig (developed against `0.17.0-dev`; the plan targeted 0.16,
but the code tracks the current `std.Io`/build API — see notes in `build.zig`).

```
zig build                 # build the emulator -> zig-out/bin/<arch>-<os>/runupc
zig build test            # run the unit + integration test suite
zig build run             # build + run the self-check
```

Each target installs into its own `zig-out/bin/<arch>-<os>/` directory, so
cross-builds (`-Dtarget=...`) don't overwrite each other. For example the
native Linux binary is `zig-out/bin/x86_64-linux/runupc`.

The Musashi 68k core is vendored under `vendor/musashi/` and compiled with
`zig cc`. The opcode tables (`m68kops.c/.h`) are pre-generated; to regenerate:

```
cd vendor/musashi && zig cc -o m68kmake m68kmake.c && ./m68kmake
```

## Running

```
runupc [--trace] [--root DIR] run <guest-binary> [args...]
runupc --load <guest-binary>          # inspect COFF header/sections
runupc --dumpstack <binary> [args...] # show initial stack + registers
```

- `--root DIR` sets the guest root ("/"). All guest paths resolve under it and
  cannot escape it. Shared binaries need `DIR/lib/shlib` present.
- `--trace` prints an strace-style line per syscall to stderr.

### Setting up a guest root

Point `--root` at a directory laid out like the 3B1 filesystem. The simplest
way is to copy an extracted 3B1 tree (skip device nodes):

```
mkdir -p guestroot
( cd /path/to/unixpc-fs && tar cf - --exclude=./dev . ) | ( cd guestroot && tar xf - )
mkdir -p guestroot/tmp guestroot/dev
```

### Examples

```
runupc --root guestroot run guestroot/bin/echo hello world
runupc --root guestroot run guestroot/bin/cat /etc/passwd
runupc --root guestroot run guestroot/bin/sh -c "echo hi; expr 6 \* 7"
runupc --trace --root guestroot run guestroot/bin/date
```

## Cross-platform

`zig build -Dtarget=<triple>` cross-compiles; each target installs to its own
`zig-out/bin/<arch>-<os>/` directory. Verified to compile for:

- `x86_64-linux` / native — full functionality.
- `aarch64-macos` — expected to work like Linux (POSIX `fork`).
- `x86_64-windows` — compiles; single-process programs run. `fork`/`exec`/
  `wait`/`pipe` return "not supported" because Windows has no `fork()`. The
  process model lives behind the `ProcessModel` interface (`src/procmodel.zig`),
  so a future in-process backend (multiple 68k contexts in one host process)
  can restore Windows multi-process support without touching the syscall
  handlers.

## Layout

```
src/
  main.zig       CLI entry (juicy std.process.Init main), run/load/dumpstack
  cpu.zig        Musashi 68010 bindings
  mem.zig        guest address space (big-endian, permissioned)
  coff.zig       COFF loader (filehdr/aouthdr/scnhdr)
  shlib.zig      3B1 shared-library mapping
  process.zig    initial stack (argc/argv/envp) per crt0
  runloop.zig    run loop + trap #0 interception
  syscalls.zig   syscall dispatcher + implementations
  fs.zig         chroot-style paths + fd table + directory reads
  procmodel.zig  fork/exec/wait/pipe (host-process backend + interface)
  diag.zig       fail-fast register/stack/disasm dump
  trace.zig      strace-style logging
  host_stat.c    portable stat/fstat + errno shim
  host_dir.c     portable directory reading shim
vendor/musashi/  vendored Musashi 68k core
tools/           extract_syscalls.py, inspect_shlib.py, mkstub.py
tests/stubs/     hand-written 68k test programs + build_stubs.sh
docs/            abi.md (syscall ABI), shlib.md (shared-lib mechanism)
```

## How it works

- **Syscall ABI** was extracted directly from the machine's own `libc.a`
  (`docs/abi.md`): number in `D0`, `trap #0`, args on the C stack, return in
  `D0`, error via the carry flag with errno in `D0`, second return in `D1`.
- **Shared libraries** use a fixed-address jump table at `0x310000`
  (`docs/shlib.md`): the loader maps `shlib` at its fixed vaddrs and the
  program's absolute calls resolve with no relocation.
- **trap #0 interception**: Musashi's per-instruction hook catches the `trap #0`
  opcode before it executes; the syscall is serviced in Zig and PC advances past
  the trap, so the CPU stays in user mode with no supervisor stack / vector
  emulation.

## License / attribution

Musashi is Copyright Karl Stenerud, MIT-licensed (see
`vendor/musashi/m68k.h`). This emulator was built with the AT&T UNIX PC
technical reference and the machine's own headers/binaries as ABI references.
