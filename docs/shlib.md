# AT&T UNIX PC (3B1) — Shared Library ("early shared binary") Mechanism

Reverse-engineered from the on-disk artifacts in `/tmp/upc/lib` and confirmed by
disassembling a real shared-linked binary (`/tmp/upc/bin/echo`). This is the
classic AT&T System V "shared library" design: a fixed-address jump table, not
ELF-style dynamic linking. No per-binary relocation of the library is required.

## TL;DR for the loader

1. The shared library image `/tmp/upc/lib/shlib` is a COFF 0413 (demand-paged)
   file that maps at **fixed** virtual addresses:
   - `.data` at `0x300000` (this is `_dbase = 0x301000`'s containing region)
   - `.bss`  at `0x304374`
   - `.text` at `0x310000` (this is `_tbase`)
   All inside the reserved shared region `SHLIB_START=0x300000 .. SHLIB_END=0x380000`.
2. The first thing in `.text` (at `_tbase = 0x310000`) is a **jump table**:
   6-byte `jmp <abs32>` slots, one per exported routine. Entry N lives at
   `_tbase + offset` where the offsets come from `shlib.ifile`.
3. A program is linked so that every library call is an absolute
   `jsr <_tbase + offset>` straight into the jump table, and every library
   global is an absolute reference into the data region (e.g. `environ` at
   `0x301004`). Because the library is always mapped at the same address, these
   absolute references resolve with no relocation.
4. A shared-linked executable is marked by the presence of a **`.lib`** section
   (may be zero-length; it is a marker/attach descriptor). The kernel maps the
   shared library at exec time when it sees this.

So our emulator: **if a loaded binary has a `.lib` section (or otherwise
references the `0x300000..0x380000` region), map `shlib` at its fixed vaddrs
before starting execution.** No relocation, no jump-table rewriting needed.

## Evidence

### shlib COFF layout (parsed)

```
magic = 0o522 (MC68KPGMAGIC, demand paged)
aouthdr: text_start=0x310000  data_start=0x300000
  .data  vaddr=0x300000 size=0x4374  fileptr=0x400
  .bss   vaddr=0x304374 size=0x4a1c  (nobits)
  .text  vaddr=0x310000 size=0x1ad08 fileptr=0x4800
```

### The jump table (disassembled at `_tbase`)

```
310000: jmp 0x3108d8     ; shlbat   (attach / init)      = _tbase + 0x0
310006: jmp 0x310902     ; shlbatid                      = _tbase + 0x6
31000c: jmp 0x32811c     ; access                        = _tbase + 0xc
310012: jmp 0x326314     ; alarm                         = _tbase + 0x12
310018: jmp 0x310938     ; brk                           = _tbase + 0x18
...
```

Slot stride is 6 bytes = `4ef9 <abs32>`. Offsets match `shlib.ifile` exactly
(e.g. `access = _tbase + 0xc`, `exit = _tbase + 0x78`, `printf = _tbase + 0x39c`).

### shlib.ifile (the map)

`shlib.ifile` is a linker directive file. Key anchors:
- `_dbase = 0x00301000` (library data globals: `errno`, `environ` at `_dbase+4`,
  `PC`, `optind`, ...)
- `_tbase = 0x00310000` (jump table base)
- Fixed data at `0x300000..0x301000`: `timezone`, `tzname`, `_iob`, `_ctype`,
  `sys_errlist`, etc.
Every exported name is `_tbase + off` (text) or a fixed data address.

### A real shared binary (`/tmp/upc/bin/echo`)

```
magic=0o522  entry=0x80000  text=0x80000  data=0x90000
sections: .text .data .bss .lib      <-- .lib present (shared marker)
disasm:
  80006: jsr 0x310000        ; call shlbat  (attach shared lib) -- from crt0
  80022: movel %a0,0x301004  ; store into environ (=_dbase+4)
  80030: jsr 0x310078        ; call exit    (=_tbase+0x78)
  80050: jsr 0x3103c6        ; call putchar (=_tbase+0x3c6)
```

Confirms: absolute calls into the jump table and absolute data references, and
that `.lib` marks the binary as shared. `entry=0x80000 = VUSER_START`.

### crt0 stack contract (also feeds Task 6)

From `crt0.o` disassembly, `main` is entered as `main(argc, argv, envp)` with the
initial user stack (at `USRSTACK`) laid out as:

```
sp -> argc (long)
      argv[0] ptr, argv[1] ptr, ..., NULL
      envp[0] ptr, ..., NULL
      (string bytes for argv/envp somewhere reachable, pointed to by the above)
```

crt0 reads `argc = *sp`, `argv = sp+4`, scans past the argv NULL to find `envp`,
stores `envp` into `environ`, then `jsr main; push d0; jsr exit`.

## `shlbat` (attach routine)

`shlbat` at `0x3108d8` does userland initialization of shared data pointers
(sets up `_iob` links, brk pointer via the sbrk glue at `0x310926`). It does
**not** itself issue the mapping syscall — the actual mapping of the shared
segment into the process address space is performed by the **kernel at exec
time** based on the `.lib` section. For the emulator we replicate that kernel
behavior in the loader.

## Implementation plan (Task 12)

- `src/shlib.zig`: parse `shlib` COFF, expose its section images and fixed
  vaddrs. Provide `mapInto(mem)` that copies `.text`/`.data` to their vaddrs and
  zero-fills `.bss`, marking the region as a distinct mapped range.
- Loader (`coff.zig`): detect the `.lib` section → classify binary as shared →
  invoke `shlib.mapInto` before execution. Static stubs (no `.lib`) are
  unaffected.
- Wire into both initial load and `exec`.

## Implementation status

Implemented in `src/shlib.zig` (`mapInto`/`loadFromRoot`) and wired into the
loader (`src/main.zig` `mapShlib`) and `exec` (`src/procmodel.zig`). When a
loaded binary has a `.lib` section, the emulator reads `<guestroot>/lib/shlib`
and maps its `.text`/`.data`/`.bss` at the fixed vaddrs above. Verified: the
real shared-linked `/bin/echo`, `/bin/cat`, `/bin/sh`, etc. run correctly, with
all jump-table calls resolving with no relocation.
