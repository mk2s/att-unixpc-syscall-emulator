# AT&T UNIX PC (3B1) — User-Mode Syscall ABI

This document records the syscall ABI of the AT&T UNIX PC / 3B1 (Convergent
Technologies System V, MC68010), extracted directly from the machine's own C
library `/tmp/upc/lib/libc.a`. Every number here was recovered by disassembling
the syscall stub in the corresponding `libc.a` member, so these are ground
truth for this specific machine — not assumed from generic SVR2.

## Extraction method

Each `libc.a` member is a COFF object whose file header magic is one of the
68k magics (0520 / 0521 / 0522, see below). The syscall stubs follow a fixed
shape. Example — `dup.o` `.text`:

```
movew   #41, %d0        ; syscall number -> D0
trap    #0              ; enter kernel
bcc     .Lok            ; carry clear => success
jmp     cerror          ; carry set   => set errno, return -1
.Lok:
rts
```

Reproduce with the m68k-elf cross tools:

```
m68k-elf-ar x /tmp/upc/lib/libc.a          # unpack members
# parse COFF .text (see tools/extract_syscalls.py), then:
m68k-elf-objdump -D -b binary -m m68k:68010 <text.bin>
```

## Calling convention (`trap #0`)

Confirmed from the stubs:

| Aspect            | Convention                                                        |
|-------------------|-------------------------------------------------------------------|
| Trap instruction  | `trap #0` (kernel `SYSCALL` = exception vector 32, `sys/trap.h`)   |
| Syscall number    | In `D0` (loaded via `movew #N, %d0` before the trap)              |
| Arguments         | On the user (C) stack, per the standard 68k C calling convention. The kernel reads them from the user stack; libc stubs do not move them into registers. |
| Return value      | In `D0`                                                           |
| Error signalling  | Carry flag: **clear = success, set = error**. On error `D0` holds the errno value; libc's `cerror` copies it to the global `errno` and returns -1. |
| Second return val | In `D1` (used by `getppid`, `getgid`/`getegid`, `getuid`/`geteuid`, `pipe`). SVR2 dual-return: e.g. `getpid` puts pid in D0 and ppid in D1 from a single syscall. |

`exit` never returns (stub follows the trap with `stop #0` as a safety net).
`execve` does not return on success.

## Executable / object magics (`filehdr.h`)

The COFF file-header magic directly holds the 68k magic (there is no separate
optional-header magic layer for these objects):

| Magic (octal) | Hex    | Meaning                                  |
|---------------|--------|------------------------------------------|
| 0520          | 0x0150 | `MC68KWRMAGIC` — writable text (impure)  |
| 0521          | 0x0151 | `MC68KROMAGIC` — read-only sharable text |
| 0522          | 0x0152 | `MC68KPGMAGIC` — demand paged text       |

These correspond to the link formats `ifile.0407` / `0410` / `0413`.
Byte order is big-endian (`F_AR32W`).

## Syscall table (verified from libc.a)

62 distinct stubs recovered. Numbers are decimal.

| Num | Name       | Notes                                             |
|-----|------------|---------------------------------------------------|
| 1   | exit       | no return                                         |
| 2   | fork       | child pid in D0 (parent), 0 in child              |
| 3   | read       |                                                   |
| 4   | write      |                                                   |
| 5   | open       |                                                   |
| 6   | close      |                                                   |
| 7   | wait       |                                                   |
| 8   | creat      |                                                   |
| 9   | link       |                                                   |
| 10  | unlink     |                                                   |
| 12  | chdir      |                                                   |
| 13  | time       |                                                   |
| 14  | mknod      |                                                   |
| 15  | chmod      |                                                   |
| 16  | chown      |                                                   |
| 17  | sbrk       | UNIX-PC uses sbrk (not brk) as the primitive      |
| 18  | stat       |                                                   |
| 19  | lseek      |                                                   |
| 20  | getpid     | pid in D0, ppid in D1 (getppid reads D1)          |
| 21  | mount      |                                                   |
| 22  | umount     |                                                   |
| 23  | setuid     |                                                   |
| 24  | getuid     | uid in D0, euid in D1 (geteuid reads D1)          |
| 25  | __stime    | stime                                             |
| 26  | ptrace     |                                                   |
| 27  | alarm      |                                                   |
| 28  | fstat      |                                                   |
| 29  | pause      |                                                   |
| 30  | utime      |                                                   |
| 31  | stty       | (obsolete; maps to ioctl on real kernel)          |
| 32  | gtty       | (obsolete)                                        |
| 33  | access     |                                                   |
| 34  | nice       |                                                   |
| 36  | sync       |                                                   |
| 37  | kill       |                                                   |
| 39  | __setpgrp  | setpgrp                                           |
| 41  | dup        |                                                   |
| 42  | pipe       | read fd in D0, write fd in D1                     |
| 43  | times      |                                                   |
| 44  | profil     |                                                   |
| 45  | plock      |                                                   |
| 46  | setgid     |                                                   |
| 47  | getgid     | gid in D0, egid in D1 (getegid reads D1)          |
| 48  | signal     |                                                   |
| 49  | __msgsys   | msgsys                                            |
| 51  | acct       |                                                   |
| 52  | __shmsys   | shmsys                                            |
| 53  | __semsys   | semsys                                            |
| 54  | ioctl      |                                                   |
| 57  | __utssys   | utssys (uname etc.)                               |
| 59  | execve     | no return on success                              |
| 60  | umask      |                                                   |
| 61  | chroot     |                                                   |
| 62  | fcntl      |                                                   |
| 63  | ulimit     |                                                   |
| 67  | locking    |                                                   |
| 68  | syslocal   | UNIX-PC specific (see sys/syslocal.h)             |
| 69  | openi      | UNIX-PC specific                                  |
| 70  | swrite     | UNIX-PC specific                                  |

Confidence: HIGH for all entries — each number was read from the machine's own
`movew #N, %d0; trap #0` stub. The handful of paired names (getpid/getppid,
getuid/geteuid, getgid/getegid) share a syscall number by design (dual return
in D0/D1).

## errno values (`sys/errno.h`)

SysV base 1..44 plus Convergent extensions. Captured in `src/abi.zig`.
Host errno is translated to these guest values on the error path.

## Signals (`sys/signal.h`)

SIGHUP=1 .. SIGPHONE=21, `NSIG=32`, `SIG_DFL=0`, `SIG_IGN=1`.

## Process model (fork/exec/wait/pipe)

The default backend maps guest processes onto host processes (`src/procmodel.zig`,
`HostProcess`):

- `fork` (2) → host `fork()`. The child is a full copy of the emulator
  process, guest memory included, so it continues emulating with `fork()`
  returning 0 in D0; the parent gets the child pid in D0.
- `execve` (59) → clears the guest address space, loads a new COFF, rebuilds
  the initial stack, and jumps to the new entry (the run loop continues, PC not
  advanced). The halt pad is re-installed after `clearRegions`.
- `wait` (7) → host `waitpid`; the host status is re-encoded to the SVR wait
  status word `(exit_code & 0xff) << 8` and stored at the caller's pointer, pid
  returned in D0.
- `pipe` (42) → host `pipe()`, both ends registered in the guest fd table;
  read fd in D0, write fd in D1.

**Windows limitation:** host `fork()` does not exist on Windows, so this
backend is Linux/macOS only. The `ProcessModel` interface is the seam for a
future in-process backend (multiple CPU contexts in one host process) that
would restore Windows support without changing the syscall handlers.

## Notes discovered during toolchain bring-up

- **Syscall 17 is `brk`, not incremental `sbrk`.** The argument is the ABSOLUTE
  new break address. The libc `sbrk` wrapper in the shared library converts an
  increment to an absolute value (tracking the current break in a userland
  global at `0x301048`, initialized by `shlbat` from the process's initial
  break) and returns the old break. The kernel call itself just sets the
  absolute break and returns 0. The emulator's initial break must equal the
  exact end of the highest loaded section (NOT page-rounded), because that is
  the value crt0 hands to `shlbat`.

- **Directories are read with `read(2)`.** The 3B1 s5 filesystem returns 16-byte
  `struct direct` records (2-byte big-endian inode + 14-byte name) directly from
  `read()` on a directory fd. The emulator detects directory opens and
  synthesizes these records from the host directory stream (`src/host_dir.c`),
  since modern hosts forbid `read()` on directories.

- **fd allocation is lowest-free-first including 0/1/2**, so the classic
  `close(1); dup(pipefd)` redirection idiom the shell uses works (a closed
  standard descriptor is reused).

## Implemented syscalls

exit, fork, read, write, open, close, wait, creat, chdir, time, chmod?/chown?
(no), sbrk(=brk), stat, lseek, getpid, setuid, getuid, alarm, fstat, pause,
access, nice, sync, dup, pipe, times?(no), setgid, getgid, signal, ioctl,
execve, umask, chroot?(no), fcntl, syslocal, stty/gtty (as ENOTTY). Unimplemented
syscalls trigger a fail-fast diagnostic dump.
