#!/usr/bin/env bash
# Assemble the hand-written 68k test stubs into COFF executables the emulator
# can load. Requires the m68k-elf cross toolchain (/opt/cross/bin) and python3.
set -euo pipefail
export PATH=/opt/cross/bin:$PATH
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

build_one() {
    local name="$1"
    local entry="${2:-80000}"
    m68k-elf-as -m68010 -o "$here/$name.o" "$here/$name.s"
    m68k-elf-objcopy -O binary "$here/$name.o" "$here/$name.bin"
    python3 "$root/tools/mkstub.py" "$here/$name.bin" "$here/$name.coff" "$entry"
    rm -f "$here/$name.o" "$here/$name.bin"
}

for s in "$here"/*.s; do
    base="$(basename "$s" .s)"
    build_one "$base"
done
