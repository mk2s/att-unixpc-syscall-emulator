#!/usr/bin/env python3
"""Wrap a raw m68k .text blob into a minimal AT&T UNIX PC COFF executable.

Produces a COFF file the emulator's loader accepts: filehdr (magic 0407
MC68KWRMAGIC) + aouthdr + one .text section, big-endian. Text is loaded at
VUSER_START=0x80000 and entry = text_start.

Usage: tools/mkstub.py <in.bin> <out.coff> [entry_hex]
"""
import struct, sys

VUSER_START = 0x80000
MC68KWRMAGIC = 0o520


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    text = open(sys.argv[1], "rb").read()
    out = sys.argv[2]
    entry = int(sys.argv[3], 16) if len(sys.argv) > 3 else VUSER_START

    filhsz = 20
    aouthsz = 28
    scnhsz = 40
    text_off = filhsz + aouthsz + scnhsz  # raw text follows headers

    # filehdr: f_magic, f_nscns, f_timdat, f_symptr, f_nsyms, f_opthdr, f_flags
    filehdr = struct.pack(
        ">HHIIIHH", MC68KWRMAGIC, 1, 0, 0, 0, aouthsz, 0x0002  # F_EXEC
    )
    # aouthdr: magic, vstamp, tsize, dsize, bsize, entry, text_start, data_start
    aouthdr = struct.pack(
        ">HHIIIIII", MC68KWRMAGIC, 0, len(text), 0, 0, entry, VUSER_START, VUSER_START + len(text)
    )
    # scnhdr .text
    name = b".text".ljust(8, b"\x00")
    scnhdr = struct.pack(
        ">8sIIIIIIHHI",
        name,
        VUSER_START,           # s_paddr
        VUSER_START,           # s_vaddr
        len(text),             # s_size
        text_off,              # s_scnptr
        0, 0, 0, 0,            # relptr, lnnoptr, nreloc, nlnno
        0x20,                  # STYP_TEXT
    )

    with open(out, "wb") as f:
        f.write(filehdr)
        f.write(aouthdr)
        f.write(scnhdr)
        f.write(text)
    print(f"wrote {out}: {len(text)} bytes text, entry=0x{entry:x}")


if __name__ == "__main__":
    main()
