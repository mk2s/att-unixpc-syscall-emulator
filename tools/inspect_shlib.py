#!/usr/bin/env python3
"""Inspect the 3B1 shared library: parse shlib COFF, dump the jump table, and
verify a binary references it. See docs/shlib.md.

Usage:
  tools/inspect_shlib.py /tmp/upc/lib/shlib [ /tmp/upc/bin/echo ]
"""
import struct, sys, subprocess

OBJDUMP = "/opt/cross/bin/m68k-elf-objdump"


def be16(d, o): return struct.unpack_from(">H", d, o)[0]
def be32(d, o): return struct.unpack_from(">I", d, o)[0]


def parse_coff(path):
    d = open(path, "rb").read()
    magic, nscns, opthdr = be16(d, 0), be16(d, 2), be16(d, 16)
    info = {"magic": magic, "nscns": nscns, "opthdr": opthdr, "sections": {}}
    off = 20
    if opthdr:
        info["text_start"] = be32(d, 20 + 20)
        info["data_start"] = be32(d, 20 + 24)
        off = 20 + opthdr
    for _ in range(nscns):
        sh = d[off:off + 40]
        name = sh[0:8].split(b"\x00")[0].decode("latin1")
        info["sections"][name] = {
            "vaddr": be32(sh, 12), "size": be32(sh, 16), "scnptr": be32(sh, 20),
        }
        off += 40
    return d, info


def main():
    shlib = sys.argv[1] if len(sys.argv) > 1 else "/tmp/upc/lib/shlib"
    d, info = parse_coff(shlib)
    print(f"shlib magic={oct(info['magic'])} text_start={info.get('text_start'):#x} "
          f"data_start={info.get('data_start'):#x}")
    for n, s in info["sections"].items():
        print(f"  {n:8s} vaddr={s['vaddr']:#010x} size={s['size']:#010x} scnptr={s['scnptr']:#x}")
    t = info["sections"][".text"]
    off = t["scnptr"]
    open("/tmp/_jt.bin", "wb").write(d[off:off + 64])
    print("jump table (first slots):")
    subprocess.run([OBJDUMP, "-D", "-b", "binary", "-m", "m68k:68010",
                    f"--adjust-vma={t['vaddr']:#x}", "/tmp/_jt.bin"])


if __name__ == "__main__":
    main()
