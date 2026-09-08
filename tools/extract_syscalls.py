import struct, subprocess, sys, os

libc = "/tmp/upc/lib/libc.a"
workdir = "/tmp/libc_x"

def be16(b,o): return struct.unpack_from(">H",b,o)[0]
def be32(b,o): return struct.unpack_from(">I",b,o)[0]

# parse COFF: filehdr(20) where f_magic holds 68k magic, f_opthdr may be 0.
# sections follow filehdr (+ opthdr). scnhdr is 40 bytes.
def parse_text(data):
    magic = be16(data,0)
    nscns = be16(data,2)
    opthdr = be16(data,16)
    off = 20 + opthdr
    for i in range(nscns):
        sh = data[off:off+40]
        name = sh[0:8].split(b'\x00')[0].decode('latin1')
        s_size = be32(sh,16)
        s_scnptr = be32(sh,20)
        if name == '.text':
            return data[s_scnptr:s_scnptr+s_size], magic
        off += 40
    return None, magic

def find_syscall(text):
    # look for movew #N,d0 = 0x303c NNNN  followed shortly by trap #0 = 0x4e40
    for i in range(0, len(text)-4, 2):
        if text[i]==0x30 and text[i+1]==0x3c:
            n = be16(text, i+2)
            # scan next few words for trap #0
            for j in range(i+4, min(i+12, len(text)-1), 2):
                if text[j]==0x4e and text[j+1]==0x40:
                    return n
    # some stubs: trap #0 with no movew (number via other means) or moveq
    for i in range(0, len(text)-1, 2):
        if text[i]==0x4e and text[i+1]==0x40:
            return ("trap0-no-movew", i)
    return None

members = subprocess.check_output(["/opt/cross/bin/m68k-elf-ar","t",libc]).decode().split()
os.chdir(workdir)
subprocess.run(["/opt/cross/bin/m68k-elf-ar","x",libc], check=True)

results = {}
for m in members:
    try:
        with open(os.path.join(workdir,m),'rb') as f:
            data = f.read()
    except FileNotFoundError:
        continue
    if len(data)<20: continue
    if be16(data,0) not in (0x150,0x151,0x152): 
        continue
    text,magic = parse_text(data)
    if not text: continue
    sc = find_syscall(text)
    if isinstance(sc,int):
        name = m[:-2] if m.endswith('.o') else m
        results[name]=sc

for name,num in sorted(results.items(), key=lambda kv: kv[1]):
    print(f"{num:4d}  {name}")
print(f"\n# {len(results)} syscall stubs found", file=sys.stderr)
