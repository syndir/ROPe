#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
base = iter(elf.libs)

#binsh = elf.libc.symbols['/bin/sh']
#print(f"{binsh}")

for s in elf.segments:
    print(f"{s.header}")
    if s.header.p_type == 'PT_LOAD' and s.header.p_flags == 6:
        offset = s.header.p_offset
        print(f"found good place @ {hex(elf.libs[base] + offset)}")
