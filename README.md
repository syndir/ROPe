# ROPe
## Return Oriented Payload executor

ROPe is a command line utility which can be used to generate and execute a ROP chain with the goal being the execution of a second-stage shellcode.

ROPe was developed on Kali Linux 2020.1 x64 and requires Python >= 3.6.

ROPe has been designed for use on Linux x64 devices with ASLR disabled, and targets programs which take unchecked user input during runtime (not through a command line argument). This makes it suitable for attacking programs which utilize `read(2)`, `gets(3)`, and `scanf(3)`.

## Files
```shell
.
├── Makefile
├── notvuln.c
├── poc.asm
├── poc.c
├── poc.sh
├── ROPe.py
├── vuln2.c
└── vuln.c
```
- `Makefile`: Makefile which can be used to compile the following programs used for testing ROPe's functionality.
- `notvuln.c`: This program is not vulnerable to buffer overflow / ROP exploits.
- `vuln.c`: This program is vulnerable due to use of `gets()`.
- `vuln2.c`: This program is vulnerable due to the use of `scanf()`.
- `poc.asm`: This file will provide some gadgets ROPe may find suitable for use and is included as a proof-of-concept. This can be compiled into a standalone shared object file, which may be linked against by other ELF files.
- `poc.c` - This file is vulnerable, and links against the `libpoc.so` library created by `poc.asm`.
- `poc.sh` - Script to compile `poc.asm` to a .so file and to compile `poc.c` linked against `libpoc.so`.


## Requirements
ROPe relies on the following programs, libraries, and frameworks:

- Python >= 3.6
- Capstone (for use of instruction/mnemonic decoding of opcodes) (`pip3 install capstone`)
- pwntools (for examining specific segments of an ELF file) (`pip3 install pwn`)
- nasm
- build tools (gcc, make, ld, etc.)

## Setup
Aside from the requirements listed above, ROPe also requires certain operations to be performed.

Most Linux OS's today link `/bin/sh` to `/bin/dash`. However, `/bin/dash` has certain built-in protections that make exploiting processes more difficult. For more reliable results, `/bin/sh` may be linked to `/bin/zsh` (which is really the only shell one should ever use, anyway. Refer to `oh-my-zsh`).

If you are intending to use the PoC library included (compiled as `libpoc.so`), you will need to ensure that this library is in the library search path. After compiling an ELF file linked against this library, you can run `ldd [executable]` to list all libraries which the executable is linked against. In the case that the custom library is not located, you will have to perform one of the following options:

1. set and export `LD_LIBRARY_PATH` to include the directory containing the library, then execute the binary
2. execute the binary files by prepending `LD_LIBRARY_PATH=[directory_containing_library]` to the command line during execution
3. Edit the file `/etc/ld.so.conf.d/local.dconf` (creating it if it does not exist) to contain the full path of the library, then execute (as root) `ldconfig /path/to/libpoc.so`.

Option 3 is the preferred way, offering the most consistent results while enabling persistence. Options 1 and 2 are unreliable.

Note also that ASLR should be disabled. This can be achieved by `echo 0 > /proc/sys/kernel/randomize_va_space` as root.

## Usage
```shell
usage: ROPe.py [-h] [-v] [-t] [-x] [-d] [-p [P]] files [files ...]

Automatically generate and execute a ROP chain suitable for executing a third party payload.

Four possible ROP chains are provided. By default, this tool will attempt to
build and execute each of them in sequence. You may specify a particular target
ROP chain to build by combinging the -p option with one of the following:
            
    Paylods:
        1 - mprotect->read chain using system calls
        2 - mprotect->read chain using libc calls
        3 - mmap->read chain using system calls
        4 - mmap->read chain using libc calls

positional arguments:
  files       list of ELFs to examine (must be in $PATH, or absolute paths)

optional arguments:
  -h, --help  show this help message and exit
  -v          enable verbose output
  -t          display gadgets
  -x          do not attempt to launch process with ROP payload
  -d          do not write generated payloads out as files
  -p [P]      specified which payload to build.
```

- `-v`: enables verbose debugging output. This includes, but is not limited to, gadgets which are disposed of, the locations of gadgets used, and the locations of any leaked addresses from libc.
- `-t`: displays gadgets as they are found and inserted into the gadget map. Output is similar to `ropper`.
- `-x`: Only attempt to build the payload, do not attempt to execute it.
- `-d`: Do not output the generated payloads to files. By default, ROPe exports any payloads it generates to files of the format `[elfname]-[rop_chain_name].ROPe` in raw output. These files may be later examined using a hex editor or similar program, such as `od -t x4 -v file.ROPe`.
- `-p`: Only attempt to build the single specified payload (1-4, as numbered above).

`files` is the only required argument, and at least one target ELF file must be specified.

## Configuration
ROPe provides some variables which may be configured in the ROPe.py script, near the top.

- `MAX_BUFFER_SIZE`: The maximum size of the buffer (in bytes) that is targeted for exploitation. By default, this value is set to 1024 bytes.
- `MAX_GADGET_SIZE`: The maximum size of any gadget (in bytes) we may be interested in. By default, this value is set to 25 bytes. Note that changing this to a higher value will result in much more computationally expensive searching operations.
- `shellcode`: The shellcode to execute as part of the second stage of the exploit. A simple shellcode suitable for calling `exec("/bin/sh")` is supplied by default. Note that it is possible to store multiple potential payloads, changing which one is targeted by updating the `shellcode` variable to point to the desired one.


## Discussion
Upon startup, ROPe will attempt to perform the following steps in sequence for each file supplied as an argument.

#### 1. Locating Gadgets
ROPe will examine each file, considering it and all shared objects it is linked against in order to locate suitable gadgets. If it is noticed that the current object being examined is libc, we note its base address so that it may be used later when generating the ROP chain, if required.

ROPe maintains an internal database of suitable gadgets which it will consider when generating ROP chains. Gadgets are stored in a dictionary in `K=address, V=gadget` pairs. A gadget is considered suitable if it meets the following conditions:

- The instruction set of the gadget must end in `ret`
- The instruction set of the gadget must not include `leave`, `call`, or `j`-type instructions
- The instruction set of the gadget must be less than `MAX_GADGET_LENGTH`
- The address of the gadget must not contain `0x09`, `0x0a`, `0x0b`, `0x0c`, `0x0d`, or `0x20` bytes, since these denote whitespace characters when encoded into a string
- There must not exist a gadget with the same instruction set already in the database

#### 2. Determining Buffer Length
ROPe will then attempt to determine the length of the buffer that can be exploited. This is accomplished by writing n string of ever-increasing length (up to `MAX_BUFFER_LEN`, to avoid infinite loops when a program is not vulnerable) to the input of the file, checking the processes return code to see if it aborted due to a segmentation fault or not. If a segmentation fault is detected, we use the length of the input as the length of padding to prepend to the buffer prior to the actual payload.

#### 3. Generate ROP Chain
ROPe now has the required information necessary to generate any of the preformed ROP chains. ROPe will use the information gathered to pad a buffer with the amount of bytes necessary to position our ROP payload correctly, then it will use the addresses of known gadgets to generate the ROP payload.

#### 4. Execution
Unless otherwise specified, each chain will attempt to be executed as it is constructed. The process will be launched and the ROP payload generated in step 3 will be fed to the program. If the ROP chain has been correctly assembled, the program should now be waiting on a `read(2)` call, to which ROPe will now send the second-stage shellcode as input.

#### 5. Profit?
If the ROP chain was properly generated and the shellcode was successfully executed, you should now be greeted by a shell prompt. Exit the shell by pressing `^D` (Control-D).

## Provided ROP Chains
ROPe will attempt to generate a suitable ROP chain. By default, four are provided:
1. `mprotect->read` (syscall version): This chain first attempts to locate an area of memory suitable for storing the second stage shellcode, then invokes system call `mprotect(2)` to set that page `PROT_READ | PROT_WRITE | PROT_EXECUTE`. After this, the ROP chain invokes a call of `read(2)`, which will then read the shellcode (up to 4096 bytes worth) into this location. Finally, the ROP chain will "return into" the location now containing the read shellcode.
2. `mprotect->read` (libc version): Same as chain 1, except this sets up a call to `mprotect(3)` instead of invoking a system call.
3. `mmap->read` (syscall version): This chain first attempts to allocate a new page of memory for the process by invoking a system call `mmap(2)` with flags `PROT_READ | PROT_WRITE | PROT_EXECUTE`. After this, the ROP chain invokes a call of `read(2)`, which will read the shellcode (up to 4096 bytes worth) into this location. Finally, the ROP chain will "return into" the location now containing the read shellcode.
4. `mmap->read` (libc version): Same as chain 3, except this sets up a call to `mmap(3)` instead of invoking a system call.

## Providing Other ROP Chains
If desired, ROPe can be easily configured to generate other ROP chains. Simply add an appropriate build rule that knows the structure of the desired chain, then create and use any necessary gadget finders to fill in the blanks in the chain.

As an example of payload construction, consider the following segment which generates the `mmap` invocation for chain 3:
```python
    payload  = p64(xor_rax_rax)         # rax = 0
    payload += p64(add_rax_1) * 9       # rax = 9
    payload += p64(pop_rdi)             # 1st arg
    payload += p64(0x0)                 # rdi = 0
    payload += p64(pop_rsi)             # 2nd arg
    payload += p64(0x1000)              # rsi = 4kb (pagesize)
    payload += p64(pop_rdx)             # 3rd arg
    payload += p64(0x7)                 # rdx = 7
    payload += p64(pop_r10)             # 4th arg
    payload += p64(0x21)                # r10 = MAP_SHARED | MAP_ANONYMOUS
    payload += p64(pop_r8)              # 5th arg
    payload += p64(0xffffffffffffffff)  # r8 = -1
    payload += p64(pop_r9)              # 6th arg
    payload += p64(0x0)                 # r9 = 0
    payload += p64(syscall)             # invoke system call 9
```
As shown above, the constant values we are attempting to place into registers are simply placed on the stack in the appropriate place, such that they may be popped off into the correct registers. The variables `xor_rax_rax` or `pop_r10` are the addresses of gadgets suitable for performing those popping tasks, and are located beforehand via `find_xor_rax_rax_ret()` and `find_pop_r10_ret()`.

If more gadget locators are required, they may be freely added and used, following the format:
```python
def find_xor_rax_rax_ret():
    global gadget_map                           # Map of all (addr, gadget) pairs
    for g_addr in gadget_map:                   # For every address in the map
        md = Cs(CS_ARCH_X86, CS_MODE_64)        # Set up Capstone
        md.detail = False
        g = gadget_map[g_addr]                  # Get the gadget associated with the address
        instr_list = list(md.disasm(g, g_addr)) # Disassemble the gadget into instructions 
                                                # and make them into a list

        # This is the important part, where we examine the instructions list to see if it's
        # suitable for what we're looking for. This particular function looks for gadgets
        # that are 2 instructions long, with the first instruction being `xor rax, rax` and
        # the second being `ret`. If it's a match, return it. Otherwise, we'll end up
        # returning `None` after the list is exhausted.
        if len(instr_list) == 2:
            if instr_list[0].mnemonic == "xor" and instr_list[0].op_str == "rax, rax" \
                    and instr_list[1].mnemonic == "ret":
                return g_addr
    return None
```

## Demo Videos
The following demonstration videos are provided for your consideration as proof of concept:
- [Kali 2020.1 x64](https://drive.google.com/open?id=1f83kGEU9Lv0nta4QH3GzI_HIXXCGLrfH) (VirtualBox OVA available [here](https://images.offensive-security.com/virtual-images/kali-linux-2020.1-vbox-amd64.ova))
- [Ubuntu 18 x64](https://drive.google.com/open?id=1IHybLSQm7FpWms8cPQQETuXbincRpszx) (Image available [here](https://releases.ubuntu.com/18.04.4/ubuntu-18.04.4-desktop-amd64.iso))
- [Ubuntu 20 x64](https://drive.google.com/open?id=158PW58v5_X7-vZmx07IpyrmoZyG3-wqO) (Image available [here](https://ubuntu.osuosl.org/releases/20.04/ubuntu-20.04-desktop-amd64.iso))

Strangely, if I adjust the value determined to be the length of the padding necessary to cause the overflow by 1, ROPe also has varying degrees of success on Debian and Arch, as evidenced below:

![Arch PoC](https://i5.imageban.ru/out/2020/05/09/a362b20a42686a0e5edcae880edb91c7.png)

## Extending ROPe
If ROPe were to be developed further, the following potential options could be considered:
- Overcoming protections (ASLR, canaries): Needs a way to leak values, especially for overcoming canaries. If there were a reliable way to ensure that whatever input is fed into the target program would be `printf(3)`'d back, format string bugs could potentially be used to leak the values up the stack. However, this is not guaranteed and, as such, has been left out in favor of creating a more generic tool.
- More/varied potential ROP chains: Currently ROPe focuses on 4 very linear chains, using very specific gadgets. If these specific gadgets are not able to located, the ROP chain generator may fail, even though a similar gadget which performs the same functionality may exist (eg, `inc rax; ret;` does not exist within the address space, but `add rax, 1; ret;` does)

## References
- "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Direct Function Calls (on the x86)" (Sacham, 2007)
- "Hacking: The Art of Exploitation (2nd edition)" (Erickson, 2008)
- "The Shellcoder's Handbook (2nd edition)" (Anley, Heasman, Lindner, and Richarte, 2007)
- [Capstone](https://www.capstone-engine.org/)
- [pwntools](https://python3-pwntools.readthedocs.io/en/latest/) 
- [nasm](https://www.nasm.us/doc/)
- [gef](https://gef.readthedocs.io/en/master/)
