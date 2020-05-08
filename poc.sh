#!/bin/sh
nasm -felf64 poc.asm
gcc poc.o -shared -o libpoc.so

gcc -Wl,--no-as-needed -g -fno-stack-protector poc.c -o poc -L. -lpoc

sudo chown root:root poc
sudo chmod +s poc

