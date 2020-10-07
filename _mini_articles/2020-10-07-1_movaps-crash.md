---
title: "#1 movaps crash"
published: true
tags: ["mini", "ROP"]
---

When developing a ROP exploit I kept on crashing on a `movaps xmmword ptr [rsp], xmm0` instruction.

![](/assets/img/2020-10-07-1_movaps_crash.png)

After some investigating I found this was happening because the `movaps` (Move Aligned Packed Single-Precision Floating-Point Values) memory operands must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated. In the example above, the stack is not 16 byte aligned hence the crash.

The easiest way to fix our exploit is adding a `ret` gadget to our ROP chain which will act as a NOP, but increment the stack by 8, aligning it.


`movups` is the unalligned version, meaning it does not have to be aligned. Having said that sometimes just being unaligned is won't make an exploit crash, but the call to system will fail. Let's try to find why.

vector like operations (`movaps` for example) have to be 16 byte aligned or they will crash)

https://stackoverflow.com/questions/61196175/movaps-vs-movups-in-gcc-how-does-it-decide
