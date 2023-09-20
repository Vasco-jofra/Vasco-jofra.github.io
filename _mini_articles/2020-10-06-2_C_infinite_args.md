---
title: "C: infinite args"
tags: ["mini", "programming", "C"]
---

In C, functions that receive no arguments can receive an arbitrary amount of arguments. :O

```c
#include <stdio.h>

void func_1() {
    printf("func_1\n");
}

int main() {
    func_1();
    func_1(1);
    func_1(1, 2, 3);
    return 0;
}
```


I always wondered why I sometimes saw the `void` in `int func(void)`. Turns out `int func()` and `int func(void)` are not quite the same.