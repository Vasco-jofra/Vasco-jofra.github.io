---
tags: ["tool", "binary ninja", "fmt string"]
---

*Format string finder* uses **binary ninja**'s powerful IL's to find **format string vulnerabilities** in binaries (without access to source code) and ***printf-like functions***.
It was featured in [*Paged Out!'s*](https://pagedout.institute/) issue #1 winning **Best Security/RE article** leading to it being presented in São Paulo, Brasil at [*Hackers to Hackers Conference 2019*](https://www.h2hc.com.br/h2hc/en/).

You can find it here: [https://github.com/Vasco-jofra/format-string-finder-binja](https://github.com/Vasco-jofra/format-string-finder-binja) or install it from Binary Ninja's plugin manager.

## Example
![](/assets/img/tool-format-string-finder-example.gif)

## TLDR
 1. Loads [known functions](https://raw.githubusercontent.com/Vasco-jofra/format-string-finder-binja/master/src/data/default_printf_like_functions.data) that receive a format parameter.
 2. For each xref of these functions find where the fmt parameter comes from:
    1. If it comes from an **argument** we mark it as a **printf-like function** and test its xrefs
    2. If it is a **constant** value located in a **read-only** area we mark it as **safe**
    3. If it comes from a known **'safe' function call result** (functions from the `dgettext` family) we mark it as **safe**
    4. Otherwise we mark it as **vulnerable**
 3. Prints a markdown report


Find out more in Paged Out!'s issue #1 at [https://pagedout.institute/?page=issues.php](https://pagedout.institute/?page=issues.php).