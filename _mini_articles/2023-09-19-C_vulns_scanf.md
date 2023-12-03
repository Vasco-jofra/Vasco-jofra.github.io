---
title: "C vulnerabilities #1: scanf"
tags: ["mini", "C", "C_vulns"]
draft: true
---

In this series of posts about vulnerabilities in C code, we're looking at all the common ways specific functions from the C standard library can be misused to cause bugs. 

In this first post, we'll look at the `scanf` family of functions--functions with which programs read user input into buffers based on the `format` argument. This family of functions includes:
 - `int scanf(const char *format, ...);`: Reads input from `stdin`
 - `int fscanf(FILE *stream, const char *format, ...);`: Reads input from the given `stream` pointer
 - `int sscanf(const char *str, const char *format, ...);`: Reads input from the given `str` string

<!-- TL;DR:
 - Maybe use `%s` with `sscanf` by properly ensuring that the output argument has a larger size than `str`.
 - Never use `%s` with `scanf` or `fscanf`
 - Using `%<width>s` with a buffer that is `XX` size long (or larger). This writes a `\x00` out of bounds.  -->
<!-- TODO: Improve above -->
<!-- TODO: Enforce that `%[WIDTH]s` is consistent -->
<!-- TODO: Check the figure numbers -->

## 1. Using the %s format

### 1.1 %s with sscanf

**Using `%s` with `sscanf` can be ok** if you validate that the length of the input `str` argument is smaller than the length of each output buffer. The Linux kernel does this correctly in several locations, such as in the following figure.

```c
data = memdup_user_nul(buf, count);
if (IS_ERR(data))
    return PTR_ERR(data);

smack = kzalloc(count + 1, GFP_KERNEL);
if (smack == NULL) {
    rc = -ENOMEM;
    goto free_data_out;
}

i = sscanf(data, "%x:%x:%x:%x:%x:%x:%x:%x/%u %s",
        &scanned[0], &scanned[1], &scanned[2], &scanned[3],
        &scanned[4], &scanned[5], &scanned[6], &scanned[7],
        &mask, smack);
```
<p class="figure-caption">Figure 3: Example of a correct use of sscanf with the %s format. The data buffer (the input string) has a maximum size of count, and the smack buffer has a count+1 size; so, the call to sscanf cannot overflow the smack buffer (<a href="https://github.com/torvalds/linux/blob/42dc814987c1feb6410904e58cfd4c36c4146150/security/smack/smackfs.c#L1447-L1460">linux/security/smack/smackfs.c#L1447-L1460</a>)</p>


### 1.2 %s with scanf or fscanf

**You should never use the `%s` format with `scanf` or `fscanf`.** 

With `scanf` the input comes from `stdin`, so `%s` will read an arbitrary user-controlled amount of bytes to the target buffer. 

With `fscanf`, the input comes from a file, so assuming the file contents are user-controlled, `%s` will again read an arbitrary amount of bytes and overwrite our buffer.

We find both of these issues in the Linux kernel. This code belongs to tools and tests, making them less interesting and likely unexploitable.
```c
if (fscanf(namefp, "%s", thisname) != 1) {
    ret = errno ? -errno : -ENODATA;
    goto error_close_dir;
}
```
<p class="figure-caption">Figure 1: Example of a misuse of fscanf in the Linux kernel (<a href="https://github.com/torvalds/linux/blob/42dc814987c1feb6410904e58cfd4c36c4146150/tools/iio/iio_utils.c#L621-L624">linux/tools/iio/iio_utils.c#L621-L624</a>)</p>

```c
rc = scanf("%s %s %s", insn.opcode, insn.name, insn.format);
```
<p class="figure-caption">Figure 2: Example of a misuse of scanf in the Linux kernel (<a href="https://github.com/torvalds/linux/blob/42dc814987c1feb6410904e58cfd4c36c4146150/arch/s390/tools/gen_opcode_table.c#L158">linux/arch/s390/tools/gen_opcode_table.c#L158</a>)</p>


#### What should you do instead?

Instead of using the `%s` format, use `%[WIDTH]s` to limit the amount of characters read from the stream to `WIDTH`. This prevents the buffer overflow.
```c
char buf[64];
scanf("%32s", buf);
```
<p class="figure-caption">Figure 3: Example of how to use %[WIDTH]s</p>


But the length is not known at compile time, what can I do?

If the length is dynamic (e.g., based on a config file) you can't use the `%[WIDTH]s` format, but you can read the maximum amount of bytes with `fgets` and then `sscanf` the resulting buffer with `%s`. Since you know the maximum size of buffer read with `fgets`, you just need to allocate the `sscanf`'s output buffers using that size.
```c
```
<p class="figure-caption">Figure X: Example of how to use fgets and sscanf to read input safely into dynamically sized arrays</p>
<!-- TODO (maybe): see the kernel example -->


## 2. Off by one with the %XXs format 

Let's explore the boundaries of `%[WIDTH]s`. Is the buffer always null terminated? Is passing the size of the array (e.g., `%64s` for a `buf[64]`) safe?

Let's test it with the following example:

```C
void scanf_off_by_one() {
  // Declare the buffers
  char buf_before[8] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', '\0'};
  char        buf[8] = {0}
  char  buf_after[8] = {'B', 'B', 'B', 'B', 'B', 'B', 'B', '\0'};

  // Read into buf
  int ret = scanf("Enter your input: %8s", buf);

  // Print the variable's values
  printf("%s\n", buf_before); 
  printf("%s\n", buf);        
  printf("%s\n", buf_after);  
}
```
```
> ./off_by_one_test
Enter a string: XXXXXXXX
AAAAAAA
XXXXXXXX

```

The last `printf` call of `buf_after` does not print anything... Providing the maximum 8 characters to `scanf`, caused the first byte of `buf_after` to be overwritten with the terminating null single byte. The `WIDTH` in `%[WIDTH]s` can have at most `size-1` bytes.

## 3. User-controlled format string
If the format argument is user-controlled, we have a classic format string vulnerability.

---

## Testing methodology
I used the following `ripgrep` commands to look for possible vulnerable uses of `scanf`, `fscanf`, and `sscanf`:
 - Find instances of `scanf` using `%s`: `rg "\sscanf\(.*%s"`
 - Find instances of `fcanf` using `%s`: `rg "\sfcanf\(.*%s"`
 - Find instances of `sscanf` using `%s`: `rg "\ssscanf\(.*%s"`
 
Repositories searched:
 - torvalds/linux
 - Genymobile/scrcpy
 - redis/redis
 - obsproject/obs-studio
 - git/git
 - FFmpeg/FFmpeg
 - php/php-src
 - curl/curl
 - tmux/tmux
 - jqlang/jq
 - openssl/openssl
 - nginx/nginx
 - radareorg/radare2
 - postgres/postgres
 - systemd/systemd
 - videolan/vlc
 - jedisct1/libsodium
 - id-Software/DOOM
 - audacity/audacity

There are several instances of problematic code, but from my superficial analysis, only in tests and tools where there is no impact.

For more accurate analysis we should use a tool such as CodeQL.

## Extra curiosity
The kernel uses `sscanf` to "remove white space" from a buffer. 

Is this safe? Could the compiler have weird optimization that would make this UB? https://stackoverflow.com/questions/10170478/c-can-sscanf-read-from-the-same-string-its-writing-to
```C
	char *kbuf;

	kbuf = user_input_str(buf, count, ppos);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	/* Remove white space */
	if (sscanf(kbuf, "%s", kbuf) != 1) {
		kfree(kbuf);
		return -EINVAL;
	}
```
https://github.com/torvalds/linux/blob/42dc814987c1feb6410904e58cfd4c36c4146150/mm/damon/dbgfs.c#L1017-L1025

<!-- TODO: Test how this works better. Does `kbuf` really lose the spaces. Is this even safe -->



## TODO: this is possibly a bug
```c
length = -ENOMEM;
con = kzalloc(size + 1, GFP_KERNEL);
if (!con)
    goto out;

length = -ENOMEM;
user = kzalloc(size + 1, GFP_KERNEL);
if (!user)
    goto out;

length = -EINVAL;
if (sscanf(buf, "%s %s", con, user) != 2)
    goto out;
```
<p class="figure-caption">Figure 3: Example of a correct use of sscanf with the %s format. The size variable is the buf's maximum size (<a href="https://github.com/torvalds/linux/blob/42dc814987c1feb6410904e58cfd4c36c4146150/security/selinux/selinuxfs.c#L1087-L1099">linux/security/selinux/selinuxfs.c#L1087-L1099</a>)</p>