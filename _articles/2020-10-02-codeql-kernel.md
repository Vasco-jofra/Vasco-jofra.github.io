---
title: "Using CodeQL to help with linux kernel exploitation"
tags: ["CodeQL", "UAF"]
---

In this article I will describe how I used CodeQL to look for kernel structures that are kmalloc'ed and contain function pointers to help exploiting a use-after-free in the linux kernel.

## The problem
When solving a linux kernel exploitation challenge, I had the need to look for kernel structures that had function pointers (that I could overwrite to get code execution).

The challenge is quite simple and supports these 4 operations:
 1. **allocate** a chunk with `kmalloc` of a given size passed by the user
 2. **free** the chunk
 3. **read** the chunk (`copy_to_user`)
 4. **write** the chunk (`copy_from_user`)

The bug is on the `free` function that does not set the freed pointer to NULL, and so we can write on the chunk after it was freed.

In this article I won't go into detail about the exploitation of this bug, but rather on how I looked for structures with function pointers that I could overwrite and get code execution.

## CodeQL
I thought instead of searching for these structures by manually analyzing the kernel source or by reading other blog posts and seeing what is commonly used, it would be a great way to learn how to use CodeQL.

[CodeQL](https://securitylab.github.com/tools/codeql) is a code analysis platform that allows you to query source code, based on a declarative query language called QL. It is commonly used to model vulnerabilities, but here I will use it to help with exploitation.

For this challenge we are looking for two things:
 1. structures that are allocated using kmalloc
 2. structures that contain function pointers

We are aiming for a final query that will look something like this:
```ql
from StructAllocatedByKmalloc s_kmalloc, StructWithFunctionPtr s_fptrs
where s_kmalloc = s_fptrs
select s_fptrs
```

We get all the structures that are allocated by kmalloc, we get all the structures that contain function pointers and select the ones that satisfy both conditions. We just need to implement the classes `StructAllocatedByKmalloc`, and `StructWithFunctionPtr`.

### Some useful utils
Just some utils that will be helpful later, you can skip it for now and come back later when needed.

Removes a level of indirection. E.g. `char*`->`char` or `char**`->`char*`
```ql
Type deref(Type t) { result = t.(DerivedType).getBaseType() }
```

Removes all indirection levels. E.g. `char*`->`char` or `char*****`->`char`
```ql
Type max_deref(Type t) {
  t.getPointerIndirectionLevel() = 0 and result = t
  or
  t.getPointerIndirectionLevel() > 0 and result = max_deref(deref(t))
}
```

### 1. Structures that are allocated using kmalloc
To start with we don't just want kmalloc, but all the family of functions.
```ql
class KmallocFunction extends Function {
  KmallocFunction() { this.getName().regexpMatch("k[^_]*alloc") }
}
```

If we run `from KmallocFunction kf select kf` we get: `krealloc`, `kvcalloc`, `kvmalloc`, `kvzalloc`, `kzalloc`, `kcalloc`, `kmalloc`, `krealloc`. That looks good.


Now we get all places where these functions are called:
```ql
class KmallocFunctionCall extends FunctionCall {
  KmallocFunctionCall() { this.getTarget() instanceof KmallocFunction }
}
```

And finally we look for all the structures that are allocated with it.
```
class StructAllocatedByKmalloc extends Struct {
  KmallocFunctionCall kfc;

  StructAllocatedByKmalloc() { this = max_deref(kfc.getFullyConverted().getType()) }
}
```
This one is a bit harder to understand if you are not used to the QL syntax. Here we are saying that there is a `KmallocFunctionCall kfc` such that the function call resulting type, after implicit and explicit cast (`kfc.getFullyConverted().getType()`), and after removing the indirection levels (`max_deref`), is `this` structure. It's probably easier to understand with an example. Lets say you had this cpp code:
```cpp
struct intel_digital_port *dig_port;
dig_port = kzalloc(sizeof(*dig_port), GFP_KERNEL);
```
`kfc` is the `kzalloc` function call and the fully converted type is `struct intel_digital_port *`. After the `max_deref` call we get `struct intel_digital_port`, and this is our `StructAllocatedByKmalloc`.

Running the query `from StructAllocatedByKmalloc a select a` we get 1334 different structures allocated by kmalloc.

### 2. Structures that contain function pointers
Here we need to look for structures that:
 1. have function pointers
 2. have other structures (not pointers to structs, only structs) that have function pointers

Example 1:
```cpp
struct A {
	void (*operation) (int);
};
```

Example 2:
```cpp
struct B {
    int counter;
    struct A; // struct A* would not be what we are looking for
};
```

This is the query I wrote to find it:
```ql
class StructWithFunctionPtr extends Struct {
  StructWithFunctionPtr() {
    exists(FunctionPointerType fptype | this.getAField().getType() = fptype) or
    this.getAField().getType() instanceof StructWithFunctionPtr
  }
}
```
The first part checks if there exists a struct field such that its type is a `FunctionPointerType` and the second part whether there is a field which is a `StructWithFunctionPtr`. Good old recursion.

Running `from StructWithFunctionPtr a select a` yields 1769 different results.

### Putting it all together
Finally, with these classes implemented, we can run our initial simple query.

```ql
from StructAllocatedByKmalloc s_kmalloc, StructWithFunctionPtr s_fptrs
where s_kmalloc = s_fptrs
select s_fptrs
```

| #   | s_fptrs          |
| --- | ---------------- |
| 1   | file             |
| 2   | file_operations  |
| 3   | uprobe_task      |
| 4   | css_set          |
| 5   | ctl_table_header |
| 6   | page             |
| 7   | device           |
| 8   | super_block      |
| 9   | kobj_attribute   |
| 10  | attribute_group  |
| ... | ...              |

We get 417 results.. nice! To help narrow down our search lets make our query slightly more complex and print the amount of fptrs the struct has (more pointer to overwrite can only be a good thing) and the places where the allocation is made (so we can look through the source and choose one).

NOTE: Some of this code (e.g. `countFieldsOfFunctionPtrs`) was not mention above but can be seen in the end of post.
```ql
from StructAllocatedByKmalloc s_kmalloc,
     StructWithFunctionPtr s_fptrs
where s_kmalloc = s_fptrs
select
  s_fptrs.countFieldsOfFunctionPtrs() as amount_of_fptrs,
  s_fptrs,
  s_kmalloc.getAFunctionCall() as call_site,
  count(s_kmalloc.getAFunctionCall()) as kmalloc_times
order by amount_of_fptrs desc
```

This way we get more results (538) since we are also printing all the call site locations (clickable in the results) of the allocation and some structures are allocated in multiple places.

| #   | amount_of_fptrs | s_fptrs            | call_site       | kmalloc_times |
| --- | --------------- | ------------------ | --------------- | ------------- |
| 1   | 39              | intel_digital_port | call to kzalloc | 3             |
| 2   | 39              | intel_digital_port | call to kzalloc | 3             |
| 3   | 39              | intel_digital_port | call to kzalloc | 3             |
| 4   | 30              | file_operations    | call to kzalloc | 1             |
| 5   | 27              | virtual_engine     | call to kzalloc | 1             |
| 6   | 25              | intel_engine_cs    | call to kzalloc | 1             |
| 7   | 25              | clk_composite      | call to kzalloc | 1             |
| 8   | 24              | rapl_pmus          | call to kzalloc | 1             |
| 9   | 24              | perf_amd_iommu     | call to kzalloc | 1             |
| 10  | 24              | rapl_pmus          | call to kzalloc | 1             |
| ... | ...             | ...                | ...             | ...           |

I'll leave it to you to choose the one you want. There at least 2 that work, but probably many other work as well. ;)


## Improving it further
If we wanted to improve it further we could see if there is a path (and its call stack depth) from a syscall (our interface with the kernel) to a call to one of these function pointers. This way we could be sure the function pointer is called in a specific syscall and we can sort by call stack depth to look for the best ones.

## Conclusion
CodeQL is pretty cool and can be used to find bugs by modelling vulnerability classes but also to help in some exploitation scenarios. Here we looked for structures with function pointers, but we could have also looked for structures of a certain size if that was a restriction and probably many other things I can't think of right now.

## Full code
```ql
import cpp

// Removes a level of indirection. E.g. `char*`->`char` or `char**`->`char*`
Type deref(Type t) { result = t.(DerivedType).getBaseType() }

//Removes all indirection levels. E.g. `char*`->`char` or `char*****`->`char`
Type max_deref(Type t) {
  t.getPointerIndirectionLevel() = 0 and result = t
  or
  t.getPointerIndirectionLevel() > 0 and result = max_deref(deref(t))
}

// ====================
// Kmalloc style functions
class KmallocFunction extends Function {
  KmallocFunction() { this.getName().regexpMatch("k[^_]*alloc") }
}

class KmallocFunctionCall extends FunctionCall {
  KmallocFunctionCall() { this.getTarget() instanceof KmallocFunction }
}

class StructAllocatedByKmalloc extends Struct {
  KmallocFunctionCall kfc;

  StructAllocatedByKmalloc() { this = max_deref(kfc.getFullyConverted().getType()) }

  KmallocFunctionCall getAFunctionCall() { result = kfc }
}

// ====================
// Struct with function pointers, even if these are inside another struct inside it
class StructWithFunctionPtr extends Struct {
  StructWithFunctionPtr() {
    exists(FunctionPointerType fptype | this.getAField().getType() = fptype) or
    this.getAField().getType() instanceof StructWithFunctionPtr
  }

  Field getAFunctionPointerField() {
    result = this.getAField() and
    result.getType() instanceof FunctionPointerType
    or
    this.getAField().getType() instanceof StructWithFunctionPtr and
    result = this.getAField().getType().(StructWithFunctionPtr).getAFunctionPointerField()
  }

  int countFieldsOfFunctionPtrs() { result = count(this.getAFunctionPointerField()) }
}

// ====================
// Final query
from StructAllocatedByKmalloc s_kmalloc,
     StructWithFunctionPtr s_fptrs
where s_kmalloc = s_fptrs
select
  s_fptrs.countFieldsOfFunctionPtrs() as amount_of_fptrs,
  s_fptrs,
  s_kmalloc.getAFunctionCall() as call_site,
  count(s_kmalloc.getAFunctionCall()) as kmalloc_times
order by amount_of_fptrs desc
```