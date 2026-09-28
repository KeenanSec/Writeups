# Assembly Crash Course - pwn.college Notes & Writeup

**Category:** Binary Exploitation / Reverse Engineering  
**Platform:** [pwn.college](https://pwn.college/) (Architecture & Assembly Modules)  
**Architecture:** x86_64 (AMD64 / Intel 64)  
**Tools:** GDB, GCC, NASM, objdump  

---

## Overview & Fundamentals

Modern x86_64 central processing units (CPUs) and 64-bit operating systems use a **48-bit canonical virtual address space**, allowing a single user-space process to theoretically reference up to **128 TB** of virtual memory, completely independent of the physical RAM installed.

When writing or analyzing assembly, interaction with computer memory revolves around three core locations:
1. **The CPU Register File:** The fastest storage directly on the chip.
2. **The Stack:** A dynamically managed Last-In, First-Out (LIFO) memory region.
3. **The Heap & Global Data:** Dynamically allocated memory and static buffers.

---

## 1. The Stack & Stack Frame Architecture

The stack is a dedicated, contiguous segment of virtual memory that automatically manages function calls, local variables, and return pointers.

```text
High Memory Addresses (e.g., 0x7fffffffe000)
    ┌──────────────────────────┐
    │     Previous Frame       │
    ├──────────────────────────┤
    │  Return Address (Saved)  │
    ├──────────────────────────┤
    │ Saved Base Pointer (RBP) │ <--- RBP (Stack Frame Base)
    ├──────────────────────────┤
    │ Local Variables & Temp   │
    │         ...              │
    ├──────────────────────────┤
    │ Active Top of the Stack  │ <--- RSP (Stack Pointer)
    └──────────────────────────┘
Low Memory Addresses  (Memory grows downwards ▼)
```

### Key Principles of the x86_64 Stack:
- **Growth Direction:** The stack grows **downwards** towards lower memory addresses.
- **Pushing (`push`):**
  - Decrements the stack pointer (`rsp`): `sub rsp, 8`
  - Stores the specified register or immediate value at `[rsp]`.
- **Popping (`pop`):**
  - Retrieves the value currently located at `[rsp]` into the destination register.
  - Increments the stack pointer (`rsp`): `add rsp, 8`.

```assembly
push rax        ; rsp decrements by 8; contents of rax written to memory at [rsp]
pop rbx         ; rbx receives value at [rsp]; rsp increments by 8
```

---

## 2. Memory Dereferencing & Pointer Operations

In assembly, square brackets `[...]` represent **dereferencing**—using the value held within a register as a target memory address to read or write data.

### Reading from Memory:
```assembly
mov rbx, [rax]  ; Reads the 64-bit quadword from the address in rax into rbx
```

### Writing to Memory:
If we want to store the value `42` at memory address `0x12345`:
```assembly
mov rax, 0x12345
mov qword ptr [rax], 42     ; Explicitly writes a 64-bit quadword (42) to 0x12345
```
This is conceptually equivalent to:
```c
uint64_t *rax = (uint64_t *)0x12345;
*rax = 42;
```

---

## 3. Controlling Write Sizes & Immediate Values

When moving data between registers of different sizes, or writing literal numbers (immediates) to memory addresses, you must specify the **size directive** so the assembler knows how many bytes to write.

| Directive | Size (Bits / Bytes) | Matching Register Slice |
| :--- | :--- | :--- |
| `BYTE PTR` | 8 bits (1 byte) | `al`, `bl`, `cl`, `dl`, `r8b` |
| `WORD PTR` | 16 bits (2 bytes) | `ax`, `bx`, `cx`, `dx`, `r8w` |
| `DWORD PTR` | 32 bits (4 bytes) | `eax`, `ebx`, `ecx`, `edx`, `r8d` |
| `QWORD PTR` | 64 bits (8 bytes) | `rax`, `rbx`, `rcx`, `rdx`, `r8` |

### Writing Register Slices to Memory:
To write only the lower 32 bits of `rbx` (`ebx`) to memory:
```assembly
mov rax, 0x133337
mov [rax], ebx               ; Writes 4 bytes (32 bits) from ebx into 0x133337
```

### Writing Immediate Values:
When writing constants to memory directly, you **must** specify the size directive:
```assembly
mov rax, 0x133337
mov DWORD PTR [rax], 0x1337  ; Writes 32-bit 0x00001337 to address 0x133337
```

![Immediate Value Write Specification](Pasted%20image%2020260925154855.png)

---

## 4. Endianness (Little-Endian Architecture)

x86_64 processors are **Little-Endian**. When multi-byte numerical values are stored in RAM, the **Least Significant Byte (LSB)** is stored at the lowest memory address, and the **Most Significant Byte (MSB)** is stored at the highest memory address.

### Example: Storing `0xc001ca75` at `0x1000`:
```text
Value: 0x C0  01  CA  75
          MSB         LSB

Memory Layout:
Address:    [0x1000]   [0x1001]   [0x1002]   [0x1003]
Byte:        0x75       0xCA       0x01       0xC0
            (LSB)                             (MSB)
```

---

## 5. x86_64 Register Map & Calling Conventions

The 16 general-purpose registers each serve distinct conventions under the **System V AMD64 ABI** (standard on Linux) and the **Microsoft x64 ABI** (standard on Windows):

| Register | Primary Role / Purpose | Volatility (Linux System V) | Calling Convention Role (Linux) | Calling Convention Role (Windows) |
| :--- | :--- | :--- | :--- | :--- |
| **`rax`** | Accumulator / Return Value | **Volatile (Caller-Saved)** | Function Return Value | Function Return Value |
| **`rbx`** | Base Register / General Storage | **Non-Volatile (Callee-Saved)** | Preserved across calls | Preserved across calls |
| **`rcx`** | Counter / 4th Arg (Linux) | **Volatile (Caller-Saved)** | 4th Function Argument | 1st Function Argument |
| **`rdx`** | Data / 3rd Arg (Linux) | **Volatile (Caller-Saved)** | 3rd Function Argument | 2nd Function Argument |
| **`rsi`** | Source Index / 2nd Arg (Linux) | **Volatile (Caller-Saved)** | 2nd Function Argument | Non-Volatile (Callee-Saved) |
| **`rdi`** | Destination Index / 1st Arg (Linux) | **Volatile (Caller-Saved)** | 1st Function Argument | Non-Volatile (Callee-Saved) |
| **`rbp`** | Base Pointer (Stack Frame Anchor) | **Non-Volatile (Callee-Saved)** | Frame Pointer | Frame Pointer |
| **`rsp`** | Stack Pointer | *System Managed* | Active Stack Top | Active Stack Top |
| **`r8`** | General-Purpose / 5th Arg | **Volatile (Caller-Saved)** | 5th Function Argument | 3rd Function Argument |
| **`r9`** | General-Purpose / 6th Arg | **Volatile (Caller-Saved)** | 6th Function Argument | 4th Function Argument |
| **`r10`** | Temporary Scratch / Syscall | **Volatile (Caller-Saved)** | Static Chain Pointer / Syscall | Scratch Register |
| **`r11`** | Temporary Scratch / Flags | **Volatile (Caller-Saved)** | Temporary / Flags in Syscall | Scratch Register |
| **`r12`–`r15`** | Safe-Keeping Registers | **Non-Volatile (Callee-Saved)** | Preserved across calls | Preserved across calls |
| **`rip`** | Instruction Pointer | *System Managed* | Points to next instruction | Points to next instruction |

> [!NOTE]
> - **Caller-Saved (Volatile):** If a function wants to keep a value across another function call (`call foo`), it must save it to the stack itself before calling.
> - **Callee-Saved (Non-Volatile):** A called function promises to restore the original value (`push` at start, `pop` before return) if it modifies these registers.

---

## 6. The Load-Modify-Store Paradigm

CPUs cannot perform arithmetic directly across two distinct RAM locations. Memory modifications follow the 3-step paradigm:
1. **Load:** Read data from memory into a register (`mov rax, [addr]`).
2. **Modify / Compute:** Execute arithmetic or logical instructions in registers (`add rax, 5`, `xor rax, rbx`).
3. **Store:** Write the computed result back out to target memory (`mov [addr], rax`).

---

## 7. Load Effective Address (`lea`) vs `mov`

The `lea` instruction calculates an address using CPU addressing modes (`[base + index*scale + displacement]`) and stores the **resulting address**, without reading or dereferencing memory.

```assembly
; Arithmetic without RAM access:
lea rax, [rbx + 8]          ; rax = rbx + 8 (Does not access memory)
mov rax, [rbx + 8]          ; rax = value stored at memory location (rbx + 8)

; Fast arithmetic tricks:
lea edx, [eax + eax*4]      ; edx = eax * 5
lea eax, [rax + rbx*2 + 10] ; 3-way calculation in a single CPU cycle
```

---

## 8. RIP-Relative Addressing

Modern binaries are compiled with **Position Independent Executable (PIE)** support, meaning the code can be loaded at any randomized base address in memory (ASLR).

To reference strings, data buffers, or functions regardless of load address, assembly uses **RIP-Relative Addressing**:

```assembly
; Reading the current instruction address:
lea rax, [rip]              ; Loads address of the next instruction into rax

; Referencing local data relative to current RIP:
lea rdi, [rip + 0x2048]     ; Resolves target address relative to current instruction
```
This guarantees that as long as the relative distance between code and data remains constant, the binary executes correctly no matter where the loader places it in virtual memory.
