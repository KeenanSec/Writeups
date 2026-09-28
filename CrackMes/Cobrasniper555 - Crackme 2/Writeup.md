# Cobrasniper555's Crackme #2 - Reverse Engineering Writeup

**Category:** Reverse Engineering / Software Cracking / Keygening  
**Platform:** [Crackmes.one](https://crackmes.one/) (originally Crackmes.de)  
**Author:** `Cobra` (reversed by `Nuno_1`)  
**Difficulty:** 2 / 10  
**Tools:** x64dbg / OllyDbg / IDA Pro, GCC / G++ (C++ Keygen), Windows Registry  

---

## Executive Summary

**Cobrasniper555's Crackme #2** is a 32-bit Windows PE binary programmed in C++. Upon execution, the application enforces a trial lock mechanism that blocks the user from accessing the registration menu. Reverse engineering the executable reveals two distinct protection mechanisms:
1. **Trial License Validation:** The binary queries the Windows Registry for an existing installation key. Without this key, registration is disabled.
2. **Name-to-Serial Algorithm:** Once unlocked, the registration dialog generates a cryptographic validation serial based on two directional passes over the entered username, comparing the output with `strcmp`.

By auditing the disassembly, we create a `.reg` bypass for Stage 1 and implement a C++ keygen that computes valid serials for any arbitrary username.

---

## Stage 1: Bypassing the Trial Nag Screen

When the application is launched without prior configuration, a message box appears warning that the software is running in a trial state, disabling access to registration features.

Setting a breakpoint on the Windows API `RegOpenKeyA` reveals the validation logic:

```assembly
00401290  /$ 55             PUSH EBP
00401291  |. 89E5           MOV EBP,ESP
00401293  |. 83EC 18        SUB ESP,18
00401296  |. 8D45 FC        LEA EAX,DWORD PTR SS:[EBP-4]
00401299  |. 894424 08      MOV DWORD PTR SS:[ESP+8],EAX
0040129D  |. C74424 04 0040>MOV DWORD PTR SS:[ESP+4],Test.00404000   ; ASCII "Software\Cobra"
004012A5  |. C70424 0100008>MOV DWORD PTR SS:[ESP],80000001          ; HKEY_CURRENT_USER (0x80000001)
004012AC  |. E8 FF0E0000    CALL <JMP.&ADVAPI32.RegOpenKeyA>         ; \RegOpenKeyA
004012B1  |. 83EC 0C        SUB ESP,0C
004012B4  |. C9             LEAVE
004012B5  \. C3             RETN
```

### Solution:
The binary queries `HKEY_CURRENT_USER\Software\Cobra`. If this registry key exists, the trial check succeeds. We can create it instantly via command line or `.reg` file:

```cmd
reg add "HKCU\Software\Cobra" /f
```

*(See [src/cobra.reg](src/cobra.reg) for the registry script).*

---

## Stage 2: Registration Routine & Serial Verification

With the trial check satisfied, the **Register** menu item becomes active. Entering a username and test serial and clicking OK triggers the dialog handler:

```assembly
004016E8  |. E8 D3090000    CALL <JMP.&USER32.GetDlgItemTextA>       ; Fetch Username
0040170D  |. E8 AE090000    CALL <JMP.&USER32.GetDlgItemTextA>       ; Fetch Serial entered
0040171F  |. 8D45 D8        LEA EAX,DWORD PTR SS:[EBP-28]            ; Ptr to Username
00401725  |. E8 D2FBFFFF    CALL Test.004012FC                       ; Generate Valid Serial
0040173A  |. E8 81080000    CALL <JMP.&msvcrt.strcmp>                ; Compare Entered vs Valid
0040173F  |. 85C0           TEST EAX,EAX                             ; Match check
00401741  |. 75 2D          JNZ SHORT Test.00401770                  ; Jump to error if mismatch
0040174B  |. C74424 08 2B40>MOV DWORD PTR SS:[ESP+8],Test.0040402B   ; "Alert"
00401753  |. C74424 04 3140>MOV DWORD PTR SS:[ESP+4],Test.00404031   ; "You are now registered!"
00401761  |. E8 6A090000    CALL <JMP.&USER32.MessageBoxA>
```

The validation does not use inline checks—it calculates the full expected serial at `0x004012FC` and performs a standard string comparison using `strcmp`.

---

## Stage 3: Reverse-Engineering the Keygen Algorithm

Diving into function `0x004012FC`, the algorithm is structured into three phases:

### Phase 1: Forward Accumulation Loop
1. Iterates from index `0` up to `strlen(name) - 1`.
2. For each character:
   - If it is the first character (`i == 0`), add `5`.
   - Otherwise, add the previous character `name[i - 1]`.
3. XOR the character with `0x12C`.
4. Perform bit shifting:
   $$\text{val} = ((\text{val} \ll 2) + \text{val}) \ll 2$$
5. Arithmetic shift right by 2 (`SAR 2`) and bitwise AND with `0xF0F0F0F0`:
   $$\text{sum} = (\text{val} \gg 2) \ \& \ \text{0xF0F0F0F0}$$

### Phase 2: Backward Accumulation Loop
1. Iterates backward from index `strlen(name)` down to `1`.
2. For each character:
   - If `i == strlen(name)`, add `5`.
   - Otherwise, add the next character `name[i + 1]`.
3. Performs the exact same transformation (`XOR 0x12C`, shift multiply, `SAR 2`, and `& 0xF0F0F0F0`), producing `sum2`.

### Phase 3: Final Key Assembly
The application formats the two resulting 32-bit hex values into the serial string via `wsprintfA`:
```c
wsprintfA(serial, "REG-%lX-%lX-KEY", sum, sum + sum2);
```

---

## Stage 4: Keygen Implementation (C++)

We can reimplement this algorithm in standalone C++ ([src/test-keygen.cpp](src/test-keygen.cpp)):

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *getSerial(const char *name, char *newSerial) {
    unsigned int sum = 0;
    unsigned int sum2 = 0;
    unsigned int char1;

    // Pass 1: Forward transformation
    for (int i = 0; i < (int)strlen(name); i++) {
        if (i == 0) {
            char1 = name[i] + 5;
        } else {
            char1 = name[i] + name[i - 1];
        }

        char1 = char1 ^ 0x12c;
        char1 += (char1 << 2);
        char1 <<= 2;
        sum = (char1 >> 2) & 0xF0F0F0F0;
    }

    // Pass 2: Backward transformation
    for (int i = (int)strlen(name); i > 0; i--) {
        if (i == (int)strlen(name)) {
            char1 = name[i] + 5;
        } else {
            char1 = name[i] + name[i + 1];
        }

        char1 = char1 ^ 0x12c;
        char1 += (char1 << 2);
        char1 <<= 2;
        sum2 = (char1 >> 2) & 0xF0F0F0F0;
    }

    sprintf(newSerial, "REG-%lX-%lX-KEY", sum, (sum + sum2));
    return newSerial;
}

int main() {
    char name[256];
    char serial[256];

    printf("Enter username to generate serial: ");
    if (scanf("%255s", name) == 1) {
        getSerial(name, serial);
        printf("Valid Serial: %s\n", serial);
    }
    return 0;
}
```

### Verification:
Compiling and running the keygen against an arbitrary user name (e.g., `Keenan`) outputs a valid key that satisfies `strcmp` and displays the `"You are now registered!"` success box.
