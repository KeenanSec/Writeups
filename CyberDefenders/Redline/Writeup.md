# Redline - CyberDefenders Writeup

**Category:** Memory Forensics / Endpoint Investigation  
**Platform:** CyberDefenders  
**Tools:** Volatility 3, VolWeb, strings, grep  

---

## Connected Investigations
- **Memory Forensics & Process Injection Suite:** Compare with:
  - [CyberDefenders: Amadey](<../Amadey/README.md>): Masquerading loader (`lssass.exe` in Temp) spawning `rundll32.exe`.
  - [CyberDefenders: Volatility Traces](<../Volatility_Traces/Volatility_Traces_Writeup.md>): Tracing malicious PowerShell processes and defense evasion cmdlets (`Add-MpPreference`).
  - [CyberDefenders: Ramnit](<../Ramnit/Writeup.md>): Fake installer execution from user directories and C2 beaconing.
  - [CyberDefenders: QBot Lab](<../QBot Lab/Writeup.md>): Memory triage, process injection, and network C2 analysis with Volatility 3.

---

## Scenario Overview

A corporate workstation was suspected of being infected by malware. An incident responder captured a physical memory dump (`Memory.mem`). Using **Volatility 3** and the **VolWeb** graphical analysis platform, we perform triage on process execution trees, memory injection signatures, network connections, and string artifacts to uncover the rogue process, determine code injection evidence, and extract the adversary's Command and Control (C2) URI.

---

## Walkthrough

### Q1 — Identifying the Malicious Process

To inspect running processes and parent-child hierarchies, we run the `windows.pstree` plugin:

```bash
python3 vol.py -f Memory.mem windows.pstree > pstree.txt
```

Scanning the process tree reveals an anomalous process with a deliberate typographical masquerade (`oneetx.exe`):

![Volatility pstree output showing rogue oneetx.exe process](images/Pasted%20image%2020260806175007.png)

- **Process Name:** `oneetx.exe` (masquerading / randomized name)
- **PID:** `5896`
- **PPID:** `8844`
- **Execution Path:** `\Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe`
- **Child Process:** PID `7732` (`rundll32.exe`)

**Analysis:** Legitimate Windows system executables do not execute out of user `AppData\Local\Temp` subdirectories. Furthermore, the rogue process spawned a 32-bit `rundll32.exe` instance, a common behavior for malware loaders establishing injection.

---

### Q2 — Detecting Code Injection via `malfind`

To verify whether the rogue process contains unbacked or injected executable code, we execute the `windows.malfind` plugin:

```bash
python3 vol.py -f Memory.mem windows.malfind > malfind.txt
```

Examining the findings for PID `5896` (`oneetx.exe`):

![Volatility malfind output displaying RWX memory segment](images/Pasted%20image%2020260806180347.png)

- **Target PID:** `5896` (`oneetx.exe`)
- **Memory Range:** `0x400000` – `0x437fff`
- **Memory Protection:** `PAGE_EXECUTE_READWRITE` (RWX)
- **Hex Header:** `4d 5a 90 00 03 00 00 00 04 ...` (`MZ` header)

**Analysis:** Finding a memory section with `PAGE_EXECUTE_READWRITE` protection that begins with the DOS executable magic bytes (`MZ`) is a definitive indicator of process hollowing or reflective DLL injection.

---

### Q3 — Network Connections & Triage

Next, we run `windows.netscan` to audit network sockets and identify communication with external endpoints:

```bash
python3 vol.py -f Memory.mem windows.netscan > netscan.txt
```

Cross-referencing network endpoints against identified processes:

![VolWeb netscan view showing outbound connections](images/Pasted%20image%2020260814024106.png)
*(Reference view: VolWeb interface)*
![VolWeb network connections for oneetx.exe](images/Pasted%20image%2020260814024106.png)

- **Process:** `oneetx.exe` (PID `5896`)
- **Local Socket:** `10.0.85.2:55462`
- **Foreign Address:** `77.91.124.20:80`
- **State:** `CLOSED`

**Analysis:** `oneetx.exe` initiated outbound HTTP communication directly to external IP `77.91.124.20` on port 80.

---

### Q4 — Extracting the C2 Endpoint from Memory Strings

To locate the exact resource path queried on the external C2 server, we perform a string extraction across the memory dump and search for `.php` requests associated with the attacker IP:

```bash
grep "77.91.124.20" redlinestringsphp.txt
```

![Terminal grep output showing full C2 URI](images/Pasted%20image%2020260814025255.png)

**Recovered C2 URL:**
```text
http://77.91.124.20/store/games/index.php
```

---

## Summary of Findings

| Indicator / Artifact | Value |
| :--- | :--- |
| **Malicious Executable** | `oneetx.exe` |
| **Process ID (PID)** | `5896` |
| **File Location** | `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe` |
| **Spawned Child Process** | `rundll32.exe` (PID `7732`) |
| **Memory Protection** | `PAGE_EXECUTE_READWRITE` (RWX with `MZ` header) |
| **Attacker C2 IP** | `77.91.124.20` |
| **Full C2 URI** | `http://77.91.124.20/store/games/index.php` |
