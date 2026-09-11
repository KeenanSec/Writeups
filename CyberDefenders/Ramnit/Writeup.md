# Ramnit - CyberDefenders Writeup

**Category:** Memory Forensics / Malware Analysis  
**Platform:** CyberDefenders  
**Malware Family:** Ramnit Banking Trojan  
**Tools:** Volatility 3, VirusTotal, PowerShell (Get-FileHash)  

---

## Connected Investigations
- **Memory Forensics & Process Injection Suite:**
  - [CyberDefenders: Amadey](<../Amadey/README.md>) — Analyzing masquerading processes and process injection in RAM.
  - [CyberDefenders: Redline](<../Redline/Writeup.md>) — Volatility process trees, `malfind` RWX detection, and C2 extraction.
  - [CyberDefenders: Volatility Traces](<../Volatility_Traces/Volatility_Traces_Writeup.md>) — Tracing malicious PowerShell processes and defense evasion.
  - [CyberDefenders: QBot Lab](<../QBot Lab/Writeup.md>) — Memory triage, network socket analysis, and binary carving.

---

## Scenario Overview

In this investigation, an analyst is tasked with analyzing a Windows physical memory dump (`memory.dmp`) from an endpoint infected with **Ramnit**. Through process tree inspection, network socket triage, memory object carving, and threat intelligence pivoting on VirusTotal, we determine the malicious process, dump the binary to calculate its hash, extract its compile timestamp, and identify the active C2 infrastructure.

---

## Walkthrough

### Q1 — Identifying the Suspicious Process

Running `windows.pstree` against the memory dump:

```bash
vol.exe -f memory.dmp windows.pstree
```

```text
*** 4628  4568  ChromeSetup.ex  0xca82b830a300  4  -  1  True  2024-02-01 19:48:50 UTC  \Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe
```

- **Process Name:** `ChromeSetup.exe` (PID: `4628`)
- **Parent Process:** `explorer.exe` (PID: `4568`)

**Forensic Indicators of Compromise:**
- The process is executing directly out of `C:\Users\alex\Downloads\`. Legitimate Google Chrome enterprise/web installers execute from `AppData\Local\Temp` or deploy via `GoogleUpdate.exe`.
- Spawning directly from `explorer.exe` confirms interactive user execution (double-clicking a fake installer).
- `Wow64 = True` (32-bit execution), spawned shortly after user logon.

> **Question:** What is the name of the process responsible for the suspicious activity?  
> **Answer:** `ChromeSetup.exe`

---

### Q2 — Full Executable Path

Inspecting the complete path in `windows.pstree` / `windows.cmdline`:

![Process path confirmation in memory](Images/Pasted%20image%2020260731010533.png)

> **Question:** What is the exact path of the executable for the malicious process?  
> **Answer:** `C:\Users\alex\Downloads\ChromeSetup.exe`

---

### Q3 — External C2 Network Socket

Running `windows.netscan` to audit open sockets and established connections:

```powershell
.\vol.exe -f memory.dmp windows.netscan > netscan.txt
```

Searching `netscan.txt` for PID `4628` (`ChromeSetup.exe`):

![Netscan output showing malicious socket connection](Images/Pasted%20image%2020260731010714.png)

The process initiated an outbound connection:

> **Question:** What IP address did the malware attempt to connect to?  
> **Answer:** `58.64.204.181`

---

### Q4 — Geographic Location of C2 IP

Performing geolocation analysis on the remote IP `58.64.204.181`:

![IP geolocation lookup](Images/Pasted%20image%2020260731011219.png)

The C2 IP resolves to **Hong Kong**:

> **Question:** Which city is associated with the IP address the malware communicated with?  
> **Answer:** `Hong Kong`

---

### Q5 — Carving the Binary & SHA1 Hash Calculation

Dumping the executable memory object using `windows.dumpfiles`:

```powershell
.\vol.exe -f memory.dmp windows.dumpfiles --virtaddr 0xca82b85325a0
```

Calculating the SHA1 hash of the carved memory image:

```powershell
Get-FileHash file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img -Algorithm SHA1
```

![Calculating SHA1 hash of carved executable](Images/Pasted%20image%2020260731011944.png)

> **Question:** What is the SHA1 hash of the malware executable?  
> **Answer:** `280C9D36039F9432433893DEE6126D72B9112AD2`

---

### Q6 — Compilation Timestamp

Pivoting to VirusTotal with the SHA1 hash to inspect portable executable (PE) header metadata:

![VirusTotal PE compilation timestamp](Images/Pasted%20image%2020260731012112.png)

> **Question:** What is the compilation timestamp for the malware?  
> **Answer:** `2019-12-01 08:36`

---

### Q7 — C2 Domain Name

Reviewing the **Relations** tab on VirusTotal for associated network domains contacted by this binary:

![VirusTotal Relations tab showing C2 domain](Images/Pasted%20image%2020260731012433.png)

Filtering out legitimate infrastructure domains isolates the threat actor's dynamic C2 domain:

> **Question:** Can you provide the domain connected to the malware?  
> **Answer:** `dnsnb8.net`

---

## Summary of Findings

| Artifact / Indicator | Value |
| :--- | :--- |
| **Malicious Process** | `ChromeSetup.exe` (PID `4628`) |
| **File Location** | `C:\Users\alex\Downloads\ChromeSetup.exe` |
| **C2 IP Address** | `58.64.204.181` |
| **C2 Geolocation** | Hong Kong |
| **SHA1 Hash** | `280C9D36039F9432433893DEE6126D72B9112AD2` |
| **PE Compilation Time** | `2019-12-01 08:36` |
| **C2 Domain** | `dnsnb8.net` |
