# QBot - Memory Forensics Writeup

Reconstruct the QBot (QakBot) malware infection timeline by analyzing memory dumps, identifying malicious processes, extracting dropped files, and analyzing network communications using **Volatility 3** and **VirusTotal**.

- **Challenge:** [CyberDefenders - QBot](https://cyberdefenders.org/blueteam-ctf-challenges/qbot/)
- **Category:** Endpoint Forensics
- **Difficulty:** Medium
- **Tools:** Volatility 3, sha256sum, VirusTotal

---

## Connected Investigations
- **Memory Forensics & Process Triage Suite:**
  - [CyberDefenders: Amadey](<../Amadey/README.md>) — Modular loader triage, process masquerading, and C2 netscan.
  - [CyberDefenders: Volatility Traces](<../Volatility_Traces/Volatility_Traces_Writeup.md>) — Process hierarchy analysis, PowerShell tracing, and defense evasion.
  - [CyberDefenders: Redline](<../Redline/Writeup.md>) — RWX memory injection detection via `malfind` and VolWeb socket triage.
  - [CyberDefenders: Ramnit](<../Ramnit/Writeup.md>) — Memory carving of dropped executables and hash calculation.

---

## Investigation Overview

The goal of this investigation is to trace the infection lifecycle of a host compromised by QBot:
1. **Network Triage:** Identify external Command and Control (C2) servers contacted by the host.
2. **Process Analysis:** Locate the malicious process responsible for executing the malware and determine how it was invoked.
3. **Artifact Extraction:** Carve the weaponized document from memory and obtain its cryptographic hash.
4. **Threat Intelligence:** Pivot to VirusTotal to confirm the malware family and extract document metadata (creation timestamps).

---

## Q1 - First IP address the malware attempted to communicate with

> **Question:** Our first step is identifying the initial point of contact the malware made with an external server. Can you specify the first IP address the malware attempted to communicate with?

### Analysis
To examine network activity captured in the memory dump, we check the results of the `windows.netscan` plugin and filter for external HTTP traffic (port 80):

```bash
cat windows.netscan.txt | grep 80
```

Scanning through the output, the first external IP connection listed over port 80 is `94.140.112.73`:

```text
0x9500001f8420  TCPv4  192.168.58.135  50460  94.140.112.73  80  CLOSED  -  -  N/A
```

![Netscan output showing port 80 connections](imgs/Pasted%20image%2020260904054126.png)

**Answer:** `94.140.112.73`

---

## Q2 - Secondary IP address the malware attempted to communicate with

> **Question:** We need to determine if the malware attempted to communicate with another IP. Which IP address did the malware attempt to communicate with again?

### Analysis
Continuing down the `windows.netscan` output, we find a second external IP address communicating over port 80:

```text
0xcd8ef63cb0c0  TCPv4  192.168.58.135  50459  45.147.230.104  80  CLOSED  -  -  N/A
```

> **Forensic Note on Ephemeral Port Sequencing:**  
> Windows assigns outbound source ports sequentially:
> - Ephemeral Port **`50459`** $\rightarrow$ `45.147.230.104:80`
> - Ephemeral Port **`50460`** $\rightarrow$ `94.140.112.73:80`
>
> In real-time network chronology, the malware attempted to connect to `45.147.230.104` first. When that connection failed/closed, it immediately fell back to `94.140.112.73`. However, because Volatility scans physical memory addresses in ascending order (`0x95...` before `0xcd8...`), `94.140.112.73` appears earlier in the raw output file, which is how the challenge platform evaluates Q1 and Q2.

**Answer:** `45.147.230.104`

---

## Q3 - Process that initiated the malware

> **Question:** Identifying the process responsible for this suspicious behavior helps reconstruct the sequence of events leading to the execution of the malware and its source. What is the name of the process that initiated the malware?

### Analysis
Examining the process tree (`windows.pstree`) and suspicious memory regions (`windows.malfind`) points toward an Office process. We inspect command-line arguments using `windows.cmdline`:

```bash
cat cmdline.txt | grep EXCEL
```

```text
4516  EXCEL.EXE  "C:\Program Files\Microsoft Office\Office16\EXCEL.EXE" /dde
```

![cmdline output showing EXCEL.EXE with /dde flag](imgs/Pasted%20image%2020260904060238.png)

The presence of the `/dde` (Dynamic Data Exchange) switch indicates that `EXCEL.EXE` (PID 4516) was launched because a user opened a spreadsheet attachment (e.g. from an email lure), rather than launching Excel manually.

**Answer:** `EXCEL.EXE`

---

## Q4 - Malware file name

> **Question:** The malware's file name is crucial for further forensic analysis and extracting the malware. Can you provide its file name?

### Analysis
Since `EXCEL.EXE` (PID 4516) was invoked to open a malicious document, we dump all files associated with PID 4516 using `windows.dumpfiles`:

```bash
python3 vol.py -f ../../Artifacts/memory.dmp windows.dumpfiles --pid 4516
```

We then search the extracted files for Excel extensions (`.xls` / `.xlsx`):

```bash
ls | grep "xls"
```

```text
file.0xcd8ef507ac60.0xcd8ef514f5d0.DataSectionObject.Payment.xls.dat
```

![Extracted Excel file from dumpfiles](imgs/Pasted%20image%2020260904055604.png)

This identifies the weaponized workbook as `Payment.xls`.

**Answer:** `Payment.xls`

---

## Q5 - SHA256 hash of the malware

> **Question:** Hashes are like digital fingerprints for files. Once the hash is known, it can be used to scan other systems within the network to identify if the same malicious file exists elsewhere. What is the SHA256 hash of the malware?

### Analysis
We calculate the SHA256 hash of the dumped file (`Payment.xls.dat`) using `sha256sum`:

```bash
sha256sum file.0xcd8ef507ac60.0xcd8ef514f5d0.DataSectionObject.Payment.xls.dat
```

![sha256sum calculation](imgs/Pasted%20image%2020260904060628.png)

```text
3cef2e4a0138eeebb94be0bffefcb55074157e6f7d774c1bbf8ab9d43fdbf6a4
```

**Answer:** `3cef2e4a0138eeebb94be0bffefcb55074157e6f7d774c1bbf8ab9d43fdbf6a4`

---

## Q6 - UTC creation time of the malware file

> **Question:** To trace the origin of the malware and understand its development timeline, can you provide the UTC creation time of the malware file?

### Analysis
Using the SHA256 hash from Q5, we look up the file on **VirusTotal**. The file is flagged by 37/62 security vendors as a malicious QBot/QakBot macro document.

![VirusTotal detection score](imgs/Pasted%20image%2020260904060759.png)

Navigating to the **Details** tab and checking the **History** section reveals the document's internal metadata creation timestamp:

![VirusTotal History tab showing Creation Time](imgs/Pasted%20image%2020260904060827.png)

```text
Creation Time: 2015-06-05 18:17:20 UTC
```

**Answer:** `2015-06-05 18:17:20 UTC`

---

## Indicators of Compromise (IOCs)

| Type | Indicator / Value | Description |
|------|-------------------|-------------|
| **C2 IPv4** | `94.140.112.73:80` | External C2 communication endpoint |
| **C2 IPv4** | `45.147.230.104:80` | External C2 communication endpoint |
| **Process** | `EXCEL.EXE` (PID 4516) | Process running weaponized workbook with `/dde` flag |
| **File Name** | `Payment.xls` | Malicious macro lure workbook |
| **SHA256** | `3cef2e4a0138eeebb94be0bffefcb55074157e6f7d774c1bbf8ab9d43fdbf6a4` | Hash of `Payment.xls` |
| **Timestamp**| `2015-06-05 18:17:20 UTC` | Metadata creation timestamp |

---

## MITRE ATT&CK Mapping

| Tactic | Technique Name | Technique ID | Observed Evidence & Activity |
|--------|----------------|--------------|------------------------------|
| **Initial Access** | Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Delivery of malicious Excel workbook (`Payment.xls`) |
| **Execution** | User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User double-clicked and opened the attachment |
| **Execution** | Inter-Process Communication: Dynamic Data Exchange | [T1559.001](https://attack.mitre.org/techniques/T1559/001/) | `EXCEL.EXE` invoked with `/dde` protocol parameter |
| **Execution** | Command and Scripting Interpreter: Visual Basic | [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Obfuscated VBA macro execution inside Excel |
| **Defense Evasion** | Indicator Removal: Timestomping | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | Backdated document creation timestamp (`2015-06-05 18:17:20 UTC`) |
| **Command & Control** | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Outbound HTTP traffic over port 80 |
| **Command & Control** | Fallback Channels | [T1008](https://attack.mitre.org/techniques/T1008/) | C2 failover between `45.147.230.104` and `94.140.112.73` |