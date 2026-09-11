# LNK-in-Archive PowerShell Phishing - SOC Simulator Writeup

**Category:** SOC Triage / Phishing & Endpoint Investigation  
**Platform:** SOC Simulator  
**Tools:** SIEM (Elastic / Splunk), Windows Event Logs  
**Flag:** `INVOICE#BUSAPOMKDS03.lnk`  

---

## Connected Investigations
- **Phishing Attachment Investigations:** Compare with [TryHackMe: AI Forensics](<../../TryHackMe/AI Forensics/Writeup.md>), which investigates spear-phishing lures delivering weaponized invoice spreadsheets.
- **Malware Loaders & C2 Beaconing:** Compare with [CyberDefenders: Dana Bot Lab](<../../CyberDefenders/Dana Bot Lab/Writeup.md>) (JS/WScript droppers) and [CyberDefenders: Amadey](<../../CyberDefenders/Amadey/README.md>) (modular botnet loaders).

---

## Scenario Overview

A clerk at Brightwater Logistics received a malicious phishing email carrying a compressed `.zip` archive attachment (`INVOICE_8841.zip`). The email security gateway permitted the inbound archive because compressed formats frequently evade rudimentary gateway inspection. Inside the archive was a disguised shortcut file (`.lnk`) crafted to appear as a legitimate billing invoice. Upon execution, the `.lnk` shortcut triggered an obfuscated PowerShell loader that dropped a hidden archive into a shared directory, decompressed secondary payloads, established persistence, and initiated C2 beaconing.

---

## Incident Investigation

### 1. Inbound Phishing & Archive Triage

Querying the SIEM for high-severity Windows and mail gateway events (`level:critical AND source:WinEventLog...`), we identify the initial mail-delivery event on host `INVOICES-BWLOGISTICS-PAY`:

![SIEM log identifying malicious LNK attachment](assets/Pasted%20image%2020260716223853.png)

**Key Email & File Attributes:**
- **Host Affected:** `INVOICES-BWLOGISTICS-PAY`
- **Mail Event:** `mail-received`
- **Email Security Check:** `dmarc: fail` (Spoofed or unauthenticated domain)
- **Outer Attachment:** `INVOICE_8841.zip`
- **Inner Attachment (Payload):** `INVOICE#BUSAPOMKDS03.lnk`
- **Flag:** `INVOICE#BUSAPOMKDS03.lnk`

> **Forensic Note on LNK Attacks:**  
> Legitimate business invoices are typically formatted as `.pdf` or `.docx` documents. Attackers frequently wrap weaponized Windows Shortcut (`.lnk`) files inside `.zip` or `.iso` containers to bypass perimeter email filters. When double-clicked by an unsuspecting user, Windows Explorer parses the shortcut targets and silently spawns `powershell.exe` with hidden or encoded flags.

---

### 2. Execution Chain & Behavioral Analysis

1. **Initial Vector:** Email delivery of `INVOICE_8841.zip` to the billing clerk on workstation `INVOICES-BWLOGISTICS-PAY`.
2. **User Execution:** User extracts the archive and double-clicks `INVOICE#BUSAPOMKDS03.lnk`.
3. **Execution (`powershell.exe`):** The shortcut executes a command line invoking PowerShell with bypass arguments.
4. **Staging & Persistence:** The loader script drops a secondary payload into a shared directory, unzips stage-2 modules, and configures scheduled tasks/registry run keys.
5. **C2 Beaconing:** Outbound HTTP/HTTPS connections are initiated to remote adversary infrastructure.

---

## Key Security Concepts

- **Beaconing:** Periodic, automated network communications initiated by compromised endpoints to adversary Command and Control (C2) servers to signal availability, request instructions, or upload stage outputs.
- **Loader:** A lightweight first-stage malicious executable or script designed to bypass perimeter defenses, establish an initial foothold, and pull down larger, feature-complete payloads (e.g., info-stealers, ransomware).
