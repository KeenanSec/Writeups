# MeteorHit - Indra Lab — CyberDefenders Lab Notes

**Category:** Endpoint Forensics / Incident Response  
**Platform:** CyberDefenders  
**Triage Artifacts:** KAPE SANS Triage  
**Threat Focus:** Active Directory Compromise & Wiper Malware Deployment  

---

## Connected Investigations
- **Active Directory Compromise & Persistence:**
  - [CyberDefenders: GoldenSpray Lab](<../GoldenSpray Lab/Writeup.md>) — Password spraying and scheduled task persistence on Domain Controllers.
  - [Root-Me: Kerberos - Pre-Authentication](<../../Root-Me/Kerberos - Pre-Authentication/Writeup.md>) — Kerberos authentication exploitation.
- **Defense Evasion & Wiper Impact:**
  - [CyberDefenders: Volatility Traces](<../Volatility_Traces/Volatility_Traces_Writeup.md>) — Adding Defender exclusions (`Add-MpPreference`).
  - [CyberDefenders: REvil - GOLD SOUTHFIELD Lab](<../REvil - GOLD SOUTHFIELD Lab/Writeup.md>) — System recovery disruption and shadow copy deletion.

---

## Scenario Overview

A critical network infrastructure encountered severe operational disruptions, causing system outages across enterprise machines. Public message boards displayed politically charged messages, and several systems were wiped, causing widespread service failures. Initial investigations reveal that attackers compromised the Active Directory (AD) environment and deployed wiper malware across multiple endpoints.

During the attack, an alert employee noticed suspicious activity and powered down several key systems, halting the wiper before it wiped the entire network. Forensic artifacts were collected using **KAPE SANS Triage** to analyze initial access, execution vectors, GPO abuse, defense evasion, and damage scope.

---

## Core Investigation Guide

*Refer to [Guiding Questions.md](Guiding%20Questions.md) for detailed investigative prompts covering initial access, process hierarchies, boot sector deletion, and filesystem USN journal analysis.*

---

## Lab Questions & Forensic Tracking

### Q1 — Initiating Malicious GPO
The attack began by abusing a Group Policy Object (GPO) to execute a malicious batch file across domain-joined machines.  
- **Question:** What is the name of the malicious GPO responsible for initiating the attack by running a script?  
- **Investigative Pivot:** Inspect Active Directory Group Policy history, `GroupPolicy` event logs (Event ID 4016), and Sysvol scripts directory (`\\<domain>\sysvol\<domain>\Policies\...`).

---

### Q2 — Expanded Staging Archive
During the investigation, a specific file containing critical components necessary for later attack stages was located on the system and expanded using a built-in utility.  
- **Question:** What is the name of the file, and where was it located on the system? Please provide the full file path.  
- **Path Format:** `C:\...\...`  
- **Investigative Pivot:** Check `expand.exe` / `extrac32.exe` execution in Prefetch and UserAssist.

---

### Q3 — Archive Extraction Password
The attacker employed password-protected archives to conceal secondary payloads.  
- **Question:** What is the password used to extract the malicious files?  
- **Investigative Pivot:** Search script command lines, batch file strings, and PowerShell transcript logs.

---

### Q4 — Antivirus Defense Evasion (Defender Exclusions)
Multiple commands were executed to add exclusions to Windows Defender to prevent detection of staged payloads.  
- **Question:** What is the name of the first file added to the Windows Defender exclusion list?  
- **Investigative Pivot:** Check Event ID `5007` in `Microsoft-Windows-Windows Defender/Operational` or PowerShell commands executing `Add-MpPreference -ExclusionPath`.

---

### Q5 — Scheduled Task Execution Delay
A scheduled task was configured to execute after a set delay.  
- **Question:** How many seconds after the task creation time is it scheduled to run?  
- **Investigative Pivot:** Parse XML files under `C:\Windows\System32\Tasks` or Event ID `4698` in Security logs.

---

### Q6 — Domain Unjoin Command PID
Following malware execution, `wmic.exe` was used to unjoin the compromised machine from the domain to hinder centralized administrative remediation.  
- **Question:** What is the Process ID (PID) of the utility responsible for performing this action?  
- **Investigative Pivot:** Check Event ID 1 (`Process Creation`) in Sysmon logs or Event ID 4688 for `wmic.exe computeraccount delete` / `netdom.exe`.

---

### Q7 — Boot Manager Deletion Command
The malware deleted the Windows Boot Manager to render the machine unbootable upon subsequent reboot.  
- **Question:** What command did the malware use to delete the Windows Boot Manager?  
- **Format:** `C:\Windows\System32\bcdedit.exe /delete {bootmgr} /f`  
- **Investigative Pivot:** Audit command-line parameters for `bcdedit.exe`.

---

### Q8 — Elevated Startup Persistence Task
The malware created a scheduled task configured with elevated privileges at system startup.  
- **Question:** What is the name of the scheduled task created by the malware to maintain persistence?  
- **Investigative Pivot:** Check `TaskScheduler` operational logs and scheduled tasks registry keys (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`).

---

### Q9 — Screen Locker Malware Name
A malicious component locked the endpoint display, displaying political defacement and preventing interactive user response.  
- **Question:** What is the name of this malware? (not the filename)  
- **Investigative Pivot:** Match defacement strings and binary metadata against threat intelligence and CISA/CERT wiper alerts (e.g., Meteor / HermeticWiper / CaddyWiper / IsaacWiper).

---

### Q10 — NTFS USN Journal Analysis
The disk shows file overwrite patterns where files were zeroed and deleted.  
- **Question:** What is the USN (Update Sequence Number) associated with the deletion of the file `msuser.reg`?  
- **Investigative Pivot:** Parse `$UsnJrnl:$J` using `MFTECmd` or `USN-Journal-Parser` and filter for file record `msuser.reg` with reason `FILE_DELETE`.
