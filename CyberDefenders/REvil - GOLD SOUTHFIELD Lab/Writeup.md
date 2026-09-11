# REvil - GOLD SOUTHFIELD Lab — CyberDefenders Writeup

**Category:** Threat Hunting / Ransomware Analysis  
**Platform:** CyberDefenders  
**Threat Actor:** GOLD SOUTHFIELD (Pinchy Spider)  
**Malware Family:** REvil / Sodinokibi  
**Tools:** Splunk, Threat Intelligence (Triage / Any.Run)  

---

## Connected Investigations
- **Threat Actor Taxonomies:** Compare with [CyberDefenders: IcedID](<../IcedID/Writeup.md>) (threat group GOLD CABIN).
- **System Recovery Disruption:** Compare with [CyberDefenders: MeteorHit - Indra Lab](<../MeteorHit - Indra Lab/Writeup.md>) (abusing administrative commands to prevent recovery).

---

## Scenario Overview

In this lab, an enterprise Windows endpoint was encrypted by **REvil** (Sodinokibi) ransomware, operated by threat syndicate **GOLD SOUTHFIELD**. Using Splunk to analyze Windows Event Logs (Event ID 1 Process Creation, Event ID 11 File Creation), we trace the adversary from the drop of the ransom note to the originating disguised executable, uncover commands used to inhibit system recovery by deleting volume shadow copies, obtain the cryptographic file hash, and identify the attacker's Tor negotiation portal.

---

## Walkthrough

### Q1 — Identifying the Ransom Note Filename

![Splunk event search for ransomware indicators](images/Pasted%20image%2020260804233656.png)

Querying the `revil` index for dropped text files containing common ransom note keywords (`README` or `HELP`):

```spl
index=revil winlog.event_data.TargetFilename="*README*" OR winlog.event_data.TargetFilename="*HELP*" 
| table _time winlog.event_data.Image winlog.event_data.TargetFilename winlog.event_data.CurrentDirectory
```

- **Answer:** `5uizv5660t-readme.txt`

---

### Q2 — Ransomware Process ID (PID)

Tracing process creation events (Event ID 1) for the suspicious binary executing during the encryption window:

```spl
index=revil winlog.event_id=1 "facebook assistant.exe"
| table _time winlog.event_data.Image winlog.event_data.ProcessId winlog.event_data.ParentImage winlog.event_data.ParentProcessId
```

![Splunk query showing ransomware PID and execution hierarchy](images/Pasted%20image%2020260805002745.png)

- **Answer:** `5348`

---

### Q3 — Executable File Path on Disk

From the same process creation event in Q2, the image path reveals the binary location in the Administrator's Downloads directory:

- **Answer:** `C:\Users\Administrator\Downloads\facebook assistant.exe`

---

### Q4 — Command Used to Delete Volume Shadow Copies

Ransomware routinely disables backup and recovery mechanisms prior to file encryption. Querying Splunk for PowerShell command line executions:

![Splunk command line search for recovery inhibition](images/Pasted%20image%2020260805005537.png)
![Command line parameter showing shadow copy deletion](images/Pasted%20image%2020260805010244.png)

```powershell
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

- **Answer:** `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`

---

### Q5 — SHA-256 Hash of the Ransomware Binary

Querying Splunk for file creation hashes associated with `facebook assistant.exe`:

![Splunk hash output for facebook assistant.exe](images/Pasted%20image%2020260805010653.png)

- **Answer:** `B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA`

---

### Q6 — Threat Actor Tor (.onion) Negotiation Domain

Querying the SHA-256 hash on `tri.age` (Triage sandbox) reveals the ransomware configuration and contact portal:

![Triage sandbox analysis revealing REvil onion portal](images/Pasted%20image%2020260805013320.png)

- **Answer:** `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion`

---

## Summary of Findings

| Artifact / Indicator | Value |
| :--- | :--- |
| **Ransom Note** | `5uizv5660t-readme.txt` |
| **Ransomware Executable** | `facebook assistant.exe` |
| **Process ID (PID)** | `5348` |
| **Inhibit Recovery Cmd** | `Get-WmiObject Win32_Shadowcopy \| ForEach-Object {$_.Delete();}` |
| **SHA-256 Hash** | `B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA` |
| **Tor Payment Portal** | `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion` |
