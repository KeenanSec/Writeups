# CTF Writeups & DFIR Lab Repository

A centralized, structured repository and Obsidian vault containing comprehensive writeups, incident reports, investigation notes, and proof-of-concept scripts across major cybersecurity platforms.

---

## Repository Structure & Overview

```text
CTFWriteups/
├── CyberDefenders/        # Blue Team & DFIR CTF Challenges (19 Labs)
├── TryHackMe/             # Threat Hunting, Forensics & Web Exploitation (7 Rooms)
├── Root-Me/               # Network Forensics & Protocol Challenges (4 Labs)
└── SOC-Simulator/         # Enterprise SOC Triage Scenarios (1 Scenario)
```

---

## Core Investigation Methodology & Playbook

- 📘 **[Professional DFIR Investigation Playbook](DFIR_Investigation_Playbook.md)**: A structured methodology for moving from question-hunting to hypothesis-driven intrusion analysis across CyberDefenders, Hack The Box, and TryHackMe.
  - **The 6-Phase Investigative Spine:** Scoping $\rightarrow$ Anchor Lead ($T_0$) $\rightarrow$ Bidirectional Timeline Reconstruction $\rightarrow$ MITRE & Diamond Model Attribution $\rightarrow$ Blast Radius Scoping $\rightarrow$ Executive Synthesis.
  - **Modular Artifact Checklists:** Network Traffic (Wireshark/Zeek), Host Telemetry (Windows EVTX & Sysmon), SIEM (Splunk SPL & Elastic KQL), Memory Forensics (Volatility 3), and Malware Triage.
  - **Master Case Template:** Copy-pasteable Markdown case ledger with chronological timeline and IoC table.

---

## Connected Investigations & Campaign Matrix

Projects and investigations in this repository share recurring adversaries, storylines, or complementary investigative techniques:

### 1. The Byte Lotus Resort CTF Storyline (TryHackMe)
A connected multi-part OSINT and digital forensics campaign tracking data leaks and espionage at the Byte Lotus Hotel:
- **Part 1: [The Brochure](TryHackMe/TheBrochure/Writeup.md)** — OSINT pivoting on Vera the Concierge (`@veratheconcierge`), reconstructing 3-part Base64 Instagram leaks to recover `THM{V3r@z_aCC0unt_h4s_is3n_f0und!}`.
- **Part 2: [Overheard at Breakfast](TryHackMe/Overheard%20at%20Breakfast/Writeup.md)** — OSINT targeting hotel employee email `lambobytelotushotel@gmail.com` via Gravatar profile MD5 hashes to decode `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}`.
- **Part 3: [PackedLight](TryHackMe/PackedLight/Writeup.md)** — Network forensics on `traffic.pcapng`, reverse-engineering the `updates.py` keylogger, and decrypting XOR-encoded keystrokes exfiltrated in `hotel_sess_state` cookies to extract `THM{V3r4_1s_w4tch1ng_0veR_y0u}`.

### 2. Cloud Threat Hunting & Incident Response (AWS vs. Azure)
Two enterprise cloud compromise investigations analyzing audit trails for initial compromise, data exfiltration, and backdoor creation:
- **AWS Environment: [AWSRaid](CyberDefenders/AWSRaid/AWSRaid%20-%20CloudTrail%20Incident%20Writeup.md)** — Splunk & CloudTrail analysis tracking brute force against `helpdesk.luke`, S3 CAD design exfiltration, disabling S3 Block Public Access on `backup-and-restore98825501`, and persistence via backdoor admin `marketing.mark`.
- **Azure Environment: [AzureHunt](CyberDefenders/AzureHunt/Writeup.md)** — Elastic SIEM & KQL analysis of `cybercactus.onmicrosoft.com`, tracking unauthorized export of `CUSTOMERDATADB`, creation of backdoor `IT_Support`, elevation to `Owner` role, and validation of persistence sign-ins.
- *Note:* The target cloud tenant `cybercactus.onmicrosoft.com` connects directly with the internal on-premises domain `cybercactus.local` analyzed in **[PoisonedCredentials](CyberDefenders/PoisonedCredentials/PoisonedCredentials.md)**.

### 3. Active Directory & Lateral Movement Suite
Enterprise identity compromises spanning password spraying, LLMNR poisoning, ticket manipulation, and SMB services:
- **[GoldenSpray Lab](CyberDefenders/GoldenSpray%20Lab/Writeup.md)** — Splunk analysis of domain password spraying against `SECURETECH.local`, initial compromise of `mwilliams`, Mimikatz LSASS dumping, lateral movement to `jsmith`, and DC scheduled task persistence (`\FilesCheck`).
- **[PoisonedCredentials](CyberDefenders/PoisonedCredentials/PoisonedCredentials.md)** — Wireshark analysis of Responder LLMNR/NBT-NS poisoning against mistyped queries (`fileshaare`, `prinetr`), harvesting `janesmith`'s credentials on host `ACCOUNTINGPC` (`cybercactus.local`).
- **[PsExec Lateral Movement](CyberDefenders/Psexec/Writeup.md)** — Tracking SMB lateral movement via `ADMIN$` service staging (`PSEXESVC.exe`), `IPC$` named pipe streams (`stdin`, `stdout`, `stderr`), and targeting `MARKETING-PC$`.
- **[Block](TryHackMe/Block/Block%20Writeup%20THM.md)** — Extracting NTLM hashes from LSASS dumps with `pypykatz`, recovering session keys, and decrypting encrypted SMB3 packet captures in Wireshark.
- **[Kerberos - Pre-Authentication](Root-Me/Kerberos%20-%20Pre-Authentication/Writeup.md)** — Extracting `PA-ENC-TIMESTAMP` structures from network captures with `Krb5RoastParser` and offline cracking via Hashcat mode 19900.
- **[MeteorHit - Indra Lab](CyberDefenders/MeteorHit%20-%20Indra%20Lab/Writeup.md)** — Investigating enterprise AD compromise, malicious GPO batch execution, Defender exclusion evasion, and domain unjoining.

### 4. Memory Forensics & Endpoint Triage (Volatility 3 & VolWeb)
In-depth memory analysis uncovering process hollowing, reflective injection, masquerading, and malware beaconing:
- **[Amadey](CyberDefenders/Amadey/README.md)** — Volatility 3 triage of modular botnet loader masquerading as `lssass.exe` in user Temp and injecting into `rundll32.exe`.
- **[Redline](CyberDefenders/Redline/Writeup.md)** — Volatility 3 and VolWeb analysis detecting typographical disguise (`oneetx.exe`), RWX code injection via `malfind`, and C2 extraction (`http://77.91.124.20/store/games/index.php`).
- **[Volatility Traces](CyberDefenders/Volatility_Traces/Volatility_Traces_Writeup.md)** — Tracing malicious PowerShell parentage (`InvoiceCheckList.exe`), LOLBIN injection (`RegSvcs.exe`), and defense evasion (`Add-MpPreference`).
- **[Ramnit](CyberDefenders/Ramnit/Writeup.md)** — Memory analysis of fake installer `ChromeSetup.exe`, socket analysis to Hong Kong C2 `58.64.204.181`, memory carving, and compile timestamp extraction.
- **[QBot Lab](CyberDefenders/QBot%20Lab/Writeup.md)** — Comprehensive memory reconstruction of QakBot infection, ephemeral port sequencing, external C2 contacts, process injection, and document carving.

### 5. Threat Intelligence & Cybercrime Syndicates
Investigating advanced persistent threats, initial access brokers, and ransomware operators:
- **[REvil - GOLD SOUTHFIELD Lab](CyberDefenders/REvil%20-%20GOLD%20SOUTHFIELD%20Lab/Writeup.md)** — Splunk analysis of Sodinokibi ransomware operated by GOLD SOUTHFIELD, disguised as `facebook assistant.exe` (PID 5348), volume shadow copy deletion, and Tor negotiation portal.
- **[IcedID](CyberDefenders/IcedID/Writeup.md)** — Analysis of Excel macro droppers operated by cybercrime syndicate GOLD CABIN, downloading secondary payload `3003.gif` via `URLDownloadToFileA` across 5 NameCheap domains.
- **[Yellow RAT Lab](CyberDefenders/Yellow%20RAT%20lab/Writeup.md)** — Threat intelligence triage of SolarMarker (Jupyter / Yellow Cockatoo), tracking dropped `.dll` and `.dat` components, compilation dates, and C2 `gogohid.com`.

### 6. Phishing & Malware Delivery Chains
Investigating weaponized lure documents and loader mechanics:
- **[LNK-in-Archive PowerShell Phishing](SOC-Simulator/LNK-in-Archive%20PowerShell%20Phishing/Writeup.md)** — Email security triage of `INVOICE_8841.zip` delivering `INVOICE#BUSAPOMKDS03.lnk` to trigger obfuscated PowerShell loaders on `INVOICES-BWLOGISTICS-PAY`.
- **[AI: Forensics](TryHackMe/AI%20Forensics/Writeup.md)** — Linux email triage of overdue energy invoice lure (`invoice_Q1_2075.ods`) and correlating unauthorized SSH logins from `192.168.0.100`.
- **[Dana Bot Lab](CyberDefenders/Dana%20Bot%20Lab/Writeup.md)** — Tracing stage-1 JavaScript dropper (`allegato_708.js`) executed via `wscript.exe` to retrieve stage-2 `.dll` payloads.

### 7. Web Application Exploitation & Network Traffic
Analyzing protocol flows and web vulnerability exploitation:
- **[XXE Infiltration Lab](CyberDefenders/XXE%20Infiltration%20Lab/Writeup.md)** — PCAP analysis of XML External Entity injection on `/review/upload.php`, reading `config.php`, extracting MySQL credentials (`Winter2024`), connecting on port 3306, and uploading web shell `booking.php`.
- **[TeamCity CVE-2024-27198](CyberDefenders/TeamCity/Writeup.md)** — Packet analysis of unauthenticated administrative access bypass via path traversal (`?jsp=/app/rest/...`) on JetBrains TeamCity `2023.11.3`.
- **[Tomcat Takeover Lab](CyberDefenders/Tomcat%20Takeover%20Lab/README.md)** — Wireshark and NetworkMiner analysis of web server administration access.
- **[Fools Mate](TryHackMe/Fools%20Mate/Writeup.md)** — Bypassing browser JavaScript move restrictions by sending direct API POST requests to `/api/move` to trigger checkmate and flag `THM{cl13nt_s1d3_ch3ckm4t3}`.

### 8. Network Protocol & Packet Forensics
Deep-dive frame parsing and legacy cleartext protocol captures:
- **[ETHERNET - frame](Root-Me/ETHERNET%20-%20frame/Writeup.md)** — Hex to ASCII conversion of raw Layer 2 frame, decoding HTTP Basic Authentication header `Basic Y29uZmk6ZGVudGlhbA==` to `confi:dential`.
- **[TELNET - authentication](Root-Me/TELNET%20-%20authentication/Writeup.md)** — Wireshark TCP stream analysis capturing unencrypted OpenBSD Telnet credentials (`fake:user`).
- **[FTP and Telnet - authentication](Root-Me/FTP%20and%20Telnet%20-%20authentication/Writeup.md)** — Forensics on `ch1.pcap` detailing cleartext FTP login (`cdts3500:cdts3500`), data channel file extraction, and OS/400 `WRKACTJOB` commands.
- **[The Crime](CyberDefenders/The%20Crime%20Lab/Writeup.md)** — Mobile Android forensics using ALEAPP to parse `gass.db`, `mmssms.db` extortion messages, Google Maps caches, flight boarding passes, and Discord chat records.
- **[Letter](TryHackMe/Letter/README.md)** — OSINT challenge notes analyzing French sea-rescue (SNSM) envelopes and vintage newspaper archives (*L'Ouest-Éclair*).

---

## Comprehensive Writeup Catalog

| Platform | Challenge / Lab | Primary Domain | Core Tools | Writeup Link |
| :--- | :--- | :--- | :--- | :--- |
| **CyberDefenders** | AWSRaid | Cloud DFIR | Splunk, AWS CloudTrail | [View Writeup](CyberDefenders/AWSRaid/AWSRaid%20-%20CloudTrail%20Incident%20Writeup.md) |
| **CyberDefenders** | Amadey | Memory Forensics | Volatility 3, strings | [View Writeup](CyberDefenders/Amadey/README.md) |
| **CyberDefenders** | AzureHunt | Cloud DFIR | Elastic SIEM, KQL | [View Writeup](CyberDefenders/AzureHunt/Writeup.md) |
| **CyberDefenders** | Dana Bot Lab | Malware Analysis | Wireshark, VirusTotal | [View Writeup](CyberDefenders/Dana%20Bot%20Lab/Writeup.md) |
| **CyberDefenders** | GoldenSpray Lab | Threat Hunting / AD | Splunk, Sysmon | [View Writeup](CyberDefenders/GoldenSpray%20Lab/Writeup.md) |
| **CyberDefenders** | IcedID | Threat Intelligence | VirusTotal, Any.Run | [View Writeup](CyberDefenders/IcedID/Writeup.md) |
| **CyberDefenders** | MeteorHit - Indra Lab | Endpoint IR / AD | KAPE SANS Triage | [View Writeup](CyberDefenders/MeteorHit%20-%20Indra%20Lab/Writeup.md) |
| **CyberDefenders** | PoisonedCredentials | Network / AD | Wireshark | [View Writeup](CyberDefenders/PoisonedCredentials/PoisonedCredentials.md) |
| **CyberDefenders** | PsExec | Network / SMB | Wireshark | [View Writeup](CyberDefenders/Psexec/Writeup.md) |
| **CyberDefenders** | QBot Lab | Memory Forensics | Volatility 3, VirusTotal | [View Writeup](CyberDefenders/QBot%20Lab/Writeup.md) |
| **CyberDefenders** | Ramnit | Memory Forensics | Volatility 3, VirusTotal | [View Writeup](CyberDefenders/Ramnit/Writeup.md) |
| **CyberDefenders** | Redline | Memory Forensics | Volatility 3, VolWeb | [View Writeup](CyberDefenders/Redline/Writeup.md) |
| **CyberDefenders** | REvil - GOLD SOUTHFIELD Lab | Ransomware Analysis | Splunk, Triage | [View Writeup](CyberDefenders/REvil%20-%20GOLD%20SOUTHFIELD%20Lab/Writeup.md) |
| **CyberDefenders** | TeamCity CVE-2024-27198 | Web / Network | Wireshark | [View Writeup](CyberDefenders/TeamCity/Writeup.md) |
| **CyberDefenders** | The Crime Lab | Android Forensics | ALEAPP, SQLite | [View Writeup](CyberDefenders/The%20Crime%20Lab/Writeup.md) |
| **CyberDefenders** | Tomcat Takeover Lab | Network Forensics | Wireshark, NetworkMiner | [View Notes](CyberDefenders/Tomcat%20Takeover%20Lab/README.md) |
| **CyberDefenders** | Volatility Traces | Memory Forensics | Volatility 3 | [View Writeup](CyberDefenders/Volatility_Traces/Volatility_Traces_Writeup.md) |
| **CyberDefenders** | XXE Infiltration Lab | Web / PCAP | Wireshark | [View Writeup](CyberDefenders/XXE%20Infiltration%20Lab/Writeup.md) |
| **CyberDefenders** | Yellow RAT Lab | Threat Intelligence | VirusTotal, Red Canary | [View Writeup](CyberDefenders/Yellow%20RAT%20lab/Writeup.md) |
| **TryHackMe** | AI Forensics | Log Analysis | Bash, grep | [View Writeup](TryHackMe/AI%20Forensics/Writeup.md) |
| **TryHackMe** | Block | Network / Credential Access | Wireshark, Pypykatz | [View Writeup](TryHackMe/Block/Block%20Writeup%20THM.md) |
| **TryHackMe** | Fools Mate | Web / API Security | DevTools, curl | [View Writeup](TryHackMe/Fools%20Mate/Writeup.md) |
| **TryHackMe** | Letter | OSINT | Image Analysis, BnF Archives | [View Notes](TryHackMe/Letter/README.md) |
| **TryHackMe** | Overheard at Breakfast | OSINT (Byte Lotus) | Gravatar, CyberChef | [View Writeup](TryHackMe/Overheard%20at%20Breakfast/Writeup.md) |
| **TryHackMe** | PackedLight | Network Forensics (Byte Lotus) | Wireshark, Tshark, Python | [View Writeup](TryHackMe/PackedLight/Writeup.md) |
| **TryHackMe** | The Brochure | OSINT (Byte Lotus) | Google, Instagram, CyberChef | [View Writeup](TryHackMe/TheBrochure/Writeup.md) |
| **Root-Me** | ETHERNET - frame | Network Frame Analysis | CyberChef, Hex Viewer | [View Writeup](Root-Me/ETHERNET%20-%20frame/Writeup.md) |
| **Root-Me** | FTP and Telnet - authentication | Network Forensics | Wireshark, Tshark | [View Writeup](Root-Me/FTP%20and%20Telnet%20-%20authentication/Writeup.md) |
| **Root-Me** | Kerberos - Pre-Authentication | Network / AD | Krb5RoastParser, Hashcat | [View Writeup](Root-Me/Kerberos%20-%20Pre-Authentication/Writeup.md) |
| **Root-Me** | TELNET - authentication | Cleartext Protocols | Wireshark | [View Writeup](Root-Me/TELNET%20-%20authentication/Writeup.md) |
| **SOC-Simulator** | LNK-in-Archive PowerShell Phishing | SOC Incident Triage | SIEM, Event Logs | [View Writeup](SOC-Simulator/LNK-in-Archive%20PowerShell%20Phishing/Writeup.md) |
