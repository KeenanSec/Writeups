# AI: Forensics - TryHackMe Writeup

**Category:** Digital Forensics & Incident Response (DFIR) / Log Analysis  
**Platform:** TryHackMe  
**Tools:** Bash, grep, cat, Linux CLI  

---

## Connected Investigations
- **Phishing Lure Analysis:** Compare with [SOC-Simulator: LNK-in-Archive PowerShell Phishing](<../../SOC-Simulator/LNK-in-Archive PowerShell Phishing/Writeup.md>), where malicious invoices were similarly weaponized to target employee inboxes.
- **Initial Access via Stolen Credentials:** Compare with [CyberDefenders: AWSRaid](<../../CyberDefenders/AWSRaid/AWSRaid - CloudTrail Incident Writeup.md>) and [CyberDefenders: AzureHunt](<../../CyberDefenders/AzureHunt/Writeup.md>) for authentication log hunting following initial user compromise.

---

## Overview

The **AI: Forensics** scenario simulates an incident response investigation on a compromised Linux endpoint (`tryhackme`). Attackers targeted employees via a spear-phishing campaign disguised as an urgent vendor invoice, subsequently performing unauthorized SSH logins from internal address `192.168.0.100`. The investigation involves analyzing mailbox records in `/home/j.morgan/Mail` and auditing SSH authentication logs (`auth.log`) to reconstruct the attacker's timeline and initial access vector.

---

## Walkthrough

### 1. Phishing Email & Attachment Triage

Navigating to user `j.morgan`'s mail spool directory (`/home/j.morgan/Mail/inbox`) and inspecting the incoming email message:

```bash
cat inbox/email_invoice
```

![Phishing email targeting j.morgan](images/Pasted%20image%2020260828203421.png)

**Email Metadata:**
- **Sender:** `"A. Keane" <akeane@poseidonenergy.net>`
- **Recipient:** `j.morgan@robbco.com`
- **Subject:** `URGENT - Outstanding Invoice Q1 2075`
- **Attachment:** `invoice_Q1_2075.ods`
- **Lure Strategy:** Urgent demand for immediate review of an overdue joint energy invoice, threatening administrative escalation.

---

### 2. Authentication & SSH Log Investigation

Examining the system authentication logs (`/var/log/auth.log`) reveals anomalous SSH connections originating from IP `192.168.0.100`:

![SSH authentication log analysis](images/Pasted%20image%2020260828203449.png)

Key timeline events recorded in the logs:
1. **Brute Force / Enumeration:** Attacker attempts password authentication for invalid user `admin` from `192.168.0.100` on port 22 (`sshd[1833]`).
2. **Initial Compromise (`03:01:02`):** Successful password authentication for compromised user `j.morgan` from `192.168.0.100`.
3. **Lateral / Secondary Access (`03:15:00`):** Public key authentication accepted for user `r.house` from the same host (`192.168.0.100`), indicating privilege escalation or secondary account access.

---

## Summary of Findings

| Indicator / Field | Value | Notes |
| :--- | :--- | :--- |
| **Phishing Sender** | `akeane@poseidonenergy.net` | Spoofed or compromised domain |
| **Victim Email** | `j.morgan@robbco.com` | Target of spear-phishing lure |
| **Malicious Attachment** | `invoice_Q1_2075.ods` | OpenDocument Spreadsheet lure |
| **Attacker Source IP** | `192.168.0.100` | Internal compromised pivoting host |
| **Compromised Account** | `j.morgan` | Password accepted at `03:01:02` |
| **Secondary Account** | `r.house` | SSH public key auth at `03:15:00` |
