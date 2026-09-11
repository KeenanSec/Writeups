# PoisonedCredentials — CyberDefenders Writeup

**Category:** Network Forensics / Credential Access  
**Platform:** CyberDefenders  
**Organization:** CyberCactus (`cybercactus.local`)  
**Tools:** Wireshark, LLMNR/NBT-NS Triage  

---

## Connected Investigations
- **Organization Tenant Overlap:** Shares the **CyberCactus** environment with [CyberDefenders: AzureHunt](<../AzureHunt/Writeup.md>) (`cybercactus.onmicrosoft.com`).
- **Active Directory & Credential Abuse:**
  - [CyberDefenders: GoldenSpray Lab](<../GoldenSpray Lab/Writeup.md>) — Password spraying against AD accounts and domain persistence.
  - [CyberDefenders: Psexec](<../Psexec/Writeup.md>) — Tracking SMB authentication and lateral movement.
  - [TryHackMe: Block](<../../TryHackMe/Block/Block Writeup THM.md>) — Decrypting SMB traffic with extracted NTLM hashes.

---

## Scenario Overview

Adversaries on an internal subnet can weaponize LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) broadcast requests when endpoints attempt to resolve mistyped network share or printer names. By deploying tools like Responder to poison these resolution requests, the attacker tricks victim machines into authenticating against the rogue host, harvesting NTLMv2 password hashes across the wire.

In this investigation, we analyze `PoisonedCredentials.pcap` to identify mistyped queries, locate the rogue poisoning host, identify impacted victim systems, and track subsequent SMB access against target workstations.

---

## Summary of Key Entities

| Role | IP Address | Hostname / Details |
| :--- | :--- | :--- |
| **Rogue Attacker Host** | `192.168.232.215` | Responding to poisoned broadcasts |
| **First Victim Host** | `192.168.232.162` | Queried `fileshaare` |
| **Second Victim Host** | `192.168.232.176` | Queried `prinetr`, compromised account `janesmith` |
| **Compromised Target Host** | `192.168.232.176` | `ACCOUNTINGPC` (`cybercactus.local`) |

---

## Walkthrough

### Q1 — Identifying the Mistyped Resolution Query

When Windows endpoints cannot resolve a hostname via DNS, they broadcast LLMNR and NBT-NS queries across the local subnet. Applying the Wireshark filter:

```text
llmnr and ip.src == 192.168.232.162
```

![LLMNR query showing mistyped fileshaare string](images/Pasted%20image%2020260729002208.png)

The victim host queries for a misspelled share name:

> **Question:** Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?  
> **Answer:** `fileshaare`

---

### Q2 — IP Address of the Rogue Poisoning Machine

Filtering for LLMNR responses claiming to be the authoritative host for `fileshaare`:

![Rogue host poisoning LLMNR query](images/Pasted%20image%2020260729003528.png)

Host `192.168.232.215` repeatedly sends rogue resolution responses to `192.168.232.162`, poisoning the name resolution cache:

> **Question:** What is the IP address of the machine acting as the rogue entity?  
> **Answer:** `192.168.232.215`

---

### Q3 — Second Affected Machine Receiving Poisoned Responses

To detect other victim machines poisoned by the rogue host, we filter for outbound LLMNR responses from `192.168.232.215`:

```text
ip.src == 192.168.232.215 and llmnr
```

![Second victim machine poisoned for mistyped prinetr](images/Pasted%20image%2020260729003917.png)

The rogue machine responded to host `192.168.232.176`, which was attempting to resolve the mistyped printer name `prinetr`:

> **Question:** What is the IP address of the second machine that received poisoned responses from the rogue machine?  
> **Answer:** `192.168.232.176`

---

### Q4 — Compromised User Account Username

Filtering for NTLM authentication exchanges (`ntlmssp.auth.username`):

```text
ntlmssp.auth.username
```

![NTLM authentication exchange identifying janesmith](images/Pasted%20image%2020260729004829.png)

Following the poisoned response, victim machine `192.168.232.176` initiated an SMB connection to the attacker and transmitted authentication credentials for user `janesmith`:

> **Question:** What is the username of the account that the attacker compromised?  
> **Answer:** `janesmith`

---

### Q5 — Target Machine Hostname Accessed via SMB

Following the SMB2 TCP stream (`tcp.stream eq 11`) between the attacker (`192.168.232.215`) and the victim (`192.168.232.176`):

![NTLMSSP Challenge packet displaying Target Info and NetBIOS name](images/Pasted%20image%2020260729010027.png)

Inspecting the **NTLMSSP Challenge** packet (`Target Info` structure):
- **NetBIOS Domain Name:** `CYBERCACTUS`
- **NetBIOS Computer Name:** `ACCOUNTINGPC`
- **DNS Hostname:** `AccountingPC.cybercactus.local`

> **Question:** What is the hostname of the machine that the attacker accessed via SMB?  
> **Answer:** `ACCOUNTINGPC`

---

## Summary of Findings

| Item | Value |
| :--- | :--- |
| **Initial Mistyped Query** | `fileshaare` |
| **Rogue Attacker IP** | `192.168.232.215` |
| **Second Victim IP** | `192.168.232.176` |
| **Second Mistyped Query** | `prinetr` |
| **Compromised User Account** | `janesmith` |
| **Target Hostname** | `ACCOUNTINGPC` |
| **Domain** | `cybercactus.local` |
