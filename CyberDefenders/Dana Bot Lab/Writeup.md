# Dana Bot Lab — CyberDefenders Writeup

**Category:** Malware Analysis / Network Forensics  
**Platform:** CyberDefenders  
**Malware Family:** DanaBot  
**Tools:** Wireshark, VirusTotal, JavaScript Deobfuscation  

---

## Connected Investigations
- **Malware Loaders & Stage-2 Droppers:**
  - [CyberDefenders: IcedID](<../IcedID/Writeup.md>) — Analyzing malicious initial access documents downloading secondary payloads.
  - [CyberDefenders: Amadey](<../Amadey/README.md>) — Modular loader infection chain and process injection.
  - [SOC-Simulator: LNK-in-Archive PowerShell Phishing](<../../SOC-Simulator/LNK-in-Archive PowerShell Phishing/Writeup.md>) — Phishing lures triggering scripting engine execution.

---

## Scenario Overview

In this forensic lab, an adversary executed a multi-stage malware campaign deploying **DanaBot**. By analyzing captured network packets and endpoint artifacts, we reconstruct the attack chain: uncovering the attacker's initial access IP address, extracting the weaponized JavaScript attachment (`allegato_708.js`), calculating its cryptographic hash, analyzing its execution via `wscript.exe`, and tracing the secondary payload download of a malicious `.dll`.

---

## Walkthrough

### Q1 — Attacker IP Address for Initial Access

Examining HTTP transactions in the network capture reveals external communications delivering the malicious stage-1 script:

> **Question:** Which IP address was used by the attacker during the initial access?  
> **Answer:** `62.173.142.148`

---

### Q2 — Malicious File Used for Initial Access

Reviewing the exported HTTP objects in Wireshark (`File > Export Objects > HTTP`):

![Exporting initial access file from Wireshark](images/Pasted%20image%2020260804184701.png)

The victim endpoint downloaded a malicious JavaScript file:

> **Question:** What is the name of the malicious file used for initial access?  
> **Answer:** `allegato_708.js`

---

### Q3 — SHA-256 Hash of the Initial Access File

Exporting the file `allegato_708.js` and calculating its SHA-256 hash:

![Exporting HTTP object](images/Pasted%20image%2020260804173118.png)
![Calculating SHA-256 hash](images/Pasted%20image%2020260804173255.png)

Querying the hash on VirusTotal confirms malicious detection for DanaBot:

![VirusTotal detection for allegato_708.js](images/Pasted%20image%2020260804184850.png)

> **Question:** What is the SHA-256 hash of the malicious file used for initial access?  
> **Answer:** `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

---

### Q4 — Process Used to Execute the Malicious Script

Deobfuscating the downloaded JavaScript file reveals references to Windows Script Host (`WScript`):

![Deobfuscated JavaScript snippet showing WScript](images/Pasted%20image%2020260804175336.png)

Inspecting the endpoint process tree confirms that `wscript.exe` executed the script:

![Process tree showing execution via wscript.exe](images/Pasted%20image%2020260804181509.png)

> **Question:** Which process was used to execute the malicious file?  
> **Answer:** `wscript.exe`

---

### Q5 — File Extension of the Secondary Payload

Analyzing subsequent network downloads initiated by the script:

![Capturing secondary payload download](images/Pasted%20image%2020260804182046.png)

The script connects to remote infrastructure to fetch a dynamic link library (`.dll`) payload:

> **Question:** What is the file extension of the second malicious file utilized by the attacker?  
> **Answer:** `.dll`

---

### Q6 — MD5 Hash of the Second Malicious File

Extracting the downloaded `.dll` payload and inspecting its VirusTotal details tab:

![VirusTotal details tab displaying MD5 hash](images/Pasted%20image%2020260804182545.png)

> **Question:** What is the MD5 hash of the second malicious file?  
> **Answer:** `e758e07113016aca55d9eda2b0ffeebe`

---

## Summary of Key Artifacts

| Artifact / Indicator | Value | Description |
| :--- | :--- | :--- |
| **Attacker IP** | `62.173.142.148` | Initial delivery web server |
| **Initial Access File** | `allegato_708.js` | Weaponized JavaScript dropper |
| **Dropper SHA-256** | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` | Cryptographic signature |
| **Execution Engine** | `wscript.exe` | Windows Script Host binary |
| **Stage-2 Extension** | `.dll` | Dynamic Link Library binary |
| **Stage-2 MD5** | `e758e07113016aca55d9eda2b0ffeebe` | DanaBot core payload |
