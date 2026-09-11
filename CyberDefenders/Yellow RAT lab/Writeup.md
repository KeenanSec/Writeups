# Yellow RAT Lab — CyberDefenders Writeup

**Category:** Threat Intelligence / Malware Analysis  
**Platform:** CyberDefenders  
**Malware Family:** Yellow Cockatoo RAT (SolarMarker / Jupyter)  
**Tools:** VirusTotal, Threat Intelligence Repositories, Red Canary Intelligence Reports  

---

## Connected Investigations
- **Threat Intelligence & Sandbox Triage:**
  - [CyberDefenders: IcedID](<../IcedID/Writeup.md>) — Pivoting on macro droppers, dropped payloads, and threat group attributions.
  - [CyberDefenders: Dana Bot Lab](<../Dana Bot Lab/Writeup.md>) — Deobfuscating script droppers and secondary DLL payloads.

---

## Scenario Overview

In this lab, an analyst investigates abnormal network traffic and anomalous endpoint activity tied to the **Yellow Cockatoo RAT** (also widely tracked by industry researchers as **SolarMarker** or **Jupyter**). Starting with a raw file hash (`hash.txt`), we query VirusTotal and published threat reports (Red Canary) to identify the malware taxonomy, common dropped filenames, compilation timestamps, first submission dates, persistent AppData artifacts, and active Command and Control (C2) domains.

---

## Walkthrough

### Q1 — Identifying the Malware Family

Extracting the cryptographic hash from `hash.txt` and querying VirusTotal:

![Opening hash.txt to retrieve sample hash](images/Pasted%20image%2020260729200839.png)

Inspecting the **Community** and detection tags identifies the malware family:

![VirusTotal Community tab identifying Yellow Cockatoo RAT](images/Pasted%20image%2020260729202346.png)

- **Question:** What is the name of the malware family that causes abnormal network traffic?  
- **Answer:** `Yellow Cockatoo RAT`

---

### Q2 — Common Dropped Filename

Reviewing common file names associated with the hash on VirusTotal under the **Details** tab:

![VirusTotal Details tab displaying common filename](images/Pasted%20image%2020260729202609.png)

- **Question:** What is the common filename associated with the malware discovered on our workstations?  
- **Answer:** `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`

---

### Q3 — PE Compilation Timestamp

Inspecting the Portable Executable (PE) header metadata on VirusTotal:

![VirusTotal PE header compilation timestamp](images/Pasted%20image%2020260729202856.png)

The compile time is recorded as `2020-09-24 18:26:47 UTC`:

- **Question:** What is the compilation timestamp of the malware that infected our network?  
- **Answer:** `2020-09-24 18:26`

---

### Q4 — First VirusTotal Submission Date

Checking the **History** section on VirusTotal for the initial public submission timestamp:

![VirusTotal submission history](images/Pasted%20image%2020260729203026.png)

The earliest submission occurred on `2020-10-15 02:47:37 UTC`:

- **Question:** When was the malware first submitted to VirusTotal?  
- **Answer:** `2020-10-15 02:47`

---

### Q5 — Dropped AppData Component (`.dat` File)

Reviewing Red Canary threat intelligence reports on SolarMarker / Yellow Cockatoo execution patterns:

![Google search for Yellow Cockatoo threat report](images/Pasted%20image%2020260729203322.png)
![Threat report detailing solarmarker.dat dropped in AppData](images/Pasted%20image%2020260729203711.png)

The report documents that the malware writes a encrypted configuration / staging file into the user's `AppData` directory:

- **Question:** What is the name of the .dat file that the malware dropped in the AppData folder?  
- **Answer:** `solarmarker.dat`

---

### Q6 — Command and Control (C2) Server

Auditing network communications and memory pattern indicators on VirusTotal:

![VirusTotal network communication showing C2 domain](images/Pasted%20image%2020260729203906.png)

Under **Memory Pattern Domains** and **Memory Pattern URLs**, the sample beacons to:

- **Question:** What is the C2 server that the malware is communicating with?  
- **Answer:** `gogohid.com`

---

## Summary of Findings

| Artifact / Indicator | Value |
| :--- | :--- |
| **Malware Family** | `Yellow Cockatoo RAT` (SolarMarker / Jupyter) |
| **Common Binary Name** | `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll` |
| **Compilation Timestamp** | `2020-09-24 18:26` |
| **First Submission** | `2020-10-15 02:47` |
| **Dropped AppData File** | `solarmarker.dat` |
| **C2 Domain** | `gogohid.com` |
