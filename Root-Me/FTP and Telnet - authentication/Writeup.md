# Network Forensics Mini-Writeup: FTP & Telnet Session Analysis

**Platform:** Root-Me  
**Category:** Network Forensics / Cleartext Protocols  
**Tools:** Wireshark, Tshark  
**Credentials Recovered:** `cdts3500:cdts3500`  

---

## Connected Investigations
- **Cleartext Protocol Triage:** Compare with [Root-Me: TELNET - authentication](<../TELNET - authentication/Writeup.md>) and [Root-Me: ETHERNET - frame](<../ETHERNET - frame/Writeup.md>).

---

## Overview
This writeup analyzes a captured communications trace (`ch1.pcap`) detailing an administrative session involving an FTP data extraction followed by an interactive Telnet session on an IBM i (OS/400) server.

---

## Session Details
- **Source IP (Client):** `10.20.144.150` [cite: 1]
- **Destination IP (Server):** `10.20.144.151` (`fran.csg.stercomm.com`) [cite: 1]
- **Target System:** OS/400 V5R2M0 [cite: 1]
- **Protocols Captured:** FTP (TCP Port 21) [cite: 1], Telnet (TCP Port 23) [cite: 1]

---

## Timeline of Events

| Timestamp | Protocol | Action / Event Description |
| :--- | :--- | :--- |
| **15:26:03** | TCP / FTP | Client establishes a connection to the FTP server; the server greets with banner `220-QTCP` [cite: 1]. |
| **15:26:07 - 15:26:11** | FTP | **Authentication:** User `cdts3500` logs in. Credentials are transmitted in **cleartext** (`USER cdts3500`, `PASS cdts3500`) [cite: 1]. |
| **15:26:11** | FTP | Client queries system details (`SYST`, `SITE NAMEFMT`, `PWD`), identifying the remote OS as OS/400 and working library as `CDTS3500` [cite: 1]. |
| **15:26:24** | FTP | Client initiates passive mode (`PASV`), opens a data channel, and retrieves database file member `qgpl/apkeyf.apkeyf` [cite: 1]. |
| **15:26:24** | Data Channel | File payload transferred, containing internal product licensing details, system models, and configuration hashes [cite: 1]. |
| **15:26:34** | FTP | Client sends `QUIT`, successfully terminating the FTP session [cite: 1]. |
| **15:26:39** | Telnet | Client opens a new interactive Telnet session (Port 23) to the same target [cite: 1]. |
| **15:26:40** | Telnet | OS/400 sign-on screen and main menu are negotiated and rendered [cite: 1]. |
| **15:26:49 - 15:26:53** | Telnet | Client executes the `WRKACTJOB` (Work with Active Jobs) command, inspecting active system subsystems, active jobs (`CDTS3400`, `CDTS3500`), and queue allocations [cite: 1]. |
| **15:26:57** | TCP | Telnet session gracefully closes [cite: 1]. |

---

## Security Implications
1. **Cleartext Authentication:** Both FTP and standard Telnet lack encryption. Network sniffers can easily capture user credentials (`cdts3500` / `cdts3500`), posing a severe risk of credential compromise [cite: 1].
2. **Data Exposure:** The file transfer revealed internal system architecture configurations, product versions, and licensing fingerprints without access control barriers once authenticated [cite: 1].