# TELNET - authentication — Root-Me Writeup

**Platform:** Root-Me  
**Category:** Network / Cleartext Protocols  
**Tools:** Wireshark, TCP Stream Analysis  
**Credentials / Flag:** `user` (Account: `fake`)  

---

## Connected Investigations
- **Legacy Cleartext Protocols:** Compare with [Root-Me: FTP and Telnet - authentication](<../FTP and Telnet - authentication/Writeup.md>), which also captures unencrypted credentials transmitted over FTP and Telnet sessions.
- **Network Packet Analysis:** Compare with [Root-Me: ETHERNET - frame](<../ETHERNET - frame/Writeup.md>).

---

## Challenge Overview

The objective of this challenge is to inspect a network packet capture containing administrative Telnet communications. Because Telnet does not employ encryption, all terminal inputs—including usernames and passwords—are transmitted across the wire in plaintext.

---

## Walkthrough

### 1. Protocol Hierarchy & Traffic Filtering

Opening the capture file in Wireshark and checking `Statistics > Protocol Hierarchy` confirms the presence of Telnet traffic (TCP Port 23). Applying the display filter:

```text
telnet
```

---

### 2. Following the TCP Stream

Because Telnet transmits keystrokes interactively packet-by-packet, following the complete TCP conversation (`Right-click packet > Follow > TCP Stream`) reconstructs the terminal session:

![Wireshark Follow TCP Stream showing Telnet login](images/Pasted%20image%2020260911075318.png)

### 3. Analyzing the Captured Session

The reconstructed session displays an OpenBSD terminal login prompt:

```text
OpenBSD/i386 (oof) (ttyp1)

login: fake
Password: user
```

- **Banner:** `OpenBSD/i386 (oof) (ttyp1)`
- **Username:** `fake` (echoed character-by-character: `f`, `a`, `k`, `e`)
- **Password:** `user`

Submitting the recovered password validates the challenge.

---

## Key Takeaway

Telnet transmits authentication credentials and session data in cleartext without cryptographic protection. Modern network management should universally enforce secure, encrypted protocols such as SSH (Secure Shell) to prevent passive packet sniffing and credential harvesting.
