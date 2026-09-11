# PsExec Lateral Movement Analysis — CyberDefenders Writeup

**Category:** Network Forensics / Lateral Movement  
**Platform:** CyberDefenders  
**Tools:** Wireshark, SMB2 Protocol Analysis  

---

## Connected Investigations
- **SMB Traffic & Lateral Movement:** Compare with [TryHackMe: Block](<../../TryHackMe/Block/Block Writeup THM.md>) (decrypting encrypted SMB3 traffic and dumping LSASS credentials) and [CyberDefenders: GoldenSpray Lab](<../GoldenSpray Lab/Writeup.md>) (Active Directory domain lateral movement).

---

## Scenario Overview

During an internal security incident, an adversary performed lateral movement across the enterprise Windows network using the Sysinternals **PsExec** utility. PsExec operates by connecting to network shares over SMB (Port 445), dropping a service executable (`PSEXESVC.exe`) onto the administrative share (`ADMIN$`), creating a Windows service remotely via RPC, and establishing named pipes over the Inter-Process Communication share (`IPC$`) to redirect standard input, standard output, and standard error streams across the network.

---

## Walkthrough

### 1. Identifying the Service Executable via SMB Object Export

To detect binaries transferred across the network over SMB, navigate to **File > Export Objects > SMB / SMB2** in Wireshark:

![Exporting SMB objects in Wireshark](images/Pasted%20image%2020260728043335.png)

The capture shows the transfer of `PSEXESVC.exe` to the remote target host:

- **Malicious Service Binary:** `PSEXESVC.exe`

---

### 2. Identifying Administrative Share Access

Applying the Wireshark filter `smb2.tree` isolates tree connection requests used by the attacker to connect to target shares:

![Wireshark filter smb2.tree showing share connections](images/Pasted%20image%2020260728045748.png)

The attacker connects to:
- **`ADMIN$`:** The default administrative share mapping to `C:\Windows`. PsExec copies `PSEXESVC.exe` into this directory to register the service.
- **`IPC$`:** Inter-Process Communication share used for RPC and named pipe redirection.

---

### 3. Communication Channel & Named Pipes

Following the SMB transactions reveals named pipes dedicated to command execution and terminal I/O redirection:

![SMB named pipe traffic for stdin, stdout, and stderr](images/Pasted%20image%2020260728050848.png)

- **`stdin` pipe:** Delivers command instructions from the attacker to the remote service.
- **`stdout` pipe:** Streams command execution output back to the attacker's console.
- **`stderr` pipe:** Returns error logs and diagnostic messages.

---

### 4. Identifying the Target Workstation

Filtering for SMB traffic originating from the adversary's IP address:

![Filtering SMB traffic from the attacker IP](images/Pasted%20image%2020260728052650.png)

Following the TCP stream of the connection establishes the identity of the targeted network workstation share:

![TCP stream confirming connection to MARKETING-PC$](images/Pasted%20image%2020260728052720.png)

- **Target Workstation Share:** `MARKETING-PC$`

---

## Summary of Findings

| Indicator / Artifact | Value | Forensic Significance |
| :--- | :--- | :--- |
| **Service Executable** | `PSEXESVC.exe` | Dropped binary used to execute remote commands |
| **Target Share for Staging** | `ADMIN$` | Default Windows administrative share (`C:\Windows`) |
| **Control Channel Share** | `IPC$` | Named pipes for I/O (`stdin`, `stdout`, `stderr`) |
| **Target Host Share** | `MARKETING-PC$` | Compromised endpoint receiving remote execution |
