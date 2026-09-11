# Block - TryHackMe Writeup

**Category:** Network Forensics / Credential Access  
**Platform:** TryHackMe  
**Tools:** Wireshark, Pypykatz, Python SMB Decryptor  
**Flags:** 
- `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}`
- `THM{No_PasSw0Rd?_No_Pr0bl3m}`

---

## Connected Investigations
- **SMB Lateral Movement & Analysis:** Compare with [CyberDefenders: Psexec](<../../CyberDefenders/Psexec/Writeup.md>), analyzing SMB tree connects, `ADMIN$`, and `IPC$` pipes.
- **LSASS Credential Dumping:** Compare with [CyberDefenders: GoldenSpray Lab](<../../CyberDefenders/GoldenSpray Lab/Writeup.md>) (Mimikatz dumping) and [CyberDefenders: PoisonedCredentials](<../../CyberDefenders/PoisonedCredentials/PoisonedCredentials.md>) (NTLMv2 hash harvesting).

---

## Executive Summary

The **Block** challenge provides a network capture (`.pcap`) and a Windows LSASS memory minidump (`lsass.DMP`). An attacker accessed the server using two distinct user credentials over SMB3. Because SMB3 traffic is encrypted in transit, standard packet inspection cannot read the transferred files. Using `pypykatz` against the LSASS dump, we extract the NTLM hashes, crack the plaintext password for `mrealman`, recover session keys from the Python decryption utility, and decrypt the SMB3 session in Wireshark to retrieve the secret files and flags.

---

## Walkthrough

### 1. Identifying the First User in Network Traffic

Inspecting the packet capture for SMB session setups and filtering for `\Workgroup` strings identifies the initial user account communicating with the server:

![Wireshark identifying first SMB user](Pasted%20image%2020240904200416.png)

> **What is the username of the first person who accessed our server?**  
> **Answer:** `mrealman`

---

### 2. Dumping LSASS & Recovering Plaintext Credentials

Running `pypykatz` against the provided `lsass.DMP` file dumps logon session details, revealing the NT hash for `mrealman`:

![Pypykatz dumping LSASS credentials](Pasted%20image%2020240904200553.png)

Cracking the recovered NT hash:

![Cracking NT hash](Pasted%20image%2020240904200632.png)

> **What is the password of the user in question 1?**  
> **Answer:** `Blockbuster1`

---

### 3. Decrypting SMB Traffic & Extracting Flag 1

Because the traffic uses SMB3 encryption, we derive the session encryption keys using the session information (`Session Key`, `UserName`, `Domain`, `Password`/`Hash`, and `NTProofStr`) following the technique outlined in the [TryHackMe SMB Decryption guide](https://snynr.medium.com/tryhackme-encryption-what-encryption-2eff5ca2f065).

Feeding these parameters into the SMB decryption script generates the decryption key for Wireshark:

![SMB decryption script execution](Pasted%20image%2020240904201446.png)

Configuring Wireshark with the session key under `Preferences > Protocols > SMB2` successfully decrypts the payload:

![Decrypted SMB packets in Wireshark](Pasted%20image%2020240904201207.png)

Exporting the decrypted SMB objects reveals the first secret file and flag:

> **What is the flag that the first user got access to?**  
> **Answer:** `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}`

---

### 4. Identifying the Second User Account

Filtering the packet capture for subsequent `\Workgroup` authentication traffic reveals a second user account:

![Second user in SMB traffic](Pasted%20image%2020240904201320.png)

> **What is the username of the second person who accessed our server?**  
> **Answer:** `eshellstrop`

---

### 5. Extracting Hash & Decrypting Flag 2

Checking the `pypykatz` dump output for `eshellstrop` reveals their NTLM hash:

![Pypykatz output for eshellstrop](Pasted%20image%2020240904201749.png)

> **What is the hash of the user in question 4?**  
> **Answer:** `3f29138a04aadc19214e9c04028bf381`

Even without cracking the plaintext password, we use the NTLM hash directly to derive the SMB3 session decryption key using the Python script. Applying the key decrypts the second session:

![Exported decrypted file containing flag 2](Pasted%20image%2020240904201014.png)

> **What is the flag that the second user got access to?**  
> **Answer:** `THM{No_PasSw0Rd?_No_Pr0bl3m}`

---

## Summary of Findings

| User Account | Password / Hash | Extracted Flag |
| :--- | :--- | :--- |
| `mrealman` | `Blockbuster1` | `THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}` |
| `eshellstrop` | `3f29138a04aadc19214e9c04028bf381` | `THM{No_PasSw0Rd?_No_Pr0bl3m}` |
