# Kerberos - Pre-Authentication — Root-Me Writeup

**Platform:** Root-Me  
**Category:** Network / Active Directory Forensics  
**Tools:** Wireshark, Krb5RoastParser, Hashcat  
**Flag:** `RM{william.dupond:kittycat12}`  

---

## Connected Investigations
- **Active Directory & Kerberos Attacks:** Compare with [CyberDefenders: GoldenSpray Lab](<../../CyberDefenders/GoldenSpray Lab/Writeup.md>), analyzing Kerberos ticket request encryption types (`0x17` RC4-HMAC) and domain persistence.
- **Credential Access & Hash Cracking:** Compare with [CyberDefenders: PoisonedCredentials](<../../CyberDefenders/PoisonedCredentials/PoisonedCredentials.md>) (NTLMv2 hash cracking via Responder captures).

---

## Challenge Overview

Cat Corporation's SOC team detected suspicious Kerberos traffic on their corporate network (`CATCORP.LOCAL`). The objective is to analyze a network packet capture containing an encrypted Kerberos authentication handshake, extract the pre-authentication timestamp (`PA-ENC-TIMESTAMP`), format the hash for offline cracking, recover the victim user's plaintext password, and submit the flag in format `RM{userPrincipalName:password}`.

---

## Walkthrough

### 1. Packet Inspection & Kerberos AS-REQ Stream

Opening the capture file in Wireshark and filtering for Kerberos authentication exchanges (`kerberos`):

```text
kerberos
```

Following the TCP stream reveals the Kerberos `AS-REQ` (Authentication Service Request) packet:

![Kerberos AS-REQ packet stream](images/Pasted%20image%2020260911080945.png)

Inspecting the Kerberos fields:
- **Realm / Domain:** `CATCORP.LOCAL`
- **User Principal Name:** `william.dupond`
- **Service Name (sname):** `krbtgt / CATCORP.LOCAL`
- **Pre-Authentication Type:** `PA-ENC-TIMESTAMP` (Encrypted timestamp using the user's password-derived key)

---

### 2. Extracting the Pre-Authentication Hash

Kerberos pre-authentication requires the client to encrypt the current timestamp using a key derived from the user's password. If the encrypted timestamp is intercepted, an attacker can attempt offline dictionary attacks without sending further traffic to the Domain Controller.

Using [Krb5RoastParser](https://github.com/jalvarezz13/Krb5RoastParser), we extract the `PA-ENC-TIMESTAMP` structure from the packet capture and format it for **Hashcat**:

```bash
python3 krb5roastparser.py -p capture.pcap > hash.txt
```

---

### 3. Cracking with Hashcat (Mode 19900)

We execute Hashcat using hash mode **`19900`** (`Kerberos 5, etype 17/18, Pre-Auth`) against the `rockyou.txt` wordlist:

```bash
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashcat successfully cracks the hash:

![Challenge completion and validation](images/Pasted%20image%2020260911084308.png)

- **Cracked Password:** `kittycat12`
- **User Principal Name:** `william.dupond`

---

### 4. Constructing the Flag

The challenge specifies the flag format `RM{userPrincipalName:password}` with lowercase username:

```text
RM{william.dupond:kittycat12}
```

---

## Summary of Findings

| Field | Value |
| :--- | :--- |
| **Target Domain** | `CATCORP.LOCAL` |
| **Account Name** | `william.dupond` |
| **Kerberos Auth Type** | `PA-ENC-TIMESTAMP` |
| **Cracked Password** | `kittycat12` |
| **Hashcat Mode** | `19900` |
| **Flag** | `RM{william.dupond:kittycat12}` |
