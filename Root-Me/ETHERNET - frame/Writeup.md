# ETHERNET - frame — Root-Me Writeup

**Platform:** Root-Me  
**Category:** Network / Frame Analysis  
**Tools:** CyberChef, Hex Editor  
**Credentials / Flag:** `confi:dential`  

---

## Connected Investigations
- **Network Protocol Analysis:** Compare with [Root-Me: TELNET - authentication](<../TELNET - authentication/Writeup.md>) and [Root-Me: FTP and Telnet - authentication](<../FTP and Telnet - authentication/Writeup.md>), analyzing unencrypted legacy network protocols.

---

## Challenge Overview

The challenge presents a raw hexadecimal dump of a single captured Ethernet network frame. The objective is to parse the frame, extract the encapsulated application-layer payload, and recover the transmitted authentication credentials.

---

## Walkthrough

### 1. Analyzing the Hex Dump

The challenge provides the following raw hexadecimal byte sequence representing an Ethernet frame:

![Raw hexadecimal dump of the Ethernet frame](images/Pasted%20image%2020260911075845.png)

```text
00 05 73 a0 00 00 e0 69 95 d8 5a 13 86 dd 60 00
00 00 00 9b 06 40 26 07 53 00 00 60 2a bc 00 00
00 00 ba de c0 de 20 01 41 d0 00 02 42 33 00 00
00 00 00 00 04 96 74 00 50 bc ea 7d b8 00 c1 ...
```

Inspecting the frame header:
- **EtherType `0x86DD`:** Indicates an **IPv6** packet encapsulated within the Ethernet frame.
- **Protocol `0x06`:** Encapsulates a **TCP** segment over IPv6.

---

### 2. Converting Hex to ASCII

Loading the hex bytes into CyberChef using the **From Hex** recipe converts the raw byte stream to ASCII text:

![CyberChef From Hex recipe](images/Pasted%20image%2020260911080008.png)

The decoded ASCII stream reveals an HTTP request:

```http
GET / HTTP/1.1
Authorization: Basic Y29uZmk6ZGVudGlhbA==
User-Agent: InsaneBrowser
Host: www.myipv6.org
Accept: */*
```

---

### 3. Decoding the HTTP Basic Authentication Header

The `Authorization` header contains an HTTP Basic Authentication string encoded in Base64:

```text
Y29uZmk6ZGVudGlhbA==
```

Applying the **From Base64** recipe in CyberChef:

![Base64 decoding the Authorization header](images/Pasted%20image%2020260911080035.png)

```bash
echo -n "Y29uZmk6ZGVudGlhbA==" | base64 -d
# confi:dential
```

The decoded credentials follow the standard `username:password` format:
- **Username:** `confi`
- **Password:** `dential`
- **Validation Token:** `confi:dential`

---

## Summary

| Layer | Protocol | Decoded Artifact |
| :--- | :--- | :--- |
| **Layer 2 (Data Link)** | Ethernet | EtherType `0x86DD` |
| **Layer 3 (Network)** | IPv6 | Destination host `www.myipv6.org` |
| **Layer 4 (Transport)** | TCP | Port 80 (HTTP) |
| **Layer 7 (Application)** | HTTP | Header `Authorization: Basic Y29uZmk6ZGVudGlhbA==` |
| **Credentials / Flag** | Basic Auth | `confi:dential` |
