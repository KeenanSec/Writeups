# XXE Infiltration Lab — CyberDefenders Writeup

**Category:** Web Application Forensics / PCAP Analysis  
**Platform:** CyberDefenders  
**Tools:** Wireshark, HTTP Stream Analysis, MySQL Protocol Inspection  

---

## Connected Investigations
- **Web Application Exploitation:** Compare with [TryHackMe: Fools Mate](<../../TryHackMe/Fools Mate/Writeup.md>) (client-side validation bypass) and [CyberDefenders: TeamCity CVE-2024-27198](<../TeamCity/Writeup.md>) (auth bypass via alternate URL paths).

---

## Scenario Overview

A web application hosting a book review service was targeted by an external attacker (`210.106.114.183`). The adversary identified an XML External Entity (XXE) injection vulnerability in the upload handler (`/review/upload.php`), leveraged it to read sensitive configuration files including `config.php`, exfiltrated local MySQL database credentials, authenticated directly to the database service on port 3306, and uploaded a persistent PHP web shell (`booking.php`).

---

## Walkthrough

### Q1 — Highest Open Port on the Victim Server

Inspecting network traffic between the attacker (`210.106.114.183`) and victim web server (`50.239.151.185`):

![Wireshark protocol and port inspection](images/Pasted%20image%2020260804210151.png)

In addition to HTTP (port 80), the victim exposes port `3306` (MySQL):

- **Answer:** `3306`

---

### Q2 — Vulnerable PHP Script URI

Filtering for XML content in HTTP POST traffic (`http.request.method == "POST"`):

![Locating vulnerable script upload endpoint](images/Pasted%20image%2020260804211306.png)

The attacker submits XML payloads to the review submission endpoint:

- **Answer:** `/review/upload.php`

---

### Q3 — First Malicious XML File Uploaded

Following the HTTP stream for the initial upload reveals a crafted XML document:

![Inspecting malicious XML payload in HTTP stream](images/Pasted%20image%2020260804211440.png)

- **Answer:** `TheGreatGatsby.xml`

---

### Q4 — Configuration File Read by Attacker

Reviewing subsequent XXE payloads containing external entity definitions (`<!ENTITY xxe SYSTEM "file:///var/www/html/...">`):

![XXE external entity file extraction payloads](images/Pasted%20image%2020260804212404.png)
![Payload accessing config.php](images/Pasted%20image%2020260804212537.png)
![Payload accessing system files](images/Pasted%20image%2020260804212617.png)

The entity payload extracts `/var/www/html/config.php`:

- **Answer:** `config.php`

---

### Q5 — Password for the Compromised Database User

Inspecting the server response containing the reflected entity content of `config.php`:

![Reflected config.php content containing MySQL credentials](images/Pasted%20image%2020260804213235.png)

The extracted PHP database configuration contains:

```php
$db_host = 'localhost';
$db_name = 'pageturner';
$db_user = 'webuser';
$db_pass = 'Winter2024';
```

- **Answer:** `Winter2024`

---

### Q6 — Timestamp of Initial MySQL Connection

Filtering for MySQL protocol traffic from the attacker IP (`mysql and ip.src == 210.106.114.183`):

![MySQL authentication packet timestamp](images/Pasted%20image%2020260804214159.png)

Following the exfiltration of `config.php` at 12:03 UTC, the attacker initiates an authenticated MySQL connection:

- **Answer:** `2024-05-31 12:08`

---

### Q7 — Uploaded Web Shell Filename

Searching for subsequent HTTP requests that execute system commands via parameter `cmd`:

![Web shell traffic executing remote commands](images/Pasted%20image%2020260804215124.png)

The attacker interacts with the uploaded backdoor script using `?cmd=...`:

- **Answer:** `booking.php`

---

## Summary of Findings

| Item | Value |
| :--- | :--- |
| **Attacker IP** | `210.106.114.183` |
| **Victim Web Server** | `50.239.151.185` |
| **Highest Exposed Port** | `3306` (MySQL) |
| **Vulnerable URI** | `/review/upload.php` |
| **Weaponized XML File** | `TheGreatGatsby.xml` |
| **Leaked Config File** | `config.php` |
| **Compromised DB Password** | `Winter2024` (User: `webuser`) |
| **MySQL Auth Timestamp** | `2024-05-31 12:08` |
| **Uploaded Web Shell** | `booking.php` |
