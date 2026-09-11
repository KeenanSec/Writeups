# PackedLight - TryHackMe Writeup

**Category:** Network Forensics / Malware Analysis  
**Platform:** TryHackMe  
**Series:** [The Byte Lotus Resort CTF Series](<../TheBrochure/Writeup.md>)  
**Tools:** Wireshark, Tshark, Python  
**Flag:** `THM{V3r4_1s_w4tch1ng_0veR_y0u}`  

---

## Connected Investigations
This challenge is the final installment of the **Byte Lotus Resort** storyline on TryHackMe:
- **Part 1 — [The Brochure](<../TheBrochure/Writeup.md>)**: OSINT discovery of Vera the Concierge (`@veratheconcierge`) leaking Base64 fragments on Instagram.
- **Part 2 — [Overheard at Breakfast](<../Overheard at Breakfast/Writeup.md>)**: OSINT investigating employee email `lambobytelotushotel@gmail.com` via Gravatar profile hashes.
- **Part 3 — PackedLight** (Current): Network Forensics on `traffic.pcapng` tracking C2 communications to `http://byte-lotus-hotel.thm:8080/`, reverse-engineering the keylogger script `updates.py`, and decrypting XOR-encoded keystrokes exfiltrated in HTTP cookies to recover the flag `THM{V3r4_1s_w4tch1ng_0veR_y0u}`.

---

## Overview

In this forensic scenario, we are provided with a network capture (`traffic.pcapng`) containing suspicious traffic originating from a workstation at the Byte Lotus Hotel. By analyzing HTTP transactions in Wireshark, we extract a malicious Python payload (`updates.py`) dropped onto the endpoint. Analysis of the payload reveals it to be a keylogger that XOR-encrypts individual keystrokes with a hardcoded key and exfiltrates them in the `hotel_sess_state` HTTP cookie. Using `tshark` to dump the sequential cookie values and a custom Python decoder, we reconstruct the captured keystrokes and extract the flag.

---

## Walkthrough

### 1. Initial Traffic Triage

Filtering for HTTP traffic in Wireshark identifies web communications with external server `34.41.103.191` over port `8080`:

![HTTP traffic analysis in Wireshark](images/Pasted%20image%2020260831033500.png)

---

### 2. Identifying and Exporting the Dropped Payload

Inspecting the HTTP objects (`File > Export Objects > HTTP`), an endpoint downloads a Python script named `updates.py`:

![Exporting updates.py from Wireshark](images/Pasted%20image%2020260831034106.png)

The delivery timestamp shows when the victim machine retrieved the payload from the web server:

![Payload delivery timestamp](images/Pasted%20image%2020260831034538.png)

---

### 3. Analyzing the Malicious Script (`updates.py`)

Opening the exported `updates.py` script reveals its core logic:

![Inspecting updates.py](images/Pasted%20image%2020260831034328.png)

Key components identified in the script:
- **C2 Server:** `http://byte-lotus-hotel.thm:8080/`
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ByteLotusClient/1.1`
- **Encryption Key:** Concatenation of `H0t3lSt@ff0Nly` + `K3epS3cr3t!` $\rightarrow$ `H0t3lSt@ff0NlyK3epS3cr3t!`
- **Exfiltration Mechanism:** For every keystroke captured by `pynput.keyboard`, the character is XOR-encrypted with the key, Base64-encoded, and sent via an HTTP GET request inside the `hotel_sess_state` cookie:
  ```python
  headers = {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ByteLotusClient/1.1",
      "Cookie": f"hotel_sess_state={b64_string}"
  }
  ```

---

### 4. Isolating C2 Exfiltration Traffic

To track all subsequent exfiltration requests sent to the C2 endpoint, we apply the Wireshark display filter:

```text
http contains "http://byte-lotus-hotel.thm:8080/"
```

![Filtering C2 traffic](images/Pasted%20image%2020260831034847.png)

Each GET request carries one keystroke in the `hotel_sess_state` cookie:

![Single key exfiltration in cookie](images/Pasted%20image%2020260831035624.png)

---

### 5. Extracting Sequential Cookies with Tshark

To extract the sequential cookies efficiently in chronological order from `traffic.pcapng`, we use `tshark`:

```bash
tshark -r traffic.pcapng -Y 'http.request.method == "GET" && http.cookie contains "hotel_sess_state"' -T fields -e http.cookie
```

![Tshark extracting hotel_sess_state cookies](images/Pasted%20image%2020260831040344.png)

---

### 6. Decrypting the Keystrokes & Flag Extraction

Since the keylogger encrypts each keystroke individually:
- Each single character `b` is XOR-masked with the first byte of the key: `key[0]` (`'H'`).
- The result is then Base64-encoded.

We decode each Base64 cookie value and XOR it with `key[0]` using `decodeUpdates.py`:

```python
import base64

key = b"H0t3lSt@ff0NlyK3epS3cr3t!"

cookie_raw = """
hotel_sess_state=HA==
hotel_sess_state=AA==
hotel_sess_state=BQ==
hotel_sess_state=Mw==
hotel_sess_state=Hg==
hotel_sess_state=ew==
hotel_sess_state=Og==
hotel_sess_state=fA==
hotel_sess_state=Fw==
hotel_sess_state=eQ==
hotel_sess_state=Ow==
hotel_sess_state=Fw==
hotel_sess_state=Pw==
hotel_sess_state=fA==
hotel_sess_state=PA==
hotel_sess_state=Kw==
hotel_sess_state=IA==
hotel_sess_state=eQ==
hotel_sess_state=Jg==
hotel_sess_state=Lw==
hotel_sess_state=Fw==
hotel_sess_state=eA==
hotel_sess_state=Pg==
hotel_sess_state=LQ==
hotel_sess_state=Gg==
hotel_sess_state=Fw==
hotel_sess_state=MQ==
hotel_sess_state=eA==
hotel_sess_state=PQ==
hotel_sess_state=NQ==
"""

decoded_chars = []

for line in cookie_raw.strip().splitlines():
    if not line.strip():
        continue
    b64_val = line.split("hotel_sess_state=")[-1].strip()
    enc_byte = base64.b64decode(b64_val)
    orig_char = bytes([enc_byte[0] ^ key[0]]).decode("utf-8", errors="ignore")
    decoded_chars.append(orig_char)

result = "".join(decoded_chars)
print(f"Decoded Output:\n{result}")
```

Running the decryption script:

```bash
python3 decodeUpdates.py
```

**Output:**
```text
Decoded Output:
THM{V3r4_1s_w4tch1ng_0veR_y0u}
```

---

## Summary of Key Artifacts

| Artifact | Details |
| :--- | :--- |
| **C2 Domain / URL** | `http://byte-lotus-hotel.thm:8080/` |
| **C2 IP Address** | `34.41.103.191` |
| **Dropped Script** | `updates.py` (Python `pynput` keylogger) |
| **Exfiltration Header** | Cookie `hotel_sess_state=<base64>` |
| **XOR Encryption Key** | `H0t3lSt@ff0NlyK3epS3cr3t!` |
| **Recovered Flag** | `THM{V3r4_1s_w4tch1ng_0veR_y0u}` |
