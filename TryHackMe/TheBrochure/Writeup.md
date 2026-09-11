# The Brochure - TryHackMe Writeup

**Category:** OSINT  
**Platform:** TryHackMe  
**Series:** [The Byte Lotus Resort CTF Series](<../Overheard at Breakfast/Writeup.md>)  
**Flag:** `THM{V3r@z_aCC0unt_h4s_is3n_f0und!}`  

---

## Connected Investigations
This challenge is part of the overarching **Byte Lotus Resort** storyline on TryHackMe:
- **Part 1 — The Brochure** (Current): OSINT discovery of Vera the Concierge's public footprint and social media leakage.
- **Part 2 — [Overheard at Breakfast](<../Overheard at Breakfast/Writeup.md>)**: OSINT investigating employee email `lambobytelotushotel@gmail.com` via Gravatar profile hashes.
- **Part 3 — [PackedLight](<../PackedLight/Writeup.md>)**: Network Forensics tracking C2 beacons to `http://byte-lotus-hotel.thm:8080/` and decrypting XOR-encoded keylogger exfiltration.

---

## Overview

The challenge provides a brochure image (`thebrochure.png`) from "Byte Lotus Resorts". Inspecting the brochure text introduces Vera, the hotel concierge. Using OSINT search techniques, we identify Vera's public Instagram profile, extract three encoded image fragments from recent posts, reconstruct the segmented Base64 payload, and decode it to retrieve the flag.

---

## Walkthrough

### 1. Analyzing the Initial Artifact
Inspecting the provided brochure image reveals branding for **Byte Lotus Resorts** and references to hotel staff, specifically the concierge named **Vera**.

### 2. Search Engine Reconnaissance
Querying search engines with the keywords identified from the brochure:

```text
byte lotus resorts vera
```

![Google search results for Byte Lotus Resorts Vera](images/Pasted%20image%2020260831042502.png)

The search results reveal:
- A writeup snippet referencing *"The Byte Lotus Resort - An OSINT Journey"*, confirming Vera as the hotel concierge.
- An active Instagram profile under the handle **`@veratheconcierge`** with the bio *"Currently working for Byte Lotus Hotel."*

---

### 3. Locating the Instagram Profile
Navigating to Vera's Instagram profile (`@veratheconcierge`), we find 3 recent image posts displaying characters formatted in an unusual style:

![Instagram profile @veratheconcierge](images/Pasted%20image%2020260831042509.png)

---

### 4. Viewing Posts via an External Profile Viewer
To inspect the posts at full resolution without requiring an active Instagram session, an open profile viewer was used:

![Inspecting post images via profile viewer](images/Pasted%20image%2020260831042622.png)

Each post contains an individual segment of an encoded Base64 string:
- **Segment 1:** `VEhNe1YzckBzX2FDQz`
- **Segment 2:** `B1bnRfaDRzX2lzM25f`
- **Segment 3:** `ZjB1bmQhfQ==`

---

### 5. Reconstructing and Decoding the Payload
Concatenating the three segments in chronological order gives the complete multi-layer string:

```text
VEhNe1YzckBzX2FDQzB1bnRfaDRzX2lzM25fZjB1bmQhfQ==
```

![Base64 decoding of reconstructed string](images/Pasted%20image%2020260831042833.png)

Decoding the Base64 payload via CLI or CyberChef:

```bash
echo -n "VEhNe1YzckBzX2FDQzB1bnRfaDRzX2lzM25fZjB1bmQhfQ==" | base64 -d
```

**Output / Flag:**
```text
THM{V3r@z_aCC0unt_h4s_is3n_f0und!}
```

---

## Summary of Findings

| Field | Value |
| :--- | :--- |
| **Identified Employee** | Vera (Hotel Concierge) |
| **Instagram Account** | `@veratheconcierge` |
| **Encoded String** | `VEhNe1YzckBzX2FDQzB1bnRfaDRzX2lzM25fZjB1bmQhfQ==` |
| **Flag** | `THM{V3r@z_aCC0unt_h4s_is3n_f0und!}` |
