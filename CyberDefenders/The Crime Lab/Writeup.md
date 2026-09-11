# The Crime - CyberDefenders Writeup

**Category:** Mobile / Android Forensics  
**Platform:** CyberDefenders  
**Tools:** ALEAPP (Android Logs Events And Protobuf Parser), SQLite Viewer  

---

## Connected Investigations
- **Digital Forensics & Artifact Carving:** Compare with [SOC-Simulator: LNK-in-Archive PowerShell Phishing](<../../SOC-Simulator/LNK-in-Archive PowerShell Phishing/Writeup.md>) and [TryHackMe: AI Forensics](<../../TryHackMe/AI Forensics/Writeup.md>).

---

## Overview

**The Crime** is an Android mobile forensics challenge that requires analyzing an Android physical image / triage extraction using **ALEAPP**. By parsing application databases, SMS message stores (`mmssms.db`), downloaded documents, and instant messaging chat caches (Discord), we reconstruct an extortion and travel timeline involving a suspect.

---

## Walkthrough

### Q1 — Identifying the Suspicious Installed Application

Parsing the Google Play Services application database (`gass.db`) using ALEAPP:

```text
temp_extract_dir\data\data\com.google.android.gms\databases\gass.db
```

Reviewing the **installedappsGass report** identifies the installed applications and their cryptographic hashes:

![ALEAPP installed applications report](Pasted%20image%2020260730041728.png)

- **Application Package:** `com.ticno.olymptrade`
- **Version Code:** `672`
- **SHA-256 Hash:** `4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c`

---

### Q2 — Extortion Demand & Extortionist Phone Number

Inspecting the telephony database (`mmssms.db`):

```text
temp_extract_dir\data\user_de\0\com.android.providers.telephony\databases\mmssms.db
```

ALEAPP's **SMS Messages report** reveals an extortion attempt received on `2023-09-20 21:09:49+00:00`:

![ALEAPP SMS report displaying extortion text](Pasted%20image%2020260730042218.png)

> *"It's time for you to pay back the money you owe me, but you're not picking up my calls. You better think twice about not paying, because it won't end well for you. Prepare the sum of 250,000 EGP, and I'll expect your call within an hour at most."*

- **Sender Address:** `+201172137258`
- **Demanded Sum:** `250000` (EGP)
- **Answer:** `250000`

---

### Q3 — Geolocation & Recent Activity

Auditing the user's recent Google Maps cached snapshots and location history:

![Google Maps snapshot showing user location](Pasted%20image%2020260730042729.png)

The map cache confirms the user was located along **The Nile**.

- **Answer:** `The Nile`

---

### Q4 — Travel Plans & Flight Destination

Inspecting media artifacts under the user download directory:

```text
138-The-Crime\data\media\0\Download\
```

Found a digital Egypt Airlines boarding pass for passenger **Mohamed Ahmed**:

![Flight ticket from Cairo to Las Vegas](Pasted%20image%2020260730043305.png)

- **Flight:** `310` (Departure: `09:00 AM`, Date: `01.10.2023`)
- **Origin:** `Cairo`
- **Destination:** `Las Vegas`
- **Answer:** `Las Vegas`

---

### Q5 — Accomplice Meeting Location

Parsing Discord chat databases in ALEAPP reveals a conversation between the suspect (`infern0_o`) and user `rob1ns0n.` on `2023-09-20 20:46:02 UTC`:

![Discord conversation pinpointing the meeting location](Pasted%20image%2020260730043420.png)

> *"What a wonderful news! We'll meet at **The Mob Museum**, I'll await your call when you arrive. Enjoy you flight bro ❤️"*

- **Answer:** `The Mob Museum`

---

## Summary of Findings

| Artifact / Indicator | Value | Source Location |
| :--- | :--- | :--- |
| **Installed App Package** | `com.ticno.olymptrade` | `gass.db` |
| **App SHA-256** | `4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c` | `gass.db` |
| **Extortionist Phone** | `+201172137258` | `mmssms.db` |
| **Extortion Amount** | `250000` EGP | `mmssms.db` |
| **Google Maps Location** | `The Nile` | Maps cached snapshot |
| **Flight Destination** | `Las Vegas` | `data/media/0/Download/` |
| **Accomplice Meeting Place** | `The Mob Museum` | Discord chat database |
