# Overheard at Breakfast - TryHackMe Writeup

**Category:** OSINT  
**Platform:** TryHackMe  
**Flag:** `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}`

---

## Overview

The challenge provides a message containing a contact email and a clue about a profile tool starting with the letter **G**. Using OSINT techniques, we identify the tool as Gravatar, generate the MD5 hash of the email address to access the public profile, and decode the hidden Base64 string to extract the flag.

---

## Walkthrough

### 1. Analyzing the Clue

The message snippet gives two critical pieces of information:
- **Email:** `lambobytelotushotel@gmail.com`
- **Hint:** A free service starting with **G** used to upload a profile and link accounts.

![Discord Message Hint](./Pasted%20image%2020260830205157.png)

---

### 2. Identifying the Service

Searching the clue points directly to **Gravatar** (`gravatar.com`), a profile and avatar hosting service.

![Searching for Service](./Pasted%20image%2020260830205210.png)

---

### 3. Finding the Profile Lookup Mechanism

Gravatar public profiles are queried using an MD5 hash of the user's lowercase email address:
`https://gravatar.com/{hash}`

![Gravatar Lookup Query](./Pasted%20image%2020260830205249.png)

---

### 4. Generating the Email MD5 Hash

Calculate the MD5 hash of `lambobytelotushotel@gmail.com`:

```bash
echo -n "lambobytelotushotel@gmail.com" | md5sum
# d4a5fc5d3128890778667e24617d7cc0
```

![Generating MD5 Hash](./Pasted%20image%2020260830205059.png)

---

### 5. Retrieving the Profile & Encoded String

Visiting `https://gravatar.com/d4a5fc5d3128890778667e24617d7cc0` reveals Lambo's Gravatar profile with a Base64 string in the bio:

```text
VEhNe1MzeHJlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9
```

![Gravatar Profile String](./Pasted%20image%2020260830205117.png)

---

### 6. Decoding the Flag

Decode the Base64 string via CyberChef (or CLI):

```bash
echo "VEhNe1MzeHJlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9" | base64 -d
```

**Flag:**
```text
THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}
```

![CyberChef Base64 Decode](./Pasted%20image%2020260830205138.png)

---

## Summary of Findings

| Item | Details |
| :--- | :--- |
| **Target Email** | `lambobytelotushotel@gmail.com` |
| **Identified Service** | Gravatar |
| **MD5 Hash** | `d4a5fc5d3128890778667e24617d7cc0` |
| **Profile URL** | `https://gravatar.com/d4a5fc5d3128890778667e24617d7cc0` |
| **Encoded Payload** | `VEhNe1MzeHJlVF9QcjBmaWwzX0g0c19iMzNuX0lkZW50MWZpM2R9` |
| **Flag** | `THM{S3creT_Pr0fil3_H4s_b33n_Ident1fi3d}` |