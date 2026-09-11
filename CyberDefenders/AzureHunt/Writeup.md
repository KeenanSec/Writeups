# AzureHunt - CyberDefenders Writeup

**Category:** Cloud Threat Hunting & Incident Response  
**Platform:** CyberDefenders  
**Tools:** Elastic SIEM, KQL (Kibana Query Language), Azure Activity Logs, Entra ID / Azure AD Audit & Sign-in Logs  

---

## Connected Investigations
- **Cloud Threat Hunting Comparison:** Compare directly with [CyberDefenders: AWSRaid](<../AWSRaid/AWSRaid - CloudTrail Incident Writeup.md>). Both scenarios investigate cloud infrastructure compromise through audit logs, tracking initial entry, unauthorized data exports, defense evasion, backdoor account creation, and role escalation:
  - **AWS (AWSRaid):** Compromised IAM user `helpdesk.luke` $\rightarrow$ S3 exfiltration $\rightarrow$ Disabling S3 Block Public Access $\rightarrow$ Backdoor user `marketing.mark` added to `Admins`.
  - **Azure (AzureHunt):** Database export `CUSTOMERDATADB` $\rightarrow$ Backdoor user `IT_Support@cybercactus.onmicrosoft.com` $\rightarrow$ Privilege escalation to `Owner` $\rightarrow$ Persistence sign-in validation.

---

## Scenario Overview

An adversary gained unauthorized access to an organization's Microsoft Azure cloud tenant (`cybercactus.onmicrosoft.com`). The threat actor performed automated data exfiltration against corporate Azure SQL databases, created a stealthy persistence account disguised as IT support, escalated the backdoor account to the highest subscription privilege (`Owner`), and authenticated back into the tenant. 

Using **Elastic SIEM** and KQL queries against `azure.activitylogs`, `azure.auditlogs`, and `azure.signinlogs`, we trace the complete kill chain.

---

## Investigation Walkthrough

### 1. Identifying Database Exfiltration

To detect data collection and exfiltration activities targeting cloud data stores, we filter for SQL database export actions:

```kql
event.action: "MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION"
```

![Elastic KQL query for database export actions](Pasted%20image%2020260827054933.png)

**Findings:**
- **Timestamp:** `Oct 5, 2023 @ 15:33:31.627`
- **Resource Name:** `CACTUSDBSERVER/DATABASES/CUSTOMERDATADB`
- **Resource ID:** `/SUBSCRIPTIONS/42439AB4-76DF-453B-A380-2F7A4580F01F/RESOURCEGROUPS/RSS1/PROVIDERS/MICROSOFT.SQL/SERVERS/CACTUSDBSERVER/DATABASES/CUSTOMERDATADB`
- **Impact:** Attacker initiated an unauthorized export action against the primary customer database (`CUSTOMERDATADB`).

---

### 2. Detecting Rogue User Account Creation

Adversaries establish persistence in cloud environments by provisioning new tenant users. We query Entra ID directory audit logs for user addition events:

```kql
event.action: "Add user"
```

![Audit log showing rogue user account creation](Pasted%20image%2020260827060042.png)

**Findings:**
- **Timestamp:** `Oct 5, 2023 @ 15:42:53.536`
- **Created Account (UPN):** `IT_Support@cybercactus.onmicrosoft.com`
- **Target Resource ID:** `/tenants/0fcdf9d3-ccc9-449f-88d8-5fa11f3ff963/providers/Microsoft.aadiam`
- **Analysis:** Approximately 9 minutes after exfiltrating the database, the attacker created a persistence account masquerading as legitimate helpdesk personnel.

---

### 3. Tracking Privilege Escalation (Role Assignment)

To grant the rogue account full administrative control over cloud resources, the attacker assigns RBAC roles. We query for role assignment events:

```kql
event.action: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
```

![Role assignment activity logs in Elastic](Pasted%20image%2020260827060347.png)

**Findings:**
- **Timestamps:** `Oct 5, 2023 @ 15:44:23.722` & `15:44:26.425`
- **Assigned Role:** `Owner`
- **Role Assignment ID:** `572A0399-B006-418A-9860-6943855911E0`
- **Analysis:** The newly created `IT_Support` user was granted the `Owner` role at the subscription root scope, granting full management access to all tenant resources.

---

### 4. Validating Persistence & Sign-in Activity

To verify whether the adversary leveraged the backdoor account for interactive access, we filter Azure Sign-in logs (`azure.signinlogs`) for the compromised UPN:

```kql
azure.signinlogs.properties.user_principal_name: "it_support@cybercactus.onmicrosoft.com"
```

![Sign-in logs showing attacker authenticating with backdoor account](Pasted%20image%2020260827060550.png)

**Findings:**
- **First Successful Logon:** `Oct 6, 2023 @ 07:30:43.113`
- **Subsequent Sign-in:** `Oct 6, 2023 @ 07:31:59.626`
- **Analysis:** The attacker successfully logged in using the rogue `IT_Support` identity the following morning, validating persistent access.

---

## MITRE ATT&CK Cloud Mapping

| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| **Collection / Exfiltration** | Data from Cloud Storage / DB | T1530 | `MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION` on `CUSTOMERDATADB` |
| **Persistence** | Create Account: Cloud Account | T1136.003 | `Add user` creates `IT_Support@cybercactus.onmicrosoft.com` |
| **Privilege Escalation** | Role Assignment Manipulation | T1098.003 | `ROLEASSIGNMENTS/WRITE` elevates account to `Owner` |
| **Initial Access / Re-entry** | Valid Accounts: Cloud Accounts | T1078.004 | Sign-in on `2023-10-06 07:30:43 UTC` |

---

## Key Artifacts & Indicators

| Artifact | Value |
| :--- | :--- |
| **Compromised Tenant** | `cybercactus.onmicrosoft.com` |
| **Tenant ID** | `0fcdf9d3-ccc9-449f-88d8-5fa11f3ff963` |
| **Targeted Database** | `CUSTOMERDATADB` (Server: `CACTUSDBSERVER`) |
| **Backdoor User Principal Name** | `IT_Support@cybercactus.onmicrosoft.com` |
| **Escalated Role** | `Owner` |
| **Backdoor First Login** | `2023-10-06 07:30:43.113 UTC` |
