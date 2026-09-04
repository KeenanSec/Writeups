

| Field                    | Value                                          |
| ------------------------ | ---------------------------------------------- |
| Compromised Account      | `helpdesk.luke`                                |
| Attacker ARN             | `arn:aws:iam::141573590337:user/helpdesk.luke` |
| AWS Account ID           | `141573590337`                                 |
| Attacker-Created Account | `marketing.mark` (added to `Admins`)           |
| Data Source              | AWS CloudTrail via Splunk                      |
| Activity Window          | 2023-11-02 ~09:55 to 09:59 UTC                 |
| Key File Stolen          | `Product2_CAD_Designs.dwg`                     |

## Executive Summary

An external actor brute-forced the `helpdesk.luke` IAM user, producing 10 failed console logins before gaining access. Using those valid credentials the attacker collected 8 objects from 7 S3 buckets in under two minutes, including a secrets vault dump, customer data backups, and proprietary CAD designs. They then disabled S3 Block Public Access on `backup-and-restore98825501`, created a backdoor IAM user (`marketing.mark`) with console access, and escalated it into the `Admins` group. The entire kill chain (initial access through privilege escalation) completed in roughly four minutes.

## Attack Timeline

|Time (UTC)|Action|Detail|
|---|---|---|
|pre-09:55|Brute force|10 failed console logins against `helpdesk.luke`|
|09:55:53|Collection begins|First `GetObject`: `prototype.obj` (`research-project-files23411723`)|
|09:55:53 - 09:57:11|Bulk data access|8 objects pulled across 7 buckets|
|09:58:01|Weaken controls|`PutBucketPublicAccessBlock` on `backup-and-restore98825501`|
|09:59:33|Persistence|`CreateUser` `marketing.mark`|
|09:59:38|Persistence|`CreateLoginProfile` for `marketing.mark`|
|09:59:38|Privilege escalation|`AddUserToGroup`: `marketing.mark` to `Admins`|

## MITRE ATT&CK Mapping

| Tactic               | Technique                                         | ID        | Evidence                                                                                                              |
| -------------------- | ------------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------- |
| Credential Access    | Brute Force                                       | T1110     | 10 failed console logins for `helpdesk.luke`                                                                          |
| Initial Access       | Valid Accounts: Cloud Accounts                    | T1078.004 | Successful auth after brute force; all actions run as `helpdesk.luke`                                                 |
| Collection           | Data from Cloud Storage                           | T1530     | 8 `GetObject` calls across 7 buckets                                                                                  |
| Defense Evasion      | Impair Defenses: Disable or Modify Cloud Firewall | T1562.007 | `PutBucketPublicAccessBlock` on `backup-and-restore98825501` (closest cloud fit for disabling S3 Block Public Access) |
| Persistence          | Create Account: Cloud Account                     | T1136.003 | `CreateUser` `marketing.mark`                                                                                         |
| Persistence          | Account Manipulation                              | T1098     | `CreateLoginProfile` for `marketing.mark`                                                                             |
| Privilege Escalation | Account Manipulation                              | T1098     | `AddUserToGroup`: `marketing.mark` to `Admins`                                                                        |

## Indicators & Affected Assets

**Identities**

- Compromised: `helpdesk.luke` (`arn:aws:iam::141573590337:user/helpdesk.luke`)
- Attacker-created backdoor: `marketing.mark` (member of `Admins`)

**Buckets accessed (all via `helpdesk.luke`)**

|Bucket|Object|Sensitivity|
|---|---|---|
|`research-project-files23411723`|`prototype.obj`|R&D|
|`backup-and-restore98825501`|`secrets_vault_dump.bak`, `Configuration_Backup_Server2.zip`|Critical (public access later disabled)|
|`product-designs-repository31183937`|`Product2_CAD_Designs.dwg`|Proprietary IP|
|`contracts-data67988444`|`Contract_Termination_Letter_Client.pdf`|Legal|
|`customer-data-backup57893984`|`CustomerData_Backup_2023-11-01.zip`|Customer PII|
|`legal-docs45020393`|`Contract_Agreement.pdf`|Legal|
|`marketing-assets-vault27512203`|`logo.png`|Low|

---

## Investigation

### Q1 - Compromised user account

**Answer:** `helpdesk.luke` _(Credential Access - T1110)_

Counted failed console authentications per user from CloudTrail sign-in events, sorted descending.

```
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication" | stats count by userIdentity.userName | sort -count
```

`helpdesk.luke` had 10 failed attempts, well above the next user (`devops.ethan`, 3), consistent with a targeted brute force that eventually succeeded.

![[Pasted image 20260728175204.png]]

### Q2 - First S3 object access

**Answer:** `2023-11-02 09:55:53` _(Collection - T1530)_

Listed every S3 object touched by `helpdesk.luke`, with time, action, bucket, and key.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" | table _time, eventName, requestParameters.bucketName, requestParameters.key
```

The earliest `GetObject` was `prototype.obj` at 09:55:53. In total 8 objects were pulled from 7 buckets within 78 seconds, indicating scripted bulk collection rather than manual browsing.

![[Pasted image 20260728180720.png]]

### Q3 - Bucket containing the DWG file

**Answer:** `product-designs-repository31183937` _(Collection - T1530)_

Same query as Q2, filtered to `.dwg` (AutoCAD drawing format).

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" "*.dwg" | table _time, requestParameters.bucketName, requestParameters.key
```

One hit: `Product2_CAD_Designs.dwg` in `product-designs-repository31183937` at 09:56:07. Proprietary engineering IP, no legitimate reason for a helpdesk account to read it.

![[Pasted image 20260728182141.png]]

### Q4 - Bucket configured for public access

**Answer:** `backup-and-restore98825501` _(Defense Evasion - T1562.007)_

Searched for public-access-block changes, including the full ARN to confirm identity.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName="PutBucketPublicAccessBlock" | table _time, requestParameters.bucketName, userIdentity.arn
```

At 09:58:01, `helpdesk.luke` (`arn:aws:iam::141573590337:user/helpdesk.luke`) modified Block Public Access on `backup-and-restore98825501`. Note: the attacker had already pulled `secrets_vault_dump.bak` and `Configuration_Backup_Server2.zip` from this bucket at 09:57 using valid credentials, so disabling the block was not required for their own access. It reads as broad public exposure or staging for a second party rather than a step in Luke's own exfil.

![[Pasted image 20260728183538.png]]

### Q5 - Attacker-created account

**Answer:** `marketing.mark` _(Persistence - T1136.003, T1098)_

Looked for IAM user creation and console login setup by `helpdesk.luke`. `CreateUser` alone yields a user with no password, so `CreateLoginProfile` is what enables interactive console sign-in.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management" | search eventName="CreateUser" OR eventName="CreateLoginProfile" | table _time, eventName, requestParameters.userName
```

`marketing.mark` was created at 09:59:33 and given a console login profile at 09:59:38. The login profile signals intent for hands-on-keyboard access, not just API keys.

![[Pasted image 20260728184610.png]]

### Q6 - Group the account was added to

**Answer:** `Admins` _(Privilege Escalation - T1098)_

Queried all `AddUserToGroup` events account-wide (deliberately not scoped to Luke, since escalation could target any identity).

```
index="aws_cloudtrail" eventName="AddUserToGroup" | table _time, requestParameters.groupName, requestParameters.userName
```

Single result: `marketing.mark` added to `Admins` at 09:59:38. This is the escalation that turns the backdoor account from powerless into full administrator. The wide query returned only this one event, confirming the blast radius is a single created account.

![[Pasted image 20260728185116.png]]

---

## Lessons Learned

Each item maps to a control gap the attacker exploited in this incident.

| Gap                                  | Impact in this incident                                           | Recommendation                                                                              |
| ------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| No evidence of MFA on console logins | Password brute force alone granted full access                    | Enforce MFA on all IAM users via SCP                                                        |
| No alerting on failed-auth volume    | 10 failed logins went unnoticed before the breach                 | GuardDuty / CloudWatch alarm on repeated `ConsoleLogin` failures per user                   |
| Over-permissioned helpdesk account   | One account read 7 buckets of secrets, PII, contracts, and CAD IP | Scope IAM policies to least privilege; helpdesk should not reach data buckets               |
| Unmonitored IAM changes              | Backdoor admin created and escalated in seconds                   | Alert on `CreateUser`, `CreateLoginProfile`, `AddUserToGroup`; SCP-gate `Admins` membership |
| Mutable public-access controls       | Critical bucket exposed by a non-admin user                       | SCP denying `PutBucketPublicAccessBlock` except a designated break-glass role               |

## Containment / remediation

- Disable `helpdesk.luke`, force password rotation, revoke active sessions.
- Delete `marketing.mark` and remove it from `Admins`.
- Re-enable Block Public Access on `backup-and-restore98825501` and audit whether the bucket was reached publicly during the exposure window.
- Treat `secrets_vault_dump.bak`, customer data, and CAD IP as confirmed exfiltrated; rotate any credentials in the secrets dump.