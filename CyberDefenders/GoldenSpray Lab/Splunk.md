Detecting unusual login attempts in Splunk relies on querying authentication events—such as Windows Event IDs `4624` (successful logon) and `4625` (failed logon), Linux `/var/log/auth.log`, or the Splunk Common Information Model (CIM) `Authentication` data model.

  

**1. Impossible Travel (Geographic Anomaly)**

Detects when a single user account logs in successfully from two distant geographic locations within a timeframe that makes physical travel impossible.

  

Splunk SPL

```
tag=authentication action=success
| iplocation src_ip
| sort 0 user _time
| streamstats current=f window=1 values(Country) as prev_country values(lat) as prev_lat values(lon) as prev_lon values(_time) as prev_time by user
| eval time_diff = (_time - prev_time)
| where Country != prev_country AND time_diff < 7200 AND isnotnull(prev_country)
| table _time user src_ip Country prev_country time_diff
```

**2. Brute Force Followed by Successful Logon**

Finds accounts that had multiple failed attempts (`4625`) followed immediately by a successful authentication (`4624`), indicating a potential password spray or brute force breach.



Splunk SPL

```
index=winlog source="WinEventLog:Security" EventCode IN (4624, 4625)
| eval action=if(EventCode==4624, "success", "failure")
| transaction TargetUserName maxspan=15m maxpause=2m startswith=(action="failure") endswith=(action="success")
| where eventcount >= 6
| table _time TargetUserName ComputerName eventcount action
```


**3. Logins Outside Standard Business Hours**

Flags authentications occurring during off-hours (e.g., between 8 PM and 5 AM or on weekends) using Splunk's built-in date variables.

  
Splunk SPL

```
index=winlog EventCode=4624 Logon_Type IN (2, 10)
| eval hour=strftime(_time, "%H"), day=strftime(_time, "%a")
| where (hour < 5 OR hour >= 20) OR (day IN ("Sat", "Sun"))
| stats count by _time TargetUserName WorkstationName IpAddress
```

**4. Baseline Deviation (New or Rare Source IP)**

Compares logins from the past 24 hours against a historical baseline of known IP addresses used by that account over the previous 30 days.

  

Splunk SPL

```
tag=authentication action=success earliest=-30d@d
| stats earliest(_time) as first_seen latest(_time) as last_seen by user src
| where first_seen >= relative_time(now(), "-24h@h")
| table user src first_seen
```

**5. Rare Workstation or Host Logins**

Uses the `rare` command to spotlight accounts logging into servers or systems they almost never touch.

  

Splunk SPL

```
tag=authentication action=success
| rare limit=20 dest by user
| table user dest count percent
```

Are you looking to build alerts against standard Windows/Active Directory logs, cloud identity providers (like Entra ID or Okta), or via Splunk's CIM `Authentication` data model?