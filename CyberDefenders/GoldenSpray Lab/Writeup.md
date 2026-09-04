# GoldenSpray Lab — Writeup

## Summary of Key Findings

| Finding / Artifact | Value / Details |
| --- | --- |
| **Attacker IP** | `77.91.78.115` |
| **Origin Country** | Finland |
| **Initial Access Account** | `SECURETECH\mwilliams` |
| **Malicious Persistence File** | `C:\Windows\Temp\OfficeUpdater.exe` |
| **Attacker Tool Directory** | `C:\Users\Public\Backup_Tools` |
| **Credential Dumping (Mimikatz)** | `2024-09-09 17:27:59.127` (PID: `3708`) |
| **Lateral Movement Account** | `SECURETECH\jsmith` (compromised at `17:34:17.775` from `77.91.78.115`) |
| **Persistence (Domain Controller)** | Scheduled task `\FilesCheck` ran at `2024-09-09 17:38:44` (`ST-DC01.SECURETECH.local`) |
| **Kerberos Ticket Encryption** | `0x17` (`RC4-HMAC`) |
| **Exfiltration Archive** | `C:\Users\Public\Documents\Archive_8673812.zip` |

---

## Q1: What is the attacker's IP address?
- **Solved:** 974
- **Answer:** `77.91.78.115`

### Query
```spl
index=goldenspray winlog.event_id=4625 
| stats count by winlog.event_data.IpAddress
| sort - count
```

### Explanation
I ran this query to filter by IP address and list from the most amount of failed attempts to least.

### Evidence
![](img/Pasted%20image%2020260903131200.png)

---

## Q2: What country is the attack originating from?
- **Solved:** 966
- **Answer:** `Finland`

### Explanation
Looked up the attacker's IP address (`77.91.78.115`) on an IP geolocation lookup tool, which resolved the origin country to Finland.

### Evidence
![](img/Pasted%20image%2020260903131352.png)

---

## Q3: What's the compromised account username used for initial access?
- **Solved:** 961
- **Answer:** `mwilliams`

### Query
```spl
index=goldenspray winlog.event_data.IpAddress="77.91.78.115" winlog.event_id=4624
| table _time winlog.event_data.TargetDomainName winlog.event_data.TargetUserName winlog.event_data.LogonType winlog.event_data.WorkstationName
| sort _time
```

### Explanation
I first thought it was the account at the top, then I learned that logins via RDP are usually followed up by a logon type of 10, which `mwilliams` was.

### Evidence
![](img/Pasted%20image%2020260903133909.png)

---

## Q4: What's the name of the malicious file utilized by the attacker for persistence on `ST-WIN02`?
- **Solved:** 913
- **Answer:** `OfficeUpdater.exe` (`C:\Windows\Temp\OfficeUpdater.exe`)

### Query
```spl
index=goldenspray winlog.computer_name="*ST-WIN02*" winlog.event_id=11 earliest="09/09/2024:17:00:00" latest="09/09/2024:17:35:00"
| table _time winlog.event_data.Image winlog.event_data.TargetFilename winlog.event_data.User
| sort _time
```

### Explanation
So I filtered around the time frame I knew the attacker was logged in for file creation events to see what files the attacker may have created or downloaded:

![](img/Pasted%20image%2020260903134909.png)

I believe it is `C:\Windows\Temp\OfficeUpdater.exe` because it is run from the temp directory and most office applications never run from the temp directory. It is also run under the account we know was compromised for initial access, and its creating process is `powershell.exe` instead of a trusted Windows update service or installer engine like `TrustedInstaller` and `msiexec.exe`, while trying to make the name of the binary look legit.

### Evidence (MITRE ATT&CK T1137 - Office Application Startup)
![](img/Pasted%20image%2020260903232750.png)

---

## Q5: What is the complete path used by the attacker to store their tools?
- **Solved:** 913
- **Answer:** `C:\Users\Public\Backup_Tools`

### Explanation
In the same screenshot above, I can see that the attacker uploads a zip file `Backup_Tools.zip` to a public/temp directory, which is where I know most attackers tend to live after initial access.

Then I also see names of known tools like `mimikatz.exe` and `PsExec.exe` in `C:\Users\Public\Backup_Tools`.

---

## Q6: What's the process ID of the tool responsible for dumping credentials on `ST-WIN02`?
- **Solved:** 901
- **Answer:** `3708`

### Query
```spl
index=goldenspray winlog.event_id=10 winlog.event_data.TargetImage="*lsass.exe" winlog.computer_name="*ST-WIN02*" earliest="09/09/2024:17:00:00" latest="09/09/2024:17:50:00"
| table _time winlog.computer_name winlog.event_data.SourceImage winlog.event_data.SourceProcessId winlog.event_data.GrantedAccess winlog.event_data.CallTrace
| sort _time
```

### Explanation
In this query I looked for logs with the event id of `10` because I know it's going to be a process access of `lsass.exe`. So I also added `winlog.event_data.TargetImage="*lsass.exe"` to find processes that access `lsass.exe`, which is usually for dumping credentials.

I knew the attacker was on `ST-WIN02` so I looked for the hostname to be that with `winlog.computer_name="*ST-WIN02*"`.

I also made sure to filter for the attacker timeframe based on the accounts that the attacker's IP logged into: `earliest="09/09/2024:17:00:00" latest="09/09/2024:17:50:00"`.

I made the table display the time so I know when the attacker used `mimikatz`, and the source image to actually see what the name of the lsass dumper was (`C:\Users\Public\Backup_Tools\mimikatz.exe`).

In Windows internals, `0x1010` is the bitwise combination of:
- `0x0010` (`PROCESS_VM_READ`) — Allows reading memory pages inside the target process space.
- `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`) — Allows querying basic state/privilege info.

### Evidence
![](img/Pasted%20image%2020260903224907.png)

---

## Q7: What's the second account username the attacker compromised and used for lateral movement?
- **Solved:** 900
- **Answer:** `jsmith`

### Query
```spl
index=goldenspray winlog.event_data.IpAddress=77.91.78.115 winlog.event_id=4624 earliest="09/09/2024:17:27:59" latest="09/09/2024:17:50:00"
| table _time winlog.event_data.TargetUserName winlog.event_data.IpAddress winlog.event_data.WorkstationName winlog.event_data.TargetDomainName
```

### Explanation
In this query I filtered for the attacker's IP `77.91.78.115` and Event ID `4624` (successful logons), and I made sure to filter after the Mimikatz activity using `earliest="09/09/2024:17:27:59"` with the latest boundary based on the last observed login from the attacker IP.

Then I created a table to show:
- The time the attacker logged in (`2024-09-09 17:34:17.775`).
- The workstation name to see what machine the account has access to (`ST-DC01`).
- The username to see what user was compromised (`jsmith`).
- The domain name to see what domain the user is connected to (`SECURETECH`).

### Evidence
![](img/Pasted%20image%2020260903231257.png)

---

## Q8: Can you provide the scheduled task created by the attacker for persistence on the domain controller?
- **Solved:** 885
- **Answer:** `\FilesCheck`

### Query
```spl
index=goldenspray winlog.event_id=106 earliest="09/09/2024:17:00:59" latest="09/09/2024:17:50:00" 
| table _time winlog.computer_name winlog.event_data.TaskName winlog.event_data.ActionName winlog.event_data.UserName winlog.event_data.UserContext 
| sort _time
```

### Explanation
I filtered for scheduled tasks by using Event ID `106` and filtered for the timeframe that I know the attack occurred. I made sure the table view included the computer name that created the task and the task name (`\FilesCheck`).

At `2024-09-09 17:38:44.406`, a scheduled task was run from a domain controller account on `ST-DC01.SECURETECH.local`.

### Evidence
![](img/Pasted%20image%2020260903234035.png)

---

## Q9: What type of encryption is used for Kerberos tickets in the environment?
- **Solved:** 881
- **Answer:** `RC4-HMAC`

### Query
```spl
index=goldenspray winlog.event_id=4769 earliest="09/09/2024:17:27:59" latest="09/09/2024:17:50:00"
| table _time winlog.event_data.ServiceName winlog.event_data.TargetUserName winlog.event_data.TicketEncryptionType
```

### Explanation
After filtering for Event ID `4769` (Kerberos Service Ticket Operations) and adding `TicketEncryptionType` to the table view, I was able to see the encryption type:

- `0x17` as shown in the screenshot is an indicator of a weak encryption algorithm known as `RC4-HMAC`, which is susceptible to pass-the-hash / overpass-the-hash attacks and Kerberoasting.
- Another thing that I notice here is that this Kerberos ticket event happens at the same time the `jsmith` user was compromised (`17:34:17.771`).

### Evidence
![](img/Pasted%20image%2020260903235202.png)

![](img/Pasted%20image%2020260903235332.png)

---

## Q10: Can you provide the full path of the output file in preparation for data exfiltration?
- **Solved:** 865
- **Answer:** `C:\Users\Public\Documents\Archive_8673812.zip`

### Query
```spl
index=goldenspray winlog.event_id=11 winlog.event_data.TargetFilename="*.zip*"
| table _time winlog.computer_name winlog.event_data.Image winlog.event_data.TargetFilename winlog.event_data.User
| sort - time
```

### Explanation
I looked for file creation with Event ID `11` to see what files the attacker may have been trying to exfiltrate, and I also looked for zip files since most attackers create some form of file archive for exfiltration. I also see that this originated from `ST-FS01`, which indicates it's a file server of some sort.

From the query results, at `2024-09-09 17:53:10.708` the attacker created the archive:
`C:\Users\Public\Documents\Archive_8673812.zip`

### Evidence

![](img/Pasted%20image%2020260904000613.png)
