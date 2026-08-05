![[Pasted image 20260804233656.png]]

To begin your investigation, can you identify the filename of the note that the ransomware left behind?

Answer : `5uizv5660t-readme.txt`
This the query I used that looks through the `revil` index for filenames with the word `readme` or `help` in the current directory.


```
index=revil  winlog.event_data.TargetFilename="*README*" OR winlog.event_data.TargetFilename="*HELP*" | table _time winlog.event_data.Image winlog.event_data.TargetFilename winlog.event_data.CurrentDirectory
```

**********


Q2

After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved

Answer : `5348`

This query looks for processes that are being created with facebook assistant.exe in it, and it shows the Parent Process Id , Parent Process ,  Process and process ID. The purpose of this is to find the when the process was actually created ,what spawned the process initially, and what the malicious process spawned after being spawned.

```
index=revil winlog.event_id=1 "facebook assistant.exe"
| table _time winlog.event_data.Image winlog.event_data.ProcessId winlog.event_data.ParentImage winlog.event_data.ParentProcessId
```


![[Pasted image 20260805002745.png]]




****

Please enter a numeric answer.

Q3

Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?

Answer : `C:\Users\Administrator\Downloads\facebook assistant.exe`
**********


Q4

Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?

Answer : `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`

So I modified the query to find powershell commands. 

![[Pasted image 20260805005537.png]]


![[Pasted image 20260805010244.png]]

```
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```
**********

Q5


As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?

Answer : `B8D7FB4488C0556385498271AB9FFFDF0EB38BB2A330265D9852E3A6288092AA`

I modified the query to allow me to see the hashes associated with `facebook assistant.exe`

![[Pasted image 20260805010653.png]]
****************************************************************

Q6



One crucial piece remains: identifying the attacker's communication channel. Can you leverage threat intelligence and known Indicators of Compromise (IoCs) to pinpoint the ransomware author's onion domain?

Answer : `aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion`

I went to `tri.age` and I search up the hash that i found through Splunk . After scrolling down I was able to see a `.onion` that was used for allowing the victim to decrypt a file and verify the legitimacy of the attackers threats.

![[Pasted image 20260805013320.png]]