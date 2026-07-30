

| Victim   | 192.168.232.162 |
| -------- | --------------- |
| Attacker | 192.168.232.215 |

In the context of the incident described in the scenario, the attacker initiated their actions by taking advantage of benign network traffic from legitimate machines. Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?

LLMNR and NBT-NS are protocols used to resolve names when DNS is unavailable and as aresult is susceptible to MITM attacks 


I asked to identify the specific mistyped query made by 192.168.232.162 so I used the filter `llmnr and ip.src == 192.168.232.162` to make it alot easier and find llmnr queries from this IP

In this screenshot you can see that at the end of each packet it contains `fileshaare`  which seems to be misspelled.
![[Pasted image 20260729002208.png]]

**********

Q2


We are investigating a network security incident. To conduct a thorough investigation, We need to determine the IP address of the rogue machine. What is the IP address of the machine acting as the rogue entity?

Answer : `192.168.232.215`

`192.168.232.215` is the rogue host because it repeatedly sent LLMNR query responses claiming to be `fileshaare` to the victim `192.168.232.162`, which is an indicator of LLMNR poisoning 


![[Pasted image 20260729003528.png]]
*********

Q3



As part of our investigation, identifying all affected machines is essential. What is the IP address of the second machine that received poisoned responses from the rogue machine?

Answer : ` 192.168.232.176`

I found this out by looking for llmnr responses from the attacker IP I found from the last question using this filter `ip.src == 192.168.232.215 and llmnr`. Then I was able to see that the attacker was able to poison `192.168.232.176` by taking advantage of the victim trying to resolve `prinetr`

![[Pasted image 20260729003917.png]]


*********

Q4

We suspect that user accounts may have been compromised. To assess this, we must determine the username associated with the compromised account. What is the username of the account that the attacker compromised?


Now I need to find the username of the account that got compromised and I will do this by filtering for NTLM authentication data using `ntlmssp.auth.username

After applying this filter I saw that the victim `.176` authenticated to the attacker since it was poisoned and send its credentials as `janesmith`

![[Pasted image 20260729004829.png]]
*********

Q5

As part of our investigation, we aim to understand the extent of the attacker's activities. What is the hostname of the machine that the attacker accessed via SMB?

I looked for NTLM 

![[Pasted image 20260729010027.png]]