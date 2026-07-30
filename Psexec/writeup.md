
|                       |              |                                            |
| --------------------- | ------------ | ------------------------------------------ |
| Malicious Executable  | PSEXESVC.exe |                                            |
| Affected Share        | Admin$       |                                            |
| Communication Channel | IPC$         | Indicated by `stderr`, `stdout`, & `stdin` |


I went to `File > Export Objects > SMB` to see all the files transferred over SMB so that I can find the executable the attacker setup on the target.

![[Pasted image 20260728043335.png]]

So i applied the filter `smb2.tree` to see when the attacker is trying to connect to a network share. After applying this filter i see what i see below and there are two shares which are indicated by the `$` at the end and `IPC` is a hidden share for processes to communicate to each other in RAM so 

`ADMIN$` is the share the attacker is using to install services on the target machines

![[Pasted image 20260728045748.png]]



So the purpose of `stdin` is an indicator for sending cmds over the network, `stdout` sends the responses back and `stderr` is for errors

![[Pasted image 20260728050848.png]]



## Question 7


So I looked for smb traffic from the attackers IP

![[Pasted image 20260728052650.png]]


Then I followed the TCP Stream of the packet and it shows the share `MARKETING-PC$`
![[Pasted image 20260728052720.png]]