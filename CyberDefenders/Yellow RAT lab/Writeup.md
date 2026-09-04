
## Summary

In this report I used VirusTotal to identify the malware family , common filename associated with discovery , I also identified where the malware dropped a file via Red Canary Report & I identified the C2.

Q1


Understanding the adversary helps defend against attacks. What is the name of the malware family that causes abnormal network traffic?

Answer : `Yellow Cockatoo RAT`


FIrst I opened the file `hash.txt` and copied the hash.

![[Pasted image 20260729200839.png]]




Then I went to Virustotal and when I looked at the Community tab I see that the name `Yellow Cockatoo RAT`

![[Pasted image 20260729202346.png]]


****** ******** ***

Q2



As part of our incident response, knowing common filenames the malware uses can help scan other workstations for potential infection. What is the common filename associated with the malware discovered on our workstations?

Answer : `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`
This asks for the common file and I saw at the top that `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`

![[Pasted image 20260729202609.png]]

*********

Q3

Determining the compilation timestamp of malware can reveal insights into its development and deployment timeline. What is the compilation timestamp of the malware that infected our network?

Answer : `2020-09-24 18:26`

After looking in the Portable Executable Info i was able to see the compilation timestamp which is `2020-09-24 18:26:47 UTC`

![[Pasted image 20260729202856.png]]
*********

Q4



Understanding when the broader cybersecurity community first identified the malware could help determine how long the malware might have been in the environment before detection. When was the malware first submitted to VirusTotal?
Answer : `2020-10-15 02:47`

This question asks for when the malware was first submitted to VirusTotal. I am able to see this by scrolling down to the `History` section. The first submission was at `2020-10-15 02:47:37 UTC`

![[Pasted image 20260729203026.png]]
*********

Q5


To completely eradicate the threat from Industries' systems, we need to identify all components dropped by the malware. What is the name of the **.dat** file that the malware dropped in the **AppData** folder?

First I searched for the Malware on google to see a report on this piece of malware.

![[Pasted image 20260729203322.png]]

After looking at the threat report i was able to see the file `solarmarker.dat`

![[Pasted image 20260729203711.png]]
*********

Q6

It is crucial to identify the C2 servers with which the malware communicates to block its communication and prevent further data exfiltration. What is the C2 server that the malware is communicating with?

![[Pasted image 20260729203906.png]]
*********