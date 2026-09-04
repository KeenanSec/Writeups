

I went to virus total and looked up the hash given to be in the lab files.  I went to the `Details` tab and then scrolled down to the `Names` section which is what is show in the screenshot below

![[Pasted image 20260729230844.png]]

`document-1982481273.xlsm`

Q1


What is the name of the file associated with the given hash?


Q2

Can you identify the filename of the **GIF** file that was deployed?

Answer : `3003.gif`

So I went to the `Relations` section and then scrolled down to the dropped files.
After scrolling down I looked for files ending in `.gif`

![[Pasted image 20260729231205.png]]
*******

Q3

How many domains does the malware look to download the additional payload file in **Q2**?

Answer :  `5`

After looking through the contacted urls I looked for urls that included `3003.gif` which is the file that I found

![[Pasted image 20260729231902.png]]


Q4

From the domains mentioned in **Q3**, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?

Answer : `NameCheap`

I looked for the Registrar corresponding to the domains that I found out were hosting the `3003.gif` and `tajushariya.com` used the Registrar NameCheap, Inc.

![[Pasted image 20260729232150.png]]
*********

Q5

Could you specify the threat actor linked to the sample provided?

Answer : `Gold Cabin`

I looked for the threat groups associated with IcedID and then after looking through the Group Description I was able to identify the threat actor was named `GOLD CABIN`
![[Pasted image 20260729232752.png]]
**** *****

Q6

In the **Execution** phase, what function does the malware employ to fetch extra payloads onto the system?

![[Pasted image 20260729234724.png]]