# Block Writeup THM



I looked the pcap file provided and then I looked for the first line with `\Workgroup` in it then 

![Screenshot](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904200416.png)

What is the username of the first person who accessed our server?  

`Answer : mrealman`

I got the password by using pypykatz on the `lsass.DMP` file provided and cracked the NT hash in the output

![Screenshot](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904200553.png)

![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904200632.png)

What is the password of the user in question 1?

`Answer : Blockbuster1`


We have to decrypt the SMB traffic and I found out how to do this by using this https://snynr.medium.com/tryhackme-encryption-what-encryption-2eff5ca2f065


You use the session keys from the python program provided in the article and decrypt the encrypted SMB traffic 

![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904201446.png)

![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904201207.png)

What is the flag that the first user got access to?  

`Answer : THM{SmB_DeCrypTing_who_Could_Have_Th0ughT}`


Look for the second username with `\Workgroup` 

![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904201320.png)

What is the username of the second person who accessed our server?  

`Answer : eshellstrop`

You use pypykatz and if you look for the username from the previous question you should see it 


![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904201749.png)

What is the hash of the user in question 4?

`Answer : 3f29138a04aadc19214e9c04028bf381`


The flag is in the exported file after decrypting the traffic with the key provided after running the python script 
![](https://github.com/SNUFFKEY/Writeups/blob/main/Block/Pasted%20image%2020240904201014.png)

What is the flag that the second user got access to?

`Answer : THM{No_PasSw0Rd?_No_Pr0bl3m}`


## Summary

I downloaded the files that I was given which had a DMP and a pcap file. I then used pypykatz on the dumpp and got the NTLM hashes and tried to crack them. I was able to get 
a password for the user "mrealman". Then I realized that it used encrypted SMB meaning that I would need to decrypt to find the flag. So what I Decide to do is search up how
to crack SMB encryption then I used the python program from the blog. It required the session key , username , domain , password or password hash ,and the ntproofstr. I did
this for both of the usernames I found in the pcap.I exported the csv files and found the flags in the files.
