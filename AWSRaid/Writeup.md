
| Attacker Username | `helpdesk.luke`          |
| ----------------- | ------------------------ |
| Files Accessed    | Product2_CAD_Designs.dwg |

## Question 1 

Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?

Answer : `helpdesk.luke`

I used this Splunk Query to look for fail authentications attempts from CloudTrail sign in events, then count the number of failed attempts by each user and then sort descending so the account with the most amount of logins would be at the top.

```
index="aws_cloudtrail" eventSource="signin.amazonaws.com" errorMessage="Failed authentication" | stats count by userIdentity.userName | sort -count
```

![[Pasted image 20260728175204.png]]


From this I was able to identify that `helpdesk.luke` had the most amount of failed attempts.


## Question 2

We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?

Answer : `2023-11-02 09:55`

This Splunk query is used to find out every S3 object accessed by the user `helpdesk.luke` , when he accessed (`_time`) , what he did with it (`eventName`) , which bucket is was (`requestParameters.bucketName`) , and the specific object/filepath from the bucket (`requestParameters.key`)

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" | table _time, eventName, requestParameters.bucketName, requestParameters.key
```

![[Pasted image 20260728180720.png]]
## Question 3 

Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?

Answer :  `product-designs-repository31183937
`

This command is very similar to the other command in which it looks for S3 objects accessed by the user `helpdesk.luke` , but it also filters out the objects found for files ending `.dwg` which is  the AutoCAD drawing format.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventSource="s3.amazonaws.com" eventName="GetObject" "*.dwg" | table _time, requestParameters.bucketName, requestParameters.key
```

The image below shows that the `.dwg` file accessed by `helpdesk.luke ` is `Product2_CAD_Designs.dwg` which is located in the bucket : `product-designs-repository31183937`

![[Pasted image 20260728182141.png]]
## Question 4

We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?

Answer : `backup-and-restore98825501`


This query looks for every time the user `helpdesk.luke` changed the public-access-block setting on an S3 bucket , when he did it , which bucket it was , and the ARN or full account identity.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventName="PutBucketPublicAccessBlock" | table _time, requestParameters.bucketName, userIdentity.arn
```

In this screenshot you can see that the bucket `helpdesk.luke` modified public access block for was `backup-and-restore98825501`

![[Pasted image 20260728183538.png]]


## Question 5

Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?

Answer :  `marketing.mark`


This query looks instances where `helpdesk.luke` created a new IAM user or instances where `helpdesk.luke`​ setup a console login for an account so that he could actually login. The console login is necessary because when someone `CreateUser` in IAM it creates an account that starts with no password and to be able to use the web UI a Console login is required which is why I looked for `CreateLoginProfile`​.

```
index="aws_cloudtrail" "userIdentity.userName"="helpdesk.luke" eventCategory="Management" | search eventName="CreateUser" OR eventName="CreateLoginProfile"| table _time, eventName, requestParameters.userName
```

As can be seen by this screenshot `helpdesk.luke` created an account named `marketing.mark` & setup a console login for `marketing.mark`

![[Pasted image 20260728184610.png]]

## Question 6

Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?

Answer : `Admins`

This query shows every time any user is added to a group, when the user was added , who the user is and the group the user is added to.

```
index="aws_cloudtrail" eventName="AddUserToGroup" | table _time, requestParameters.groupName, requestParameters.userName
```

This screenshot shows that `marketing.mark` was added to the  `Admins` group

![[Pasted image 20260728185116.png]]

