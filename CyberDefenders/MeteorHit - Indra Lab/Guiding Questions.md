Here are the core questions to guide your investigation, kept simple and focused:

  

**Initial Access & Foothold**

  

- How did the attacker first get onto this specific machine?
    
      The attacker compromised Active Directory
    
- Which user account or process executed the initial suspicious activity?
    
      
    
- When is the earliest timestamp of anomalous activity?
    
      
    

**Execution & Malware Activity**

  

- What is the name, hash, and file path of the wiper malware?
    
      
    
- How was the wiper triggered (e.g., scheduled task, service, script, manual command)?
    
      
    
- What processes spawned before and during the wiping activity?
    
      
    

**Impact & Damage**

  

- What files, directories, or registry keys were modified, encrypted, or deleted before shutdown?
    
      
    
- Did the malware attempt to wipe the Master Boot Record (MBR) or volume shadow copies?
    
      
    
- What specific political messages or defacement files were created locally?
    
      
    

**Privilege & Active Directory Abuse**

  

- Were domain administrative or elevated credentials used on this host?
    
      
    
- Are there signs of credential dumping (e.g., LSASS access, SAM hive access)?
    
      
    
- Did Group Policy Objects (GPOs) or domain-level tools push the wiper here?
    
      
    

**Lateral Movement & Scope**

  

- Did this machine communicate with other internal systems or the Domain Controller?
    
      
    
- Are there inbound or outbound remote access artifacts (e.g., RDP, SMB, WinRM, PsExec)?
    
      
    
- What external Command and Control (C2) IP addresses or domains were contacted?d