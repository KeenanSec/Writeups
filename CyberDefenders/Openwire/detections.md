# Detection Rules: Apache ActiveMQ CVE-2023-46604 & Stager Artifacts
**Associated Incident / Lab:** CyberDefenders OpenWire  
**Target Vulnerability:** CVE-2023-46604 (Apache ActiveMQ OpenWire Deserialization RCE)  
**Author:** Keenan  
**Date:** 2026-10-23  

---

## 1. Sigma Rule: ActiveMQ Anomalous Child Process Execution (Host / SIEM)

Detects the exploitation phase where the vulnerable ActiveMQ `java` process instantiates `ClassPathXmlApplicationContext` and spawns a shell or download utility (`curl`, `wget`, `sh`, `bash`) to fetch and execute dropped binaries in `/tmp`.

```yaml
title: Suspicious Process Spawning from Apache ActiveMQ (CVE-2023-46604)
id: e4b2d871-3312-4f79-8cb1-8051283e9b01
status: experimental
description: Detects suspicious child processes (e.g., shells, downloaders, script interpreters) spawned by Apache ActiveMQ (java process), characteristic of CVE-2023-46604 exploitation.
references:
    - https://nvd.nist.gov/vuln/detail/CVE-2023-46604
    - https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt
author: Keenan
date: 2026-10-23
tags:
    - attack.execution
    - attack.t1059
    - attack.initial_access
    - attack.t1190
    - cve.2023.46604
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        Image|endswith: '/java'
        CommandLine|contains: 'activemq'
    selection_child_process:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/curl'
            - '/wget'
            - '/chmod'
            - '/python'
            - '/python3'
    selection_child_cmdline:
        CommandLine|contains:
            - 'curl'
            - 'wget'
            - '/tmp/'
            - '/dev/shm/'
            - 'chmod +x'
    condition: selection_parent and (selection_child_process or selection_child_cmdline)
falsepositives:
    - Administrative automation or monitoring scripts wrapped directly into ActiveMQ start scripts (uncommon)
level: high
```

---

## 2. Suricata / Snort Rule: OpenWire Deserialization RCE (Network IDS)

Inspects incoming OpenWire traffic on port `61616` for the malicious unmarshaling command (Type `0x1f` ExceptionResponse) loading Spring's `ClassPathXmlApplicationContext`.

```suricata
alert tcp any any -> $HOME_NET 61616 (
    msg:"SEC-ALERT Apache ActiveMQ OpenWire Deserialization Attempt (CVE-2023-46604)";
    flow:established,to_server;
    content:"|1f|"; offset:4; depth:1;
    content:"org.springframework.context.support.ClassPathXmlApplicationContext"; nocase; fast_pattern;
    reference:cve,2023-46604;
    reference:url,github.com/X1r0z/ActiveMQ-RCE;
    classtype:attempted-admin;
    sid:1000001;
    rev:1;
)
```

---

## 3. YARA Rule: Minimalist Linux x86-64 Reverse TCP Shellcode Stager (Endpoint / Hunting)

Detects the 250-byte handcrafted ELF reverse stager (dropped as `docker`) by matching its raw assembly syscall sequence: `sys_mmap` with `PROT_EXEC`, `sys_socket`, `sys_connect`, `sys_nanosleep` retry loop, and direct memory execution via `jmp *%rsi`.

```yara
rule Linux_Stager_ReverseTCP_x64 {
    meta:
        description = "Detects minimalist handcrafted Linux x86-64 reverse TCP stager with direct in-memory execution"
        author = "Keenan"
        reference = "CyberDefenders OpenWire Analysis"
        date = "2026-10-23"
    strings:
        // sys_mmap (syscall 9) with PROT_READ|PROT_WRITE|PROT_EXEC (0x7) and MAP_ANONYMOUS|MAP_PRIVATE (0x22)
        $mmap_rwx = { 6a 22 41 5a 6a 07 5a 0f 05 }

        // sys_socket (syscall 41 / 0x29, AF_INET=2, SOCK_STREAM=1)
        $socket = { 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 }

        // sys_connect (syscall 42 / 0x2a)
        $connect = { 6a 10 5a 6a 2a 58 0f 05 }

        // sys_nanosleep retry loop (syscall 35 / 0x23, 5s delay)
        $sleep_retry = { 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 }

        // sys_read into mmap buffer followed by jmp *%rsi execution
        $exec_jump = { 0f 05 48 85 c0 78 ?? ff e6 }

    condition:
        uint32(0) == 0x464c457f and // ELF magic (\x7fELF)
        filesize < 2KB and
        3 of ($mmap_rwx, $socket, $connect, $sleep_retry, $exec_jump)
}
```
