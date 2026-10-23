# Detection Rules: Apache ActiveMQ CVE-2023-46604 & In-Memory Stager

This folder contains production detection rules developed from the digital forensics and malware analysis of the **CyberDefenders OpenWire** incident.

---

## Detection Matrix

| Rule File | Detection Type | Target Phase | Key Logic / Signature |
|---|---|---|---|
| [`sigma_activemq_cve_2023_46604.yml`](./sigma_activemq_cve_2023_46604.yml) | **Sigma (SIEM / Host)** | Execution / Defense Evasion | Detects ActiveMQ `java` process spawning shells (`/bin/sh`, `/bin/bash`), downloaders (`curl`, `wget`), or executing dropped payloads out of `/tmp/`. |
| [`suricata_openwire_cve_2023_46604.rules`](./suricata_openwire_cve_2023_46604.rules) | **Suricata / Snort (NIDS)** | Initial Access / Exploit | Alerts on OpenWire TCP port 61616 unmarshaling commands (Type `0x1f` ExceptionResponse) loading `org.springframework.context.support.ClassPathXmlApplicationContext`. |
| [`yara_linux_reverse_tcp_stager.yar`](./yara_linux_reverse_tcp_stager.yar) | **YARA (Endpoint / Hunting)** | C2 / Memory Execution | Fingerprints handcrafted Linux x86-64 reverse TCP stagers using the raw syscall sequence: `mmap` with `PROT_EXEC` (0x7) $\rightarrow$ `sys_socket` $\rightarrow$ `sys_connect` $\rightarrow$ `nanosleep` $\rightarrow$ `jmp *%rsi`. |

---

## Testing & Deployment

### 1. Suricata Rule Validation (Network)
Test the rule directly against a captured PCAP:
```bash
suricata -r c119-OpenWire.pcap -s suricata_openwire_cve_2023_46604.rules -l ./suricata_logs/
grep -i "CVE-2023-46604" ./suricata_logs/fast.log
```

### 2. YARA Rule Validation (Binary / Hunting)
Scan the dropped binary or suspicious directory:
```bash
yara -w yara_linux_reverse_tcp_stager.yar /path/to/extracted/docker
```

### 3. Sigma Rule Conversion (SIEM)
Convert the Sigma YAML rule into target SIEM queries using `pySigma`:
* **Splunk:**
  ```bash
  sigma convert -t splunk -p sysmon_linux sigma_activemq_cve_2023_46604.yml
  ```
* **Elasticsearch / Kibana (KQL):**
  ```bash
  sigma convert -t elasticsearch -p ecs_linux sigma_activemq_cve_2023_46604.yml
  ```

---

## Author
* **Author:** Keenan (KeenanSec)
* **Writeup Reference:** [OpenWire Writeup](../Writeup.md)
